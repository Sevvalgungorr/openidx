package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/openidx/openidx/internal/common/orgctx"
	"go.uber.org/zap"
)

// SSF transmitter: enqueue signed SETs for every subscribed stream, and drain
// the outbox with a push worker (at-least-once, retry/backoff, dead-letter).
// This is the outbound half — OpenIDX telling downstream receivers that a CAEP
// event (e.g. session-revoked) happened.

const ssfMaxAttempts = 8

// EmitCAEPEvent fans a CAEP/RISC event out to every enabled stream that
// requested it (or requested nothing, meaning "all"), building + signing one SET
// per stream and enqueuing it for delivery. Best-effort: called from revocation
// paths, it never fails the caller. Returns the number of SETs enqueued.
func (s *Service) EmitCAEPEvent(ctx context.Context, orgID, eventType, subjectEmail, subjectID string, eventClaims map[string]interface{}) int {
	// SECURITY: fan out only to the affected tenant's streams. This predicate
	// used to carry an `OR $1=''` escape, so an empty org would have enqueued
	// the event to EVERY tenant's receivers — leaking one tenant's security
	// events (session revoked, credential change) to all the others. The sole
	// production caller passes a real org; an empty one is a bug, so emit
	// nothing rather than broadcasting. Best-effort by contract: callers treat
	// a 0 return as "nothing subscribed" and never fail on it.
	if orgID == "" {
		s.logger.Warn("SSF: refusing to emit a CAEP event without a tenant",
			zap.String("event_type", eventType))
		return 0
	}
	rows, err := s.db.Pool.Query(ctx, `
        SELECT id::text, audience, COALESCE(events_requested,'[]'::jsonb)
          FROM ssf_streams
         WHERE status='enabled' AND org_id::text=$1`, orgID)
	if err != nil {
		s.logger.Warn("SSF: query streams failed", zap.Error(err))
		return 0
	}
	type stream struct {
		id, aud string
		events  []byte
	}
	var streams []stream
	for rows.Next() {
		var st stream
		if err := rows.Scan(&st.id, &st.aud, &st.events); err == nil {
			streams = append(streams, st)
		}
	}
	rows.Close()

	enqueued := 0
	for _, st := range streams {
		if !streamWantsEvent(st.events, eventType) {
			continue
		}
		setJWT, _, err := s.BuildSET(st.aud, eventType, subjectEmail, subjectID, eventClaims)
		if err != nil {
			s.logger.Warn("SSF: build SET failed", zap.String("stream", st.id), zap.Error(err))
			continue
		}
		subj := subjectEmail
		if subj == "" {
			subj = subjectID
		}
		if _, err := s.db.Pool.Exec(ctx, `
            INSERT INTO ssf_stream_delivery (org_id, stream_id, event_type, subject, set_jwt)
            VALUES ($1,$2,$3,$4,$5)`,
			ssfNullIfEmpty(orgID), st.id, eventType, ssfNullIfEmpty(subj), setJWT); err != nil {
			s.logger.Warn("SSF: enqueue SET failed", zap.String("stream", st.id), zap.Error(err))
			continue
		}
		enqueued++
	}
	if enqueued > 0 {
		s.logger.Info("SSF: CAEP event enqueued",
			zap.String("event", eventType), zap.String("subject", subjectEmail),
			zap.Int("streams", enqueued))
	}
	return enqueued
}

// streamWantsEvent reports whether a stream's events_requested JSON array
// contains eventType, or is empty (meaning all events).
func streamWantsEvent(eventsJSON []byte, eventType string) bool {
	var events []string
	if len(eventsJSON) == 0 {
		return true
	}
	_ = json.Unmarshal(eventsJSON, &events)
	if len(events) == 0 {
		return true
	}
	for _, e := range events {
		if e == eventType {
			return true
		}
	}
	return false
}

// StartSSFPushWorker launches the outbox drain loop.
func (s *Service) StartSSFPushWorker(ctx context.Context) {
	go s.runSSFPush(orgctx.WithBypassRLS(ctx))
	s.logger.Info("SSF push worker starting")
}

func (s *Service) runSSFPush(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for {
				n, err := s.drainSSFDelivery(ctx)
				if err != nil {
					s.logger.Warn("SSF push drain failed", zap.Error(err))
					break
				}
				if n == 0 {
					break
				}
			}
		}
	}
}

type ssfDeliveryItem struct {
	id       int64
	streamID string
	setJWT   string
	attempts int
}

// drainSSFDelivery claims and pushes up to 50 due SETs.
func (s *Service) drainSSFDelivery(ctx context.Context) (int, error) {
	rows, err := s.db.Pool.Query(ctx, `
        UPDATE ssf_stream_delivery d SET state='processing', updated_at=NOW()
         WHERE d.id IN (
             SELECT id FROM ssf_stream_delivery
              WHERE state='pending' AND next_attempt_at <= NOW()
              ORDER BY id ASC LIMIT 50 FOR UPDATE SKIP LOCKED)
        RETURNING d.id, d.stream_id::text, d.set_jwt, d.attempts`)
	if err != nil {
		return 0, err
	}
	var items []ssfDeliveryItem
	for rows.Next() {
		var it ssfDeliveryItem
		if err := rows.Scan(&it.id, &it.streamID, &it.setJWT, &it.attempts); err != nil {
			rows.Close()
			return 0, err
		}
		items = append(items, it)
	}
	rows.Close()

	for _, it := range items {
		s.pushSSFItem(ctx, it)
	}
	return len(items), nil
}

func (s *Service) pushSSFItem(ctx context.Context, it ssfDeliveryItem) {
	endpoint, auth, err := s.ssfDeliveryTarget(ctx, it.streamID)
	if err != nil {
		s.failSSFItem(ctx, it, err)
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader([]byte(it.setJWT)))
	if err != nil {
		s.failSSFItem(ctx, it, err)
		return
	}
	req.Header.Set("Content-Type", setContentType)
	req.Header.Set("Accept", "application/json")
	if auth != "" {
		req.Header.Set("Authorization", "Bearer "+auth)
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		s.retryOrDeadSSF(ctx, it, err)
		return
	}
	defer resp.Body.Close()
	// RFC 8935: 202 Accepted on success; 200 also tolerated.
	if resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusOK {
		_, _ = s.db.Pool.Exec(ctx, `UPDATE ssf_stream_delivery SET state='delivered', updated_at=NOW() WHERE id=$1`, it.id)
		return
	}
	s.retryOrDeadSSF(ctx, it, fmt.Errorf("receiver returned %d", resp.StatusCode))
}

func (s *Service) ssfDeliveryTarget(ctx context.Context, streamID string) (endpoint, auth string, err error) {
	var authEnc *string
	if err = s.db.Pool.QueryRow(ctx,
		//orgscope:ignore background push worker (runs under bypass_rls) resolving the delivery target of an outbox row it already claimed; addressed by stream primary key, no request/tenant context
		`SELECT delivery_endpoint, delivery_auth_enc FROM ssf_streams WHERE id=$1`, streamID).
		Scan(&endpoint, &authEnc); err != nil {
		return "", "", err
	}
	if authEnc != nil && *authEnc != "" {
		auth, _ = s.ssfDecrypt(*authEnc)
	}
	return endpoint, auth, nil
}

func (s *Service) retryOrDeadSSF(ctx context.Context, it ssfDeliveryItem, cause error) {
	attempts := it.attempts + 1
	if attempts >= ssfMaxAttempts {
		_, _ = s.db.Pool.Exec(ctx,
			`UPDATE ssf_stream_delivery SET state='dead', attempts=$2, last_error=$3, updated_at=NOW() WHERE id=$1`,
			it.id, attempts, cause.Error())
		s.logger.Warn("SSF delivery dead-lettered", zap.Int64("id", it.id), zap.Error(cause))
		return
	}
	backoff := time.Duration(1<<uint(attempts)) * time.Second
	if backoff > time.Hour {
		backoff = time.Hour
	}
	_, _ = s.db.Pool.Exec(ctx, `
        UPDATE ssf_stream_delivery
           SET state='pending', attempts=$2, last_error=$3,
               next_attempt_at=NOW() + $4::interval, updated_at=NOW()
         WHERE id=$1`,
		it.id, attempts, cause.Error(), fmt.Sprintf("%d seconds", int(backoff.Seconds())))
}

func (s *Service) failSSFItem(ctx context.Context, it ssfDeliveryItem, cause error) {
	_, _ = s.db.Pool.Exec(ctx,
		`UPDATE ssf_stream_delivery SET state='failed', last_error=$2, updated_at=NOW() WHERE id=$1`,
		it.id, cause.Error())
}
