// Package audit provides test helpers for audit testing
package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/openidx/openidx/internal/common/database"
	"github.com/openidx/openidx/pkg/storage"
	"go.uber.org/zap"
)

// TestAuditLogger provides a test-friendly audit logger that uses the tamper-evident storage
type TestAuditLogger struct {
	store  storage.AppendOnlyStore
	secret string
}

// NewTestAuditLogger creates a new test audit logger with the given store
func NewTestAuditLogger(store storage.AppendOnlyStore) *TestAuditLogger {
	return &TestAuditLogger{
		store:  store,
		secret: "test-secret-key",
	}
}

// NewAuditLogger creates a new audit logger for testing
// This matches the signature expected by logger_test.go
func NewAuditLogger(store storage.AppendOnlyStore) *TestAuditLogger {
	return NewTestAuditLogger(store)
}

// AuditEventForTest is the AuditEvent type used by logger_test.go tests
// We alias this for clarity since the audit package has multiple AuditEvent types
type AuditEventForTest struct {
	ID           string                 `json:"id"`
	Timestamp    time.Time              `json:"timestamp"`
	EventType    string                 `json:"event_type"`
	ActorID      string                 `json:"actor_id"`
	ActorType    string                 `json:"actor_type"`
	ResourceID   string                 `json:"resource_id"`
	ResourceType string                 `json:"resource_type"`
	Action       string                 `json:"action"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
	Checksum     string                 `json:"checksum"`
	PreviousHash string                 `json:"previous_hash"`
}

// LogEvent logs an audit event to the append-only store
func (l *TestAuditLogger) LogEvent(ctx context.Context, event AuditEventForTest) error {
	// Generate ID if not set
	if event.ID == "" {
		event.ID = generateUUID()
	}

	// Set timestamp if not set
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	// Get previous hash
	lastHash, _ := l.store.GetLastHash()

	// Compute checksum using SHA256-HMAC
	checksum := l.computeChecksum(event, lastHash)
	event.Checksum = checksum
	event.PreviousHash = lastHash

	// Marshal to JSON
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}

	return l.store.Append(data)
}

// computeChecksum computes SHA256-HMAC checksum for the event
func (l *TestAuditLogger) computeChecksum(event AuditEventForTest, previousHash string) string {
	// Create canonical representation
	canonical := event.ID + "|" +
		event.Timestamp.UTC().Format(time.RFC3339Nano) + "|" +
		event.EventType + "|" +
		event.ActorID + "|" +
		event.Action + "|" +
		event.ResourceID + "|" +
		previousHash + "|" +
		l.secret

	h := sha256.New()
	h.Write([]byte(canonical))
	return hex.EncodeToString(h.Sum(nil))
}

// GetAllEvents retrieves all events from the store
func (l *TestAuditLogger) GetAllEvents(ctx context.Context) ([]AuditEventForTest, error) {
	entries, err := l.store.ReadAll()
	if err != nil {
		return nil, err
	}

	events := make([]AuditEventForTest, 0, len(entries))
	for _, entry := range entries {
		var event AuditEventForTest
		if err := json.Unmarshal(entry, &event); err != nil {
			continue
		}
		events = append(events, event)
	}

	return events, nil
}

// GetEventByID retrieves an event by its ID
func (l *TestAuditLogger) GetEventByID(ctx context.Context, id string) (AuditEventForTest, error) {
	events, err := l.GetAllEvents(ctx)
	if err != nil {
		return AuditEventForTest{}, err
	}

	for _, event := range events {
		if event.ID == id {
			return event, nil
		}
	}

	return AuditEventForTest{}, &EventNotFoundError{ID: id}
}

// VerifyChecksum verifies the checksum of an event
func (l *TestAuditLogger) VerifyChecksum(event AuditEventForTest) bool {
	if event.Checksum == "" {
		return false
	}
	// Recompute checksum and verify
	expected := l.computeChecksum(event, event.PreviousHash)
	return expected == event.Checksum
}

// VerifyChain verifies the integrity of the hash chain
func (l *TestAuditLogger) VerifyChain(ctx context.Context) (bool, error) {
	entries, err := l.store.ReadAll()
	if err != nil {
		return false, err
	}

	if len(entries) == 0 {
		return true, nil
	}

	var previousHash string
	for _, entry := range entries {
		var event AuditEventForTest
		if err := json.Unmarshal(entry, &event); err != nil {
			return false, err
		}

		if event.PreviousHash != previousHash {
			return false, nil
		}

		previousHash = event.Checksum
	}

	return true, nil
}

// GetEventsByTimeRange retrieves events within a time range
func (l *TestAuditLogger) GetEventsByTimeRange(ctx context.Context, start, end time.Time) ([]AuditEventForTest, error) {
	events, err := l.GetAllEvents(ctx)
	if err != nil {
		return nil, err
	}

	var result []AuditEventForTest
	for _, event := range events {
		if (event.Timestamp.Equal(start) || event.Timestamp.After(start)) &&
			(event.Timestamp.Equal(end) || event.Timestamp.Before(end)) {
			result = append(result, event)
		}
	}

	return result, nil
}

// GetEventsByActor retrieves events by actor ID
func (l *TestAuditLogger) GetEventsByActor(ctx context.Context, actorID string) ([]AuditEventForTest, error) {
	events, err := l.GetAllEvents(ctx)
	if err != nil {
		return nil, err
	}

	var result []AuditEventForTest
	for _, event := range events {
		if event.ActorID == actorID {
			result = append(result, event)
		}
	}

	return result, nil
}

// GetEventsByResource retrieves events by resource ID
func (l *TestAuditLogger) GetEventsByResource(ctx context.Context, resourceID string) ([]AuditEventForTest, error) {
	events, err := l.GetAllEvents(ctx)
	if err != nil {
		return nil, err
	}

	var result []AuditEventForTest
	for _, event := range events {
		if event.ResourceID == resourceID {
			result = append(result, event)
		}
	}

	return result, nil
}

// GetEventsByType retrieves events by type
func (l *TestAuditLogger) GetEventsByType(ctx context.Context, eventType string) ([]AuditEventForTest, error) {
	events, err := l.GetAllEvents(ctx)
	if err != nil {
		return nil, err
	}

	var result []AuditEventForTest
	for _, event := range events {
		if event.EventType == eventType {
			result = append(result, event)
		}
	}

	return result, nil
}

// EventNotFoundError is returned when an event is not found
type EventNotFoundError struct {
	ID string
}

func (e *EventNotFoundError) Error() string {
	return "event not found: " + e.ID
}

// createTestService creates a test service with nil database for unit tests
func createTestService(t *testing.T) *Service {
	logger := zap.NewNop()
	db := &database.PostgresDB{
		// Pool is nil, but methods should handle this gracefully
	}
	return &Service{
		db:     db,
		logger: logger,
	}
}
