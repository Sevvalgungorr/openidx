package admin

import "testing"

// TestSystemActorIDIsStorableAsUUID pins a production incident.
//
// data_subject_requests.processed_by is a nullable uuid column. The background
// DSAR processor used to pass the descriptive string "system-dsar-processor"
// as the actor, which Postgres rejected with SQLSTATE 22P02 ("invalid input
// syntax for type uuid"). The UPDATE that marks the request completed therefore
// failed every time, the request stayed pending, and the processor picked it up
// again on the next tick — forever.
//
// Measured on the live system before the fix: 864 identical failures in 24
// hours against 3 export requests that could never complete. Nothing alerted,
// because from the outside the service was healthy: it was busy failing.
//
// The guard is deliberately about *storability*, not about the specific value.
// Any future actor constant is fine as long as the database can hold it: either
// empty (stored as NULL by nilIfEmpty) or a real UUID.
func TestSystemActorIDIsStorableAsUUID(t *testing.T) {
	if systemActorID == "" {
		// Empty is the intended value: nilIfEmpty turns it into NULL, and NULL
		// is the honest record of "no human processed this".
		if got := nilIfEmpty(systemActorID); got != nil {
			t.Fatalf("empty actor must map to NULL, got %v", *got)
		}
		return
	}

	// A non-empty actor is written into a uuid column verbatim, so it has to be
	// a UUID. This is the check that would have caught the incident.
	if !looksLikeUUID(systemActorID) {
		t.Fatalf("systemActorID = %q, which is not a UUID and not empty; "+
			"data_subject_requests.processed_by is a uuid column, so this value "+
			"cannot be stored (SQLSTATE 22P02) and every automated DSAR would "+
			"fail and retry forever", systemActorID)
	}
}

// looksLikeUUID checks the canonical 8-4-4-4-12 hex form. Kept local and
// deliberately simple: the point is to reject obviously non-UUID values like a
// human-readable label, not to validate RFC 4122 variants.
func looksLikeUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, r := range s {
		switch i {
		case 8, 13, 18, 23:
			if r != '-' {
				return false
			}
		default:
			isHex := (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
			if !isHex {
				return false
			}
		}
	}
	return true
}
