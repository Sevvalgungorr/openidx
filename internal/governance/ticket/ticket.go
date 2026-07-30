// Package ticket validates change/incident tickets (ServiceNow, Jira) as a
// precondition for privileged access approval (PAM C4).
//
// Auditors on SOX/PCI/ITIL programs require that privileged access is tied to
// an approved change or incident ticket. This package lets an OpenIDX approval
// policy demand a ticket reference and verify — against the ticketing system's
// live API — that the ticket exists, is in an acceptable state (e.g. an
// approved/implementing change window), and (optionally) matches the requester.
//
// Providers are pluggable behind the Validator interface. The two built-ins
// (ServiceNow, Jira) talk to their REST APIs; both are configured with a base
// URL + credentials and a set of acceptable states. A NullValidator is provided
// for deployments that record a ticket reference without live verification.
package ticket

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Result is the outcome of validating a ticket reference.
type Result struct {
	Valid      bool   // whether the ticket satisfies policy
	Ref        string // normalized ticket reference
	State      string // the ticket's current state (provider-specific)
	Summary    string // short human-readable summary (never secrets)
	Reason     string // why it failed, when Valid is false
	Provider   string // "servicenow" | "jira" | "null"
	AssignedTo string // ticket assignee/requester, when the provider exposes it
}

// Validator verifies a ticket reference against a ticketing system.
type Validator interface {
	// Validate checks the ticket reference. requesterHint is the OpenIDX
	// requester identity (username/email) so a provider MAY enforce that the
	// ticket belongs to the person requesting access; providers that don't
	// support that ignore it. A non-nil error is a transport/verification
	// failure (fail closed at the call site); a Result with Valid=false is a
	// clean policy rejection.
	Validate(ctx context.Context, ref, requesterHint string) (*Result, error)
	// Provider returns the provider id.
	Provider() string
}

var (
	// ErrNoTicket is returned by the enforcement helper when a ticket is
	// required but none was supplied.
	ErrNoTicket = errors.New("a ticket reference is required for this access")
	// ErrInvalidRef is returned when a supplied reference is malformed.
	ErrInvalidRef = errors.New("ticket reference is malformed")
)

// snowRefRe matches ServiceNow record numbers like CHG0031234 / INC0012345.
var snowRefRe = regexp.MustCompile(`^[A-Z]{2,5}[0-9]{4,}$`)

// jiraRefRe matches Jira issue keys like OPS-1234.
var jiraRefRe = regexp.MustCompile(`^[A-Z][A-Z0-9]+-[0-9]+$`)

// NormalizeRef trims and upper-cases a ticket reference and sanity-checks its
// shape for the given provider. Returns ErrInvalidRef on an obviously bad ref.
func NormalizeRef(provider, ref string) (string, error) {
	r := strings.ToUpper(strings.TrimSpace(ref))
	if r == "" {
		return "", ErrNoTicket
	}
	switch provider {
	case "servicenow":
		if !snowRefRe.MatchString(r) {
			return "", fmt.Errorf("%w: %q is not a ServiceNow record number", ErrInvalidRef, ref)
		}
	case "jira":
		if !jiraRefRe.MatchString(r) {
			return "", fmt.Errorf("%w: %q is not a Jira issue key", ErrInvalidRef, ref)
		}
	}
	return r, nil
}

// EnforcementPolicy describes what a ticket must satisfy for an approval.
type EnforcementPolicy struct {
	Required       bool     // whether a ticket is mandatory
	AcceptStates   []string // acceptable ticket states (case-insensitive); empty = any
	MustMatchOwner bool     // require the ticket to belong to the requester
}

// Enforce runs the policy: normalizes the ref, validates it via the validator,
// and checks the returned state against AcceptStates. Returns the Result and a
// nil error on success; a non-nil error means the access must be blocked.
func Enforce(ctx context.Context, v Validator, policy EnforcementPolicy, ref, requesterHint string) (*Result, error) {
	if !policy.Required {
		return &Result{Valid: true, Provider: v.Provider(), Reason: "ticket not required"}, nil
	}
	norm, err := NormalizeRef(v.Provider(), ref)
	if err != nil {
		return nil, err
	}
	res, err := v.Validate(ctx, norm, requesterHint)
	if err != nil {
		return nil, fmt.Errorf("ticket verification failed: %w", err)
	}
	if !res.Valid {
		return res, fmt.Errorf("ticket %s rejected: %s", norm, res.Reason)
	}
	if len(policy.AcceptStates) > 0 && !stateAccepted(res.State, policy.AcceptStates) {
		res.Valid = false
		res.Reason = fmt.Sprintf("ticket state %q not in accepted states %v", res.State, policy.AcceptStates)
		return res, fmt.Errorf("ticket %s: %s", norm, res.Reason)
	}
	if policy.MustMatchOwner && requesterHint != "" && res.AssignedTo != "" &&
		!strings.EqualFold(res.AssignedTo, requesterHint) {
		res.Valid = false
		res.Reason = fmt.Sprintf("ticket assigned to %q, not requester %q", res.AssignedTo, requesterHint)
		return res, fmt.Errorf("ticket %s: %s", norm, res.Reason)
	}
	return res, nil
}

func stateAccepted(state string, accepted []string) bool {
	for _, a := range accepted {
		if strings.EqualFold(state, a) {
			return true
		}
	}
	return false
}

// NullValidator records a ticket reference without live verification. Useful
// when a deployment wants the audit trail of a ticket ref but has no reachable
// ticketing API. It accepts any non-empty, well-formed reference.
type NullValidator struct{ ProviderID string }

func (n NullValidator) Provider() string {
	if n.ProviderID != "" {
		return n.ProviderID
	}
	return "null"
}

func (n NullValidator) Validate(ctx context.Context, ref, requesterHint string) (*Result, error) {
	return &Result{Valid: true, Ref: ref, State: "recorded", Provider: n.Provider(), Summary: "reference recorded (no live verification)"}, nil
}
