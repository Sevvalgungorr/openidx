package identity

import (
	"errors"
	"fmt"
	"strings"
)

// SCIM PATCH filtered path expressions (RFC 7644 §3.5.2).
//
// A PATCH path may select one element of a multi-valued attribute with a
// filter — `emails[type eq "work"].value`, `members[value eq "abc"]`. Okta and
// Entra ID use exactly this shape to update or remove a single address or
// member without replacing the whole array.
//
// Support is scoped to the two attributes this directory actually persists:
// User.emails (users.email) and Group.members (group_memberships). A filtered
// path against anything else is rejected rather than applied to a struct that
// is about to be discarded — see the note on ApplySCIMPatchToUser.
//
// Before this, `add` and `replace` had no bracket handling at all: a filtered
// path fell through to a default branch that matched no known attribute and
// returned nil, so the server answered 200 OK having changed nothing. `remove`
// had partial handling that ignored the filter entirely and matched on
// op.Value instead, so `emails[type eq "work"]` (no value) removed nothing
// while `emails[value eq "x"]` worked only by accident of the value being
// echoed. Silently succeeding at an operation you did not perform is the same
// defect as the discarded SCIM query filter: the client believes the directory
// is in a state it is not.

// RFC 7644 §3.12 error types for PATCH. Clients branch on scimType: Entra ID
// treats noTarget as "already in the desired state" and moves on, while
// invalidPath is a configuration error it surfaces to the operator. Returning
// the generic invalidSyntax for both makes a benign no-op look like a bug.
var (
	errSCIMNoTarget    = errors.New("noTarget")
	errSCIMInvalidPath = errors.New("invalidPath")
)

// scimPatchErrorType maps a patch error to its RFC 7644 scimType.
func scimPatchErrorType(err error) string {
	switch {
	case errors.Is(err, errSCIMNoTarget):
		return "noTarget"
	case errors.Is(err, errSCIMInvalidPath):
		return "invalidPath"
	default:
		return "invalidSyntax"
	}
}

// noTargetf / invalidPathf build a described error carrying its scimType.
func noTargetf(format string, args ...interface{}) error {
	return fmt.Errorf("%s (%w)", fmt.Sprintf(format, args...), errSCIMNoTarget)
}

func invalidPathf(format string, args ...interface{}) error {
	return fmt.Errorf("%s (%w)", fmt.Sprintf(format, args...), errSCIMInvalidPath)
}

// scimPatchPath is a parsed PATCH path.
type scimPatchPath struct {
	// Attribute is the base multi-valued or simple attribute ("emails").
	Attribute string
	// SubAttribute is the part after the closing bracket, if any ("value" in
	// `emails[type eq "work"].value`). Empty when the path selects the whole
	// element.
	SubAttribute string
	// Filter is the bracketed expression, absent for a plain path.
	Filter *scimPatchFilter
}

// scimPatchFilter is the `attr op "value"` inside the brackets.
type scimPatchFilter struct {
	Attribute string
	Operator  string
	Value     string
}

// HasFilter reports whether the path selects a subset of a multi-valued attribute.
func (p scimPatchPath) HasFilter() bool { return p.Filter != nil }

// parseSCIMPatchPath parses a PATCH path, with or without a value filter.
//
// Only the operators that appear in real provisioning traffic are supported —
// eq, ne, co, sw, ew, pr. An unsupported operator is an error rather than a
// silent miss, so a client learns its request was not honored.
func parseSCIMPatchPath(path string) (scimPatchPath, error) {
	open := strings.Index(path, "[")
	if open < 0 {
		return scimPatchPath{Attribute: path}, nil
	}

	closeIdx := strings.LastIndex(path, "]")
	if closeIdx < open {
		return scimPatchPath{}, invalidPathf("malformed filter path %q: missing ]", path)
	}

	attr := strings.TrimSpace(path[:open])
	if attr == "" {
		return scimPatchPath{}, invalidPathf("malformed filter path %q: no attribute before [", path)
	}

	filter, err := parseSCIMPatchFilter(path[open+1 : closeIdx])
	if err != nil {
		return scimPatchPath{}, fmt.Errorf("in path %q: %w", path, err)
	}

	sub := strings.TrimPrefix(strings.TrimSpace(path[closeIdx+1:]), ".")
	return scimPatchPath{Attribute: attr, SubAttribute: sub, Filter: &filter}, nil
}

func parseSCIMPatchFilter(expr string) (scimPatchFilter, error) {
	fields := strings.Fields(strings.TrimSpace(expr))
	switch len(fields) {
	case 2: // presence: `type pr`
		if !strings.EqualFold(fields[1], "pr") {
			return scimPatchFilter{}, invalidPathf("unsupported filter %q", expr)
		}
		return scimPatchFilter{Attribute: fields[0], Operator: "pr"}, nil
	case 0, 1:
		return scimPatchFilter{}, invalidPathf("unsupported filter %q", expr)
	}

	op := strings.ToLower(fields[1])
	switch op {
	case "eq", "ne", "co", "sw", "ew":
	default:
		return scimPatchFilter{}, invalidPathf("unsupported filter operator %q", fields[1])
	}

	// Re-join so a quoted value containing spaces survives.
	raw := strings.TrimSpace(strings.Join(fields[2:], " "))
	value := strings.Trim(raw, `"`)
	return scimPatchFilter{Attribute: fields[0], Operator: op, Value: value}, nil
}

// matches evaluates the filter against one element's attributes.
//
// A nil filter matches everything, so callers can treat the filtered and
// unfiltered cases uniformly.
func (f *scimPatchFilter) matches(attrs map[string]string) bool {
	if f == nil {
		return true
	}
	actual, present := attrs[strings.ToLower(f.Attribute)]
	if f.Operator == "pr" {
		return present && actual != ""
	}
	if !present {
		return false
	}
	switch f.Operator {
	case "eq":
		return strings.EqualFold(actual, f.Value)
	case "ne":
		return !strings.EqualFold(actual, f.Value)
	case "co":
		return strings.Contains(strings.ToLower(actual), strings.ToLower(f.Value))
	case "sw":
		return strings.HasPrefix(strings.ToLower(actual), strings.ToLower(f.Value))
	case "ew":
		return strings.HasSuffix(strings.ToLower(actual), strings.ToLower(f.Value))
	}
	return false
}

// emailAttrs exposes an email element's filterable attributes.
func emailAttrs(e Email) map[string]string {
	m := map[string]string{"value": e.Value}
	if e.Type != nil {
		m["type"] = *e.Type
	}
	if e.Primary != nil && *e.Primary {
		m["primary"] = "true"
	}
	return m
}

// setEmailField assigns one sub-attribute of an email element. An empty
// sub-attribute means the caller addressed the element itself, which for a
// scalar update is equivalent to setting `value`.
func setEmailField(e *Email, sub string, value interface{}) error {
	switch sub {
	case "", "value":
		s, ok := value.(string)
		if !ok {
			return fmt.Errorf("emails.value must be a string")
		}
		e.Value = s
	case "type":
		s, ok := value.(string)
		if !ok {
			return fmt.Errorf("emails.type must be a string")
		}
		e.Type = &s
	case "primary":
		b, ok := value.(bool)
		if !ok {
			return fmt.Errorf("emails.primary must be a boolean")
		}
		e.Primary = &b
	case "display":
		s, ok := value.(string)
		if !ok {
			return fmt.Errorf("emails.display must be a string")
		}
		e.Display = &s
	default:
		return invalidPathf("unsupported emails sub-attribute %q", sub)
	}
	return nil
}

// applyFilteredUserPatch handles add/replace against a filtered path on
// `emails`. It reports whether the path was one it owns, so the caller can fall
// through to its plain-path handling (and, for a filtered path nothing owns,
// to an unsupported-path error).
//
// A filter that matches nothing is an error (RFC 7644 §3.5.2 "noTarget"), not a
// no-op: the client asked to modify a specific element, and reporting success
// when that element does not exist is what this whole change is about.
func applyFilteredUserPatch(user *User, p scimPatchPath, value interface{}) (handled bool, err error) {
	if !p.HasFilter() {
		return false, nil
	}

	switch p.Attribute {
	case "emails":
		matched := 0
		for i := range user.Emails {
			if p.Filter.matches(emailAttrs(user.Emails[i])) {
				if err := setEmailField(&user.Emails[i], p.SubAttribute, value); err != nil {
					return true, err
				}
				matched++
			}
		}
		if matched == 0 {
			return true, noTargetf("no email matches %s[%s %s %q]",
				p.Attribute, p.Filter.Attribute, p.Filter.Operator, p.Filter.Value)
		}
		return true, nil
	}

	return false, nil
}

// removeFilteredUserPatch handles remove against a filtered path.
func removeFilteredUserPatch(user *User, p scimPatchPath) (handled bool, err error) {
	if !p.HasFilter() {
		return false, nil
	}

	switch p.Attribute {
	case "emails":
		kept := make([]Email, 0, len(user.Emails))
		for _, e := range user.Emails {
			if !p.Filter.matches(emailAttrs(e)) {
				kept = append(kept, e)
			}
		}
		if len(kept) == len(user.Emails) {
			return true, noTargetf("no email matches %s[%s %s %q]",
				p.Attribute, p.Filter.Attribute, p.Filter.Operator, p.Filter.Value)
		}
		user.Emails = kept
		return true, nil
	}

	return false, nil
}

// memberAttrs exposes a group member's filterable attributes.
func memberAttrs(m Member) map[string]string {
	attrs := map[string]string{"value": m.Value, "type": m.Type}
	if m.Display != nil {
		attrs["display"] = *m.Display
	}
	return attrs
}

// replaceFilteredGroupMembers handles `members[value eq "x"].display` on a
// replace op — updating one member's metadata without rewriting the roster.
func replaceFilteredGroupMembers(group *Group, p scimPatchPath, value interface{}) (handled bool, err error) {
	if !p.HasFilter() || p.Attribute != "members" {
		return false, nil
	}

	matched := 0
	for i := range group.Members {
		if !p.Filter.matches(memberAttrs(group.Members[i])) {
			continue
		}
		s, ok := value.(string)
		if !ok {
			return true, fmt.Errorf("members.%s must be a string", p.SubAttribute)
		}
		switch p.SubAttribute {
		case "display":
			group.Members[i].Display = &s
		case "type":
			group.Members[i].Type = s
		case "", "value":
			group.Members[i].Value = s
		default:
			return true, invalidPathf("unsupported members sub-attribute %q", p.SubAttribute)
		}
		matched++
	}
	if matched == 0 {
		return true, noTargetf("no member matches members[%s %s %q]",
			p.Filter.Attribute, p.Filter.Operator, p.Filter.Value)
	}
	return true, nil
}

// removeFilteredGroupMembers handles `members[value eq "..."]` on a remove op —
// the form Okta and Entra use to detach a single member.
//
// The previous implementation ignored the filter and matched on op.Value, so a
// remove whose target was expressed only in the path (the normal case) removed
// nothing and still returned success.
func removeFilteredGroupMembers(group *Group, p scimPatchPath) (handled bool, err error) {
	if !p.HasFilter() || p.Attribute != "members" {
		return false, nil
	}

	kept := make([]Member, 0, len(group.Members))
	for _, m := range group.Members {
		if !p.Filter.matches(memberAttrs(m)) {
			kept = append(kept, m)
		}
	}
	if len(kept) == len(group.Members) {
		return true, noTargetf("no member matches members[%s %s %q]",
			p.Filter.Attribute, p.Filter.Operator, p.Filter.Value)
	}
	group.Members = kept
	return true, nil
}
