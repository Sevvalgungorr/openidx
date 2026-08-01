// Package identity provides SCIM 2.0 filter expression parsing per RFC 7644
package identity

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// ============================================================
// SCIM Filter Expression Parser (RFC 7644 3.4.2.2)
// ============================================================

// FilterOperator represents a SCIM filter operator
type FilterOperator string

const (
	OpEqual       FilterOperator = "eq"
	OpNotEqual    FilterOperator = "ne"
	OpContains    FilterOperator = "co"
	OpStartsWith  FilterOperator = "sw"
	OpEndsWith    FilterOperator = "ew"
	OpPresent     FilterOperator = "pr"
	OpGreaterThan FilterOperator = "gt"
	OpGreaterEq   FilterOperator = "ge"
	OpLessThan    FilterOperator = "lt"
	OpLessEq      FilterOperator = "le"
	OpAnd         FilterOperator = "and"
	OpOr          FilterOperator = "or"
	OpNot         FilterOperator = "not"
)

// FilterExpression represents a parsed SCIM filter expression
type FilterExpression struct {
	Operator FilterOperator
	Field    string
	Value    string
	Left     *FilterExpression // For logical operators
	Right    *FilterExpression // For and/or
	Not      *FilterExpression // For not
}

// String returns the string representation of the filter expression
func (e *FilterExpression) String() string {
	switch e.Operator {
	case OpAnd, OpOr:
		return fmt.Sprintf("(%s %s %s)", e.Left.String(), e.Operator, e.Right.String())
	case OpNot:
		return fmt.Sprintf("not (%s)", e.Not.String())
	default:
		return fmt.Sprintf("%s %s %s", e.Field, e.Operator, e.Value)
	}
}

// ParseFilter parses a SCIM filter expression string
func ParseFilter(filter string) (*FilterExpression, error) {
	if filter == "" {
		return nil, nil
	}

	parser := newFilterParser(filter)
	return parser.Parse()
}

// filterParser is a recursive descent parser for SCIM filter expressions
type filterParser struct {
	input string
	pos   int
}

// newFilterParser creates a new filter parser
func newFilterParser(input string) *filterParser {
	return &filterParser{input: strings.TrimSpace(input)}
}

// Parse parses the filter expression
func (p *filterParser) Parse() (*FilterExpression, error) {
	if p.input == "" {
		return nil, nil
	}

	expr, err := p.parseOrExpression()
	if err != nil {
		return nil, err
	}

	// Ensure we consumed the entire input
	p.skipWhitespace()
	if p.pos < len(p.input) {
		return nil, fmt.Errorf("unexpected character at position %d: %c", p.pos, p.input[p.pos])
	}

	return expr, nil
}

// parseOrExpression parses OR expressions (lowest precedence)
func (p *filterParser) parseOrExpression() (*FilterExpression, error) {
	left, err := p.parseAndExpression()
	if err != nil {
		return nil, err
	}

	for {
		p.skipWhitespace()
		if !p.consumeKeyword("or") {
			break
		}

		right, err := p.parseAndExpression()
		if err != nil {
			return nil, err
		}

		left = &FilterExpression{
			Operator: OpOr,
			Left:     left,
			Right:    right,
		}
	}

	return left, nil
}

// parseAndExpression parses AND expressions
func (p *filterParser) parseAndExpression() (*FilterExpression, error) {
	left, err := p.parseNotExpression()
	if err != nil {
		return nil, err
	}

	for {
		p.skipWhitespace()
		if !p.consumeKeyword("and") {
			break
		}

		right, err := p.parseNotExpression()
		if err != nil {
			return nil, err
		}

		left = &FilterExpression{
			Operator: OpAnd,
			Left:     left,
			Right:    right,
		}
	}

	return left, nil
}

// parseNotExpression parses NOT expressions
func (p *filterParser) parseNotExpression() (*FilterExpression, error) {
	p.skipWhitespace()
	if p.consumeKeyword("not") {
		p.skipWhitespace()
		if !p.consumeParen('(') {
			return nil, fmt.Errorf("expected '(' after 'not'")
		}

		expr, err := p.parseOrExpression()
		if err != nil {
			return nil, err
		}

		p.skipWhitespace()
		if !p.consumeParen(')') {
			return nil, fmt.Errorf("expected ')' after not expression")
		}

		return &FilterExpression{
			Operator: OpNot,
			Not:      expr,
		}, nil
	}

	return p.parsePrimaryExpression()
}

// parsePrimaryExpression parses parenthesized expressions or simple comparisons
func (p *filterParser) parsePrimaryExpression() (*FilterExpression, error) {
	p.skipWhitespace()

	// Check for parenthesized expression
	if p.consumeParen('(') {
		expr, err := p.parseOrExpression()
		if err != nil {
			return nil, err
		}

		p.skipWhitespace()
		if !p.consumeParen(')') {
			return nil, fmt.Errorf("expected ')' to close parenthesized expression")
		}

		return expr, nil
	}

	// Parse simple comparison: field operator value
	return p.parseComparison()
}

// parseComparison parses a simple comparison expression
func (p *filterParser) parseComparison() (*FilterExpression, error) {
	field, err := p.parseAttributeName()
	if err != nil {
		return nil, err
	}

	p.skipWhitespace()

	operator, err := p.parseOperator()
	if err != nil {
		return nil, err
	}

	p.skipWhitespace()

	// Handle "pr" operator (presence) - no value needed
	if operator == OpPresent {
		return &FilterExpression{
			Operator: operator,
			Field:    field,
		}, nil
	}

	value, err := p.parseValue()
	if err != nil {
		return nil, fmt.Errorf("failed to parse value: %w", err)
	}

	return &FilterExpression{
		Operator: operator,
		Field:    field,
		Value:    value,
	}, nil
}

// parseAttributeName parses a field name (may include sub-attributes like name.givenName)
func (p *filterParser) parseAttributeName() (string, error) {
	p.skipWhitespace()

	start := p.pos
	for p.pos < len(p.input) {
		c := p.input[p.pos]
		if unicode.IsLetter(rune(c)) || unicode.IsDigit(rune(c)) || c == '_' || c == '-' || c == '.' {
			p.pos++
		} else {
			break
		}
	}

	if p.pos == start {
		return "", fmt.Errorf("expected attribute name at position %d", p.pos)
	}

	return p.input[start:p.pos], nil
}

// parseOperator parses a filter operator
func (p *filterParser) parseOperator() (FilterOperator, error) {
	if p.pos+2 > len(p.input) {
		return "", fmt.Errorf("unexpected end of input while parsing operator")
	}

	twoChars := p.input[p.pos : p.pos+2]
	switch twoChars {
	case "eq":
		p.pos += 2
		return OpEqual, nil
	case "ne":
		p.pos += 2
		return OpNotEqual, nil
	case "co":
		p.pos += 2
		return OpContains, nil
	case "sw":
		p.pos += 2
		return OpStartsWith, nil
	case "ew":
		p.pos += 2
		return OpEndsWith, nil
	case "gt":
		p.pos += 2
		return OpGreaterThan, nil
	case "ge":
		p.pos += 2
		return OpGreaterEq, nil
	case "lt":
		p.pos += 2
		return OpLessThan, nil
	case "le":
		p.pos += 2
		return OpLessEq, nil
	case "pr":
		p.pos += 2
		return OpPresent, nil
	}

	return "", fmt.Errorf("invalid operator at position %d", p.pos)
}

// parseValue parses a comparison value (string or boolean)
func (p *filterParser) parseValue() (string, error) {
	p.skipWhitespace()

	if p.pos >= len(p.input) {
		return "", fmt.Errorf("unexpected end of input while parsing value")
	}

	// Check for quoted string
	if p.input[p.pos] == '"' {
		return p.parseQuotedString()
	}

	// Parse unquoted value until we hit whitespace, closing paren, or logical operator
	start := p.pos
	for p.pos < len(p.input) {
		c := p.input[p.pos]
		if unicode.IsSpace(rune(c)) || c == ')' {
			break
		}
		// Check if we're about to hit a logical operator
		if p.pos+3 <= len(p.input) {
			remaining := strings.ToLower(p.input[p.pos:])
			if strings.HasPrefix(remaining, "and ") || strings.HasPrefix(remaining, "or ") ||
				strings.HasPrefix(remaining, "and)") || strings.HasPrefix(remaining, "or)") {
				break
			}
		}
		p.pos++
	}

	if p.pos == start {
		return "", fmt.Errorf("expected value at position %d", p.pos)
	}

	return p.input[start:p.pos], nil
}

// parseQuotedString parses a double-quoted string
func (p *filterParser) parseQuotedString() (string, error) {
	if p.input[p.pos] != '"' {
		return "", fmt.Errorf("expected opening quote at position %d", p.pos)
	}
	p.pos++ // Skip opening quote

	start := p.pos
	for p.pos < len(p.input) {
		c := p.input[p.pos]
		if c == '\\' && p.pos+1 < len(p.input) {
			// Skip escaped character
			p.pos += 2
		} else if c == '"' {
			value := p.input[start:p.pos]
			p.pos++ // Skip closing quote
			return value, nil
		} else {
			p.pos++
		}
	}

	return "", fmt.Errorf("unterminated quoted string")
}

// skipWhitespace skips whitespace characters
func (p *filterParser) skipWhitespace() {
	for p.pos < len(p.input) && unicode.IsSpace(rune(p.input[p.pos])) {
		p.pos++
	}
}

// consumeKeyword consumes a keyword if the next characters match (case insensitive)
func (p *filterParser) consumeKeyword(keyword string) bool {
	if p.pos+len(keyword) > len(p.input) {
		return false
	}

	remaining := strings.ToLower(p.input[p.pos : p.pos+len(keyword)])
	if remaining != keyword {
		return false
	}

	p.pos += len(keyword)
	return true
}

// consumeParen consumes a parenthesis if it matches
func (p *filterParser) consumeParen(expected rune) bool {
	if p.pos >= len(p.input) || rune(p.input[p.pos]) != expected {
		return false
	}
	p.pos++
	return true
}

// ============================================================
// SCIM Filter to SQL Converter
// ============================================================

// SQLFilter represents a SQL WHERE clause with parameters
type SQLFilter struct {
	WhereClause string
	Args        []interface{}
}

// FilterToSQL converts a SCIM filter expression to a SQL WHERE clause
// Returns the WHERE clause and the parameter values
func FilterToSQL(expr *FilterExpression, validFields map[string]string) (*SQLFilter, error) {
	return FilterToSQLFrom(expr, validFields, 1)
}

// FilterToSQLFrom is FilterToSQL with control over the first placeholder number.
//
// A caller that has already spent $1..$n on its own parameters (tenant id,
// offset, limit) needs the filter's placeholders to continue from there rather
// than restart at $1 and collide.
func FilterToSQLFrom(expr *FilterExpression, validFields map[string]string, startIndex int) (*SQLFilter, error) {
	if expr == nil {
		return &SQLFilter{WhereClause: "", Args: nil}, nil
	}
	if startIndex < 1 {
		startIndex = 1
	}

	builder := &sqlFilterBuilder{
		validFields: validFields,
		args:        make([]interface{}, 0),
		paramIndex:  startIndex,
	}

	where, err := builder.buildFilter(expr)
	if err != nil {
		return nil, err
	}

	return &SQLFilter{
		WhereClause: where,
		Args:        builder.args,
	}, nil
}

// sqlFilterBuilder builds SQL WHERE clauses from filter expressions
type sqlFilterBuilder struct {
	validFields map[string]string // Maps SCIM field names to SQL column names
	args        []interface{}
	paramIndex  int
}

// buildFilter recursively builds the SQL WHERE clause
func (b *sqlFilterBuilder) buildFilter(expr *FilterExpression) (string, error) {
	switch expr.Operator {
	case OpAnd:
		left, err := b.buildFilter(expr.Left)
		if err != nil {
			return "", err
		}
		right, err := b.buildFilter(expr.Right)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("(%s AND %s)", left, right), nil

	case OpOr:
		left, err := b.buildFilter(expr.Left)
		if err != nil {
			return "", err
		}
		right, err := b.buildFilter(expr.Right)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("(%s OR %s)", left, right), nil

	case OpNot:
		child, err := b.buildFilter(expr.Not)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("(NOT %s)", child), nil

	default:
		return b.buildComparison(expr)
	}
}

// buildComparison builds a SQL comparison expression
func (b *sqlFilterBuilder) buildComparison(expr *FilterExpression) (string, error) {
	// Validate field
	column, ok := b.getColumnName(expr.Field)
	if !ok {
		return "", fmt.Errorf("invalid filter field: %s", expr.Field)
	}

	switch expr.Operator {
	case OpEqual:
		if b.isArrayField(expr.Field) {
			// For JSON array fields, use JSON contains
			placeholder, _ := b.addArg(expr.Value)
			return fmt.Sprintf("%s::jsonb ? %s", column, placeholder), nil
		}
		placeholder, _ := b.addArg(expr.Value)
		return fmt.Sprintf("%s = %s", column, placeholder), nil

	case OpNotEqual:
		if b.isArrayField(expr.Field) {
			placeholder, _ := b.addArg(expr.Value)
			return fmt.Sprintf("NOT (%s::jsonb ? %s)", column, placeholder), nil
		}
		placeholder, _ := b.addArg(expr.Value)
		return fmt.Sprintf("%s != %s", column, placeholder), nil

	case OpContains:
		placeholder, _ := b.addArg("%" + expr.Value + "%")
		return fmt.Sprintf("%s ILIKE %s", column, placeholder), nil

	case OpStartsWith:
		placeholder, _ := b.addArg(expr.Value + "%")
		return fmt.Sprintf("%s ILIKE %s", column, placeholder), nil

	case OpEndsWith:
		placeholder, _ := b.addArg("%" + expr.Value)
		return fmt.Sprintf("%s ILIKE %s", column, placeholder), nil

	case OpPresent:
		// Check if field has a value (not null and not empty for arrays)
		if b.isArrayField(expr.Field) {
			return fmt.Sprintf("jsonb_array_length(%s::jsonb) > 0", column), nil
		}
		return fmt.Sprintf("%s IS NOT NULL", column), nil

	case OpGreaterThan:
		// Try to parse as number, otherwise string comparison
		if num, err := strconv.ParseFloat(expr.Value, 64); err == nil {
			placeholder, _ := b.addArg(num)
			return fmt.Sprintf("%s > %s", column, placeholder), nil
		}
		placeholder, _ := b.addArg(expr.Value)
		return fmt.Sprintf("%s > %s", column, placeholder), nil

	case OpGreaterEq:
		if num, err := strconv.ParseFloat(expr.Value, 64); err == nil {
			placeholder, _ := b.addArg(num)
			return fmt.Sprintf("%s >= %s", column, placeholder), nil
		}
		placeholder, _ := b.addArg(expr.Value)
		return fmt.Sprintf("%s >= %s", column, placeholder), nil

	case OpLessThan:
		if num, err := strconv.ParseFloat(expr.Value, 64); err == nil {
			placeholder, _ := b.addArg(num)
			return fmt.Sprintf("%s < %s", column, placeholder), nil
		}
		placeholder, _ := b.addArg(expr.Value)
		return fmt.Sprintf("%s < %s", column, placeholder), nil

	case OpLessEq:
		if num, err := strconv.ParseFloat(expr.Value, 64); err == nil {
			placeholder, _ := b.addArg(num)
			return fmt.Sprintf("%s <= %s", column, placeholder), nil
		}
		placeholder, _ := b.addArg(expr.Value)
		return fmt.Sprintf("%s <= %s", column, placeholder), nil

	default:
		return "", fmt.Errorf("unsupported operator: %s", expr.Operator)
	}
}

// getColumnName maps a SCIM field name to a SQL column name
func (b *sqlFilterBuilder) getColumnName(field string) (string, bool) {
	// Check direct mapping
	if column, ok := b.validFields[field]; ok {
		return column, true
	}

	// Handle sub-attributes like name.givenName
	parts := strings.Split(field, ".")
	if len(parts) == 2 {
		if column, ok := b.validFields[parts[0]]; ok {
			// For JSON sub-fields, use JSON extraction
			return fmt.Sprintf("%s->>'%s'", column, parts[1]), true
		}
	}

	return "", false
}

// jsonArrayColumns lists columns that genuinely hold a JSON array, for which a
// comparison must use containment (`?`) rather than equality.
//
// It is empty: no column reachable from the SCIM field mappings is jsonb. It
// used to name emails/groups/roles/photos/addresses, which produced SQL like
// `emails::jsonb ? $1` against a plain VARCHAR `email` column — a runtime error
// that never surfaced because the clause was never executed. Kept as the single
// place to declare such a column if one is ever added.
var jsonArrayColumns = map[string]bool{}

// isArrayField reports whether the field maps to a JSON array column.
func (b *sqlFilterBuilder) isArrayField(field string) bool {
	column, ok := b.validFields[field]
	return ok && jsonArrayColumns[column]
}

// addArg adds a parameter and returns the updated parameter index
func (b *sqlFilterBuilder) addArg(arg interface{}) (string, error) {
	b.args = append(b.args, arg)
	idx := b.paramIndex
	b.paramIndex++
	return fmt.Sprintf("$%d", idx), nil
}

// ============================================================
// Predefined Field Mappings
// ============================================================

// GetUserFieldMapping returns the SCIM-to-SQL field mapping for users.
//
// Every entry here names a column that actually exists on the users table.
// The previous version did not: it mapped displayName to display_name and
// emails/groups/roles/photos to JSON array columns, none of which this schema
// has (see migrations — users is id, username, email, first_name, last_name,
// enabled, email_verified, external_id, org_id, timestamps). That went
// unnoticed because the generated WHERE clause was never attached to a query,
// so the invalid SQL was never sent to Postgres and the unit tests asserted
// the fictional column names right back.
//
// Attributes that cannot be expressed against this schema are deliberately
// absent rather than mapped to something invented: an unmapped attribute makes
// FilterToSQL fail, which the handlers turn into a 400 invalidFilter. Per
// RFC 7644 §3.4.2.2 that is the correct answer for a filter the server cannot
// honor — and it is far better than the previous behavior of silently ignoring
// the filter and returning every user in the tenant.
func GetUserFieldMapping() map[string]string {
	return map[string]string{
		"id":       "id",
		"userName": "username",
		"username": "username",
		// SCIM models emails as a multi-valued attribute; this schema stores a
		// single address, so both the bare attribute and its .value
		// sub-attribute resolve to that column. Okta and Entra send
		// `emails.value eq "..."` and `emails eq "..."` interchangeably.
		"emails":          "email",
		"emails.value":    "email",
		"userName.value":  "username",
		"active":          "enabled",
		"externalId":      "external_id",
		"name.givenName":  "first_name",
		"name.familyName": "last_name",
		// No display_name column exists; SCIM displayName is the composed name.
		"displayName":  "(COALESCE(first_name, '') || ' ' || COALESCE(last_name, ''))",
		"title":        "job_title",
		"department":   "department",
		"created":      "created_at",
		"meta.created": "created_at",
		"updated":      "updated_at",
		"meta.updated": "updated_at",
	}
}

// GetGroupFieldMapping returns the SCIM-to-SQL field mapping for groups.
//
// Same correction as the user mapping: displayName is the `name` column, and
// `members` is intentionally omitted because membership lives in the
// group_memberships join table and cannot be filtered by a column predicate.
// A filter on members therefore returns 400 rather than being ignored.
func GetGroupFieldMapping() map[string]string {
	return map[string]string{
		"id":           "id",
		"displayName":  "name",
		"externalId":   "external_id",
		"created":      "created_at",
		"meta.created": "created_at",
		"updated":      "updated_at",
		"meta.updated": "updated_at",
	}
}

// ============================================================
// Filter Evaluation Helper (for in-memory filtering)
// ============================================================

// EvaluateFilter evaluates a filter expression against a SCIMUser
func EvaluateFilter(expr *FilterExpression, user *SCIMUser) bool {
	if expr == nil {
		return true
	}

	return evaluateExpression(expr, user, nil)
}

// EvaluateGroupFilter evaluates a filter expression against a SCIMGroup
func EvaluateGroupFilter(expr *FilterExpression, group *SCIMGroup) bool {
	if expr == nil {
		return true
	}

	return evaluateExpression(expr, nil, group)
}

// evaluateExpression evaluates an expression against a user or group
func evaluateExpression(expr *FilterExpression, user *SCIMUser, group *SCIMGroup) bool {
	switch expr.Operator {
	case OpAnd:
		return evaluateExpression(expr.Left, user, group) && evaluateExpression(expr.Right, user, group)

	case OpOr:
		return evaluateExpression(expr.Left, user, group) || evaluateExpression(expr.Right, user, group)

	case OpNot:
		return !evaluateExpression(expr.Not, user, group)

	case OpEqual:
		return compareValues(expr.Field, expr.Value, user, group) == 0

	case OpNotEqual:
		return compareValues(expr.Field, expr.Value, user, group) != 0

	case OpContains:
		return strings.Contains(getStringValue(expr.Field, user, group), expr.Value)

	case OpStartsWith:
		return strings.HasPrefix(getStringValue(expr.Field, user, group), expr.Value)

	case OpEndsWith:
		return strings.HasSuffix(getStringValue(expr.Field, user, group), expr.Value)

	case OpPresent:
		return getStringValue(expr.Field, user, group) != ""

	default:
		return false
	}
}

// getStringValue gets the string value of a field from a user or group
func getStringValue(field string, user *SCIMUser, group *SCIMGroup) string {
	if user != nil {
		return getUserFieldValue(user, field)
	}
	if group != nil {
		return getGroupFieldValue(group, field)
	}
	return ""
}

// getUserFieldValue gets a field value from a SCIM user
func getUserFieldValue(user *SCIMUser, field string) string {
	switch field {
	case "id", "Id":
		return user.ID
	case "userName":
		return user.UserName
	case "displayName":
		if user.DisplayName != nil {
			return *user.DisplayName
		}
	case "externalId":
		if user.ExternalID != nil {
			return *user.ExternalID
		}
	case "name.givenName":
		if user.Name != nil && user.Name.GivenName != nil {
			return *user.Name.GivenName
		}
	case "name.familyName":
		if user.Name != nil && user.Name.FamilyName != nil {
			return *user.Name.FamilyName
		}
	case "nickName":
		if user.NickName != nil {
			return *user.NickName
		}
	case "title":
		if user.Title != nil {
			return *user.Title
		}
	case "userType":
		if user.UserType != nil {
			return *user.UserType
		}
	case "active":
		if user.Active != nil {
			if *user.Active {
				return "true"
			}
			return "false"
		}
	}
	return ""
}

// getGroupFieldValue gets a field value from a SCIM group
func getGroupFieldValue(group *SCIMGroup, field string) string {
	switch field {
	case "id", "Id":
		return group.ID
	case "displayName":
		return group.DisplayName
	case "externalId":
		if group.ExternalID != nil {
			return *group.ExternalID
		}
	}
	return ""
}

// compareValues compares a field value with a comparison value
// Returns 0 if equal, negative if field < value, positive if field > value
func compareValues(field, value string, user *SCIMUser, group *SCIMGroup) int {
	fieldValue := getStringValue(field, user, group)
	if fieldValue == value {
		return 0
	}
	if fieldValue < value {
		return -1
	}
	return 1
}
