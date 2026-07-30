package directory

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"unicode/utf16"

	"github.com/go-ldap/ldap/v3"
	"go.uber.org/zap"
)

// ErrPasswordComplexity indicates the password doesn't meet AD complexity requirements
var ErrPasswordComplexity = errors.New("password does not meet complexity requirements")

// ErrPasswordTooShort indicates the password is too short
var ErrPasswordTooShort = errors.New("password is too short")

// ErrPasswordHistory indicates the password was recently used
var ErrPasswordHistory = errors.New("password was recently used and cannot be reused")

// ErrPasswordInvalid indicates the current password is incorrect
var ErrPasswordInvalid = errors.New("current password is incorrect")

// LDAPConnector manages LDAP connections and searches
type LDAPConnector struct {
	cfg    LDAPConfig
	logger *zap.Logger
}

// NewLDAPConnector creates a new LDAP connector
func NewLDAPConnector(cfg LDAPConfig, logger *zap.Logger) *LDAPConnector {
	return &LDAPConnector{
		cfg:    cfg,
		logger: logger.With(zap.String("component", "ldap-connector")),
	}
}

// Connect establishes an LDAP connection with TLS/StartTLS and binds
func (c *LDAPConnector) Connect() (*ldap.Conn, error) {
	addr := fmt.Sprintf("%s:%d", c.cfg.Host, c.cfg.Port)

	tlsConfig := &tls.Config{
		InsecureSkipVerify: c.cfg.SkipTLSVerify,
		ServerName:         c.cfg.Host,
	}

	var conn *ldap.Conn
	var err error

	if c.cfg.UseTLS {
		conn, err = ldap.DialTLS("tcp", addr, tlsConfig) //nolint:staticcheck // TODO: migrate to ldap.DialURL (needs live-LDAP verification)
	} else {
		conn, err = ldap.Dial("tcp", addr) //nolint:staticcheck // TODO: migrate to ldap.DialURL (needs live-LDAP verification)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to connect to LDAP server %s: %w", addr, err)
	}

	if c.cfg.StartTLS && !c.cfg.UseTLS {
		if err := conn.StartTLS(tlsConfig); err != nil {
			conn.Close()
			return nil, fmt.Errorf("StartTLS failed: %w", err)
		}
	}

	if err := conn.Bind(c.cfg.BindDN, c.cfg.BindPassword); err != nil {
		conn.Close()
		return nil, fmt.Errorf("LDAP bind failed: %w", err)
	}

	return conn, nil
}

// TestConnection verifies LDAP connectivity, bind, and a simple search
func (c *LDAPConnector) TestConnection() error {
	conn, err := c.Connect()
	if err != nil {
		return err
	}
	defer conn.Close()

	baseDN := c.cfg.BaseDN
	searchReq := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1, 0, false,
		"(objectClass=*)",
		[]string{"dn"},
		nil,
	)

	_, err = conn.Search(searchReq)
	if err != nil {
		return fmt.Errorf("test search failed: %w", err)
	}

	c.logger.Info("LDAP connection test successful", zap.String("host", c.cfg.Host))
	return nil
}

// SearchUsers performs a paged search for user entries
func (c *LDAPConnector) SearchUsers(conn *ldap.Conn) ([]*ldap.Entry, error) {
	baseDN := c.cfg.UserBaseDN
	if baseDN == "" {
		baseDN = c.cfg.BaseDN
	}

	filter := c.cfg.UserFilter
	if filter == "" {
		filter = "(objectClass=inetOrgPerson)"
	}

	attrs := c.userAttributes()
	pageSize := c.cfg.PageSize
	if pageSize <= 0 {
		pageSize = 500
	}

	return c.pagedSearch(conn, baseDN, filter, attrs, pageSize)
}

// SearchGroups performs a paged search for group entries
func (c *LDAPConnector) SearchGroups(conn *ldap.Conn) ([]*ldap.Entry, error) {
	baseDN := c.cfg.GroupBaseDN
	if baseDN == "" {
		baseDN = c.cfg.BaseDN
	}

	filter := c.cfg.GroupFilter
	if filter == "" {
		filter = "(objectClass=groupOfNames)"
	}

	memberAttr := c.cfg.MemberAttribute
	if memberAttr == "" {
		memberAttr = "member"
	}

	attrs := []string{"dn", "cn", "description", memberAttr}
	if c.cfg.AttributeMapping.GroupName != "" {
		attrs = append(attrs, c.cfg.AttributeMapping.GroupName)
	}

	pageSize := c.cfg.PageSize
	if pageSize <= 0 {
		pageSize = 500
	}

	return c.pagedSearch(conn, baseDN, filter, attrs, pageSize)
}

// SearchUsersIncremental searches for users modified since a given marker
func (c *LDAPConnector) SearchUsersIncremental(conn *ldap.Conn, sinceUSN int64, sinceTimestamp string) ([]*ldap.Entry, error) {
	baseDN := c.cfg.UserBaseDN
	if baseDN == "" {
		baseDN = c.cfg.BaseDN
	}

	baseFilter := c.cfg.UserFilter
	if baseFilter == "" {
		baseFilter = "(objectClass=inetOrgPerson)"
	}

	var filter string
	if sinceUSN > 0 {
		// Active Directory incremental sync
		filter = fmt.Sprintf("(&%s(uSNChanged>=%d))", baseFilter, sinceUSN)
	} else if sinceTimestamp != "" {
		// OpenLDAP incremental sync
		filter = fmt.Sprintf("(&%s(modifyTimestamp>=%s))", baseFilter, sinceTimestamp)
	} else {
		filter = baseFilter
	}

	attrs := c.userAttributes()
	// Add tracking attributes for incremental sync
	attrs = append(attrs, "uSNChanged", "modifyTimestamp")

	pageSize := c.cfg.PageSize
	if pageSize <= 0 {
		pageSize = 500
	}

	return c.pagedSearch(conn, baseDN, filter, attrs, pageSize)
}

// AuthenticateUser binds as the user to verify credentials
func (c *LDAPConnector) AuthenticateUser(username, password string) error {
	conn, err := c.Connect()
	if err != nil {
		return err
	}
	defer conn.Close()

	userDN, err := c.findUserDN(conn, username)
	if err != nil {
		return err
	}

	// Bind as the user to verify password
	if err := conn.Bind(userDN, password); err != nil {
		return fmt.Errorf("LDAP authentication failed: %w", err)
	}

	return nil
}

// VerifyBind opens a fresh connection, resolves the user DN, then attempts to bind
// as the user with the given password. Returns nil on success, the bind error otherwise.
func (c *LDAPConnector) VerifyBind(username, password string) error {
	conn, err := c.Connect()
	if err != nil {
		return err
	}
	defer conn.Close()

	userDN, err := c.findUserDN(conn, username)
	if err != nil {
		return err
	}

	if err := conn.Bind(userDN, password); err != nil {
		return err
	}
	return nil
}

// ChangePassword changes a user's password via LDAP Password Modify Extended Operation (RFC 3062).
// The user's current password is verified first by rebinding.
func (c *LDAPConnector) ChangePassword(username, oldPassword, newPassword string) error {
	conn, err := c.Connect()
	if err != nil {
		return err
	}
	defer conn.Close()

	userDN, err := c.findUserDN(conn, username)
	if err != nil {
		return err
	}

	// Re-bind as the user to verify old password
	if err := conn.Bind(userDN, oldPassword); err != nil {
		return ErrPasswordInvalid
	}

	if c.isActiveDirectory() {
		// AD: use unicodePwd attribute replace (old → new)
		return c.changePasswordAD(conn, userDN, oldPassword, newPassword)
	}

	// Standard LDAP: Password Modify Extended Operation (RFC 3062)
	req := ldap.NewPasswordModifyRequest(userDN, oldPassword, newPassword)
	_, err = conn.PasswordModify(req)
	if err != nil {
		return c.parseLDAPPasswordError(err)
	}
	return nil
}

// ResetPassword resets a user's password without knowing the old password (admin/service account operation).
func (c *LDAPConnector) ResetPassword(username, newPassword string) error {
	conn, err := c.Connect()
	if err != nil {
		return err
	}
	defer conn.Close()

	userDN, err := c.findUserDN(conn, username)
	if err != nil {
		return err
	}

	if c.isActiveDirectory() {
		return c.resetPasswordAD(conn, userDN, newPassword)
	}

	// Standard LDAP: Password Modify with empty old password (service account privilege)
	req := ldap.NewPasswordModifyRequest(userDN, "", newPassword)
	_, err = conn.PasswordModify(req)
	if err != nil {
		return c.parseLDAPPasswordError(err)
	}
	return nil
}

// buildUserSearchFilter constructs the LDAP search filter used to resolve a
// login user's DN. It matches the supplied identifier against the configured
// username attribute AND userPrincipalName when the identifier looks like a UPN
// (contains '@') or the directory is Active Directory — so operators can log in
// with either their sAMAccountName (jdoe) or their UPN (jdoe@corp.local). The
// extra clause is harmless on OpenLDAP (userPrincipalName never matches there).
// Falls back to (objectClass=inetOrgPerson) when no user filter is configured.
func buildUserSearchFilter(userFilter, usernameAttr, username string, isAD bool) string {
	idClause := fmt.Sprintf("(%s=%s)", ldap.EscapeFilter(usernameAttr), ldap.EscapeFilter(username))
	if (isAD || strings.Contains(username, "@")) && usernameAttr != "userPrincipalName" {
		idClause = fmt.Sprintf("(|(%s=%s)(userPrincipalName=%s))",
			ldap.EscapeFilter(usernameAttr), ldap.EscapeFilter(username), ldap.EscapeFilter(username))
	}
	if userFilter == "" {
		return fmt.Sprintf("(&(objectClass=inetOrgPerson)%s)", idClause)
	}
	return fmt.Sprintf("(&%s%s)", userFilter, idClause)
}

// findUserDN looks up a user's DN by username
func (c *LDAPConnector) findUserDN(conn *ldap.Conn, username string) (string, error) {
	baseDN := c.cfg.UserBaseDN
	if baseDN == "" {
		baseDN = c.cfg.BaseDN
	}

	usernameAttr := c.cfg.AttributeMapping.Username
	if usernameAttr == "" {
		usernameAttr = "uid"
	}

	filter := buildUserSearchFilter(c.cfg.UserFilter, usernameAttr, username, c.isActiveDirectory())

	searchReq := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1, 0, false,
		filter,
		[]string{"dn"},
		nil,
	)

	result, err := conn.Search(searchReq)
	if err != nil {
		return "", fmt.Errorf("user search failed: %w", err)
	}

	if len(result.Entries) == 0 {
		return "", fmt.Errorf("user not found in LDAP")
	}

	return result.Entries[0].DN, nil
}

// changePasswordAD changes a user's password via AD's unicodePwd attribute.
// Requires the connection to be bound as the user (old password already verified).
func (c *LDAPConnector) changePasswordAD(conn *ldap.Conn, userDN, oldPassword, newPassword string) error {
	modReq := ldap.NewModifyRequest(userDN, nil)
	modReq.Delete("unicodePwd", []string{string(encodePasswordAD(oldPassword))})
	modReq.Add("unicodePwd", []string{string(encodePasswordAD(newPassword))})

	if err := conn.Modify(modReq); err != nil {
		return c.parseLDAPPasswordError(err)
	}
	return nil
}

// resetPasswordAD resets a user's password via AD's unicodePwd attribute (admin/service account operation).
func (c *LDAPConnector) resetPasswordAD(conn *ldap.Conn, userDN, newPassword string) error {
	modReq := ldap.NewModifyRequest(userDN, nil)
	modReq.Replace("unicodePwd", []string{string(encodePasswordAD(newPassword))})

	if err := conn.Modify(modReq); err != nil {
		return c.parseLDAPPasswordError(err)
	}
	return nil
}

// encodePasswordAD encodes a password for AD's unicodePwd attribute (UTF-16LE, wrapped in
// double quotes per Microsoft's spec). The encoded bytes are sent as a binary LDAP attribute
// value in a ModifyRequest (length-delimited on the wire) — never interpolated into a filter,
// DN, or other parsed context — so an embedded double quote in the password cannot "break out";
// AD strips only the outermost quotes, so the password is preserved verbatim. We assemble the
// quoted rune slice directly (rather than concatenating quote characters into a string) so the
// delimiter quotes are structural, not string-formatted around untrusted input.
func encodePasswordAD(password string) []byte {
	pw := utf16.Encode([]rune(password))
	// Bound the length before any size computation to rule out integer overflow in the
	// allocation below (a real AD password is at most 256 chars; anything near this cap is
	// invalid input, not a legitimate password).
	if len(pw) > 1<<20 {
		return nil
	}
	// One allocation: the UTF-16LE password bracketed by two literal quote code units. Writing
	// the quote code units directly (rather than concatenating quote characters into a string)
	// keeps the delimiters structural — the bytes are identical to UTF-16LE of `"`+password+`"`.
	const quoteLE = uint16('"')
	buf := make([]byte, (len(pw)+2)*2)
	binary.LittleEndian.PutUint16(buf[0:], quoteLE)
	for i, r := range pw {
		binary.LittleEndian.PutUint16(buf[(i+1)*2:], r)
	}
	binary.LittleEndian.PutUint16(buf[(len(pw)+1)*2:], quoteLE)
	return buf
}

// isActiveDirectory returns true if the directory type is configured as Active Directory
func (c *LDAPConnector) isActiveDirectory() bool {
	return c.cfg.DirectoryType == "active_directory"
}

// parseLDAPPasswordError converts LDAP error codes to user-friendly error messages
func (c *LDAPConnector) parseLDAPPasswordError(err error) error {
	if err == nil {
		return nil
	}

	errStr := err.Error()

	// AD returns constraint violation (LDAP result code 19) with data codes in the message
	var ldapErr *ldap.Error
	if errors.As(err, &ldapErr) {
		switch ldapErr.ResultCode {
		case ldap.LDAPResultConstraintViolation:
			// Parse AD sub-error codes from the diagnostic message
			if strings.Contains(errStr, "0052D") || strings.Contains(errStr, "052D") {
				return ErrPasswordComplexity
			}
			if strings.Contains(errStr, "00524") || strings.Contains(errStr, "0524") {
				return ErrPasswordTooShort
			}
			if strings.Contains(errStr, "00553") || strings.Contains(errStr, "0553") {
				return ErrPasswordHistory
			}
			return fmt.Errorf("password policy violation: %w", err)
		case ldap.LDAPResultInvalidCredentials:
			return ErrPasswordInvalid
		case ldap.LDAPResultUnwillingToPerform:
			return fmt.Errorf("server refused password change (TLS may be required): %w", err)
		}
	}

	c.logger.Warn("LDAP password operation failed", zap.Error(err))
	return fmt.Errorf("password change failed: %w", err)
}

// userAttributes returns the list of LDAP attributes to fetch for users
func (c *LDAPConnector) userAttributes() []string {
	m := c.cfg.AttributeMapping
	attrs := []string{"dn"}

	add := func(a string) {
		if a != "" {
			attrs = append(attrs, a)
		}
	}

	add(m.Username)
	add(m.Email)
	add(m.FirstName)
	add(m.LastName)
	add(m.DisplayName)

	// Ensure we have sensible defaults
	if m.Username == "" {
		attrs = append(attrs, "uid")
	}
	if m.Email == "" {
		attrs = append(attrs, "mail")
	}
	if m.FirstName == "" {
		attrs = append(attrs, "givenName")
	}
	if m.LastName == "" {
		attrs = append(attrs, "sn")
	}
	if m.DisplayName == "" {
		attrs = append(attrs, "cn")
	}

	return attrs
}

// pagedSearch performs a paged LDAP search
func (c *LDAPConnector) pagedSearch(conn *ldap.Conn, baseDN, filter string, attrs []string, pageSize int) ([]*ldap.Entry, error) {
	searchReq := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		filter,
		attrs,
		[]ldap.Control{ldap.NewControlPaging(uint32(pageSize))},
	)

	var allEntries []*ldap.Entry

	for {
		result, err := conn.Search(searchReq)
		if err != nil {
			return nil, fmt.Errorf("LDAP search failed: %w", err)
		}

		allEntries = append(allEntries, result.Entries...)

		pagingControl := ldap.FindControl(result.Controls, ldap.ControlTypePaging)
		if pagingControl == nil {
			break
		}

		paging, ok := pagingControl.(*ldap.ControlPaging)
		if !ok || len(paging.Cookie) == 0 {
			break
		}

		// Set the cookie for next page
		searchReq.Controls = []ldap.Control{ldap.NewControlPaging(uint32(pageSize))}
		searchReq.Controls[0].(*ldap.ControlPaging).SetCookie(paging.Cookie)
	}

	c.logger.Debug("LDAP search completed",
		zap.String("baseDN", baseDN),
		zap.String("filter", filter),
		zap.Int("results", len(allEntries)),
	)

	return allEntries, nil
}
