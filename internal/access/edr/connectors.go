package edr

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// httpDo is a small helper shared by the connectors: it issues a request with
// the given bearer/basic auth and decodes a JSON response, surfacing non-2xx as
// an error with the body.
func httpDo(ctx context.Context, client *http.Client, method, urlStr string, header http.Header, body io.Reader, out interface{}) error {
	req, err := http.NewRequestWithContext(ctx, method, urlStr, body)
	if err != nil {
		return err
	}
	for k, vs := range header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%s %s: %d: %s", method, urlStr, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	if out != nil && len(b) > 0 {
		if err := json.Unmarshal(b, out); err != nil {
			return fmt.Errorf("decode %s: %w", urlStr, err)
		}
	}
	return nil
}

func defaultClient() *http.Client { return &http.Client{Timeout: 30 * time.Second} }

// ---------------------------------------------------------------------------
// CrowdStrike Falcon
// ---------------------------------------------------------------------------

type crowdStrike struct {
	cfg    Config
	base   string
	client *http.Client
}

func newCrowdStrike(cfg Config) *crowdStrike {
	base := strings.TrimRight(cfg.BaseURL, "/")
	if base == "" {
		base = "https://api.crowdstrike.com"
	}
	return &crowdStrike{cfg: cfg, base: base, client: defaultClient()}
}

func (c *crowdStrike) Provider() string { return ProviderCrowdStrike }

// token gets an OAuth2 client-credentials bearer from Falcon.
func (c *crowdStrike) token(ctx context.Context) (string, error) {
	form := url.Values{"client_id": {c.cfg.ClientID}, "client_secret": {c.cfg.ClientSecret}}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	h := http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}
	if err := httpDo(ctx, c.client, http.MethodPost, c.base+"/oauth2/token", h,
		strings.NewReader(form.Encode()), &out); err != nil {
		return "", fmt.Errorf("crowdstrike token: %w", err)
	}
	if out.AccessToken == "" {
		return "", fmt.Errorf("crowdstrike token: empty access_token")
	}
	return out.AccessToken, nil
}

func (c *crowdStrike) TestConnection(ctx context.Context) error {
	_, err := c.token(ctx)
	return err
}

func (c *crowdStrike) ListDevices(ctx context.Context) ([]Device, error) {
	tok, err := c.token(ctx)
	if err != nil {
		return nil, err
	}
	auth := http.Header{"Authorization": {"Bearer " + tok}}

	// 1) Query device ids.
	var idsResp struct {
		Resources []string `json:"resources"`
	}
	if err := httpDo(ctx, c.client, http.MethodGet, c.base+"/devices/queries/devices/v1?limit=5000", auth, nil, &idsResp); err != nil {
		return nil, err
	}
	if len(idsResp.Resources) == 0 {
		return nil, nil
	}

	// 2) Fetch device detail. POST ids to entities endpoint.
	reqBody, _ := json.Marshal(map[string][]string{"ids": idsResp.Resources})
	postHeader := auth.Clone()
	postHeader.Set("Content-Type", "application/json")
	var detail struct {
		Resources []struct {
			DeviceID                 string `json:"device_id"`
			Hostname                 string `json:"hostname"`
			SerialNumber             string `json:"serial_number"`
			Email                    string `json:"email"`
			ReducedFunctionalityMode string `json:"reduced_functionality_mode"`
			Status                   string `json:"status"`
			LastSeen                 string `json:"last_seen"`
		} `json:"resources"`
	}
	if err := httpDo(ctx, c.client, http.MethodPost, c.base+"/devices/entities/devices/v2", postHeader,
		strings.NewReader(string(reqBody)), &detail); err != nil {
		return nil, err
	}

	devices := make([]Device, 0, len(detail.Resources))
	for _, r := range detail.Resources {
		// "contained"/"containment_pending" host status or RFM on => not compliant.
		compliant := r.Status == "normal" && !strings.EqualFold(r.ReducedFunctionalityMode, "yes")
		risk := RiskLow
		if !compliant {
			risk = RiskHigh
		}
		devices = append(devices, Device{
			ExternalID: r.DeviceID,
			Serial:     r.SerialNumber,
			Hostname:   r.Hostname,
			Email:      r.Email,
			Compliant:  compliant,
			Risk:       risk,
			LastSeen:   r.LastSeen,
			Raw:        map[string]interface{}{"status": r.Status, "rfm": r.ReducedFunctionalityMode},
		})
	}
	return devices, nil
}

// ---------------------------------------------------------------------------
// Microsoft Intune (via Microsoft Graph)
// ---------------------------------------------------------------------------

type intune struct {
	cfg    Config
	base   string
	client *http.Client
}

func newIntune(cfg Config) *intune {
	base := strings.TrimRight(cfg.BaseURL, "/")
	if base == "" {
		base = "https://graph.microsoft.com"
	}
	return &intune{cfg: cfg, base: base, client: defaultClient()}
}

func (i *intune) Provider() string { return ProviderIntune }

func (i *intune) token(ctx context.Context) (string, error) {
	tokenURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", i.cfg.TenantID)
	form := url.Values{
		"client_id":     {i.cfg.ClientID},
		"client_secret": {i.cfg.ClientSecret},
		"scope":         {"https://graph.microsoft.com/.default"},
		"grant_type":    {"client_credentials"},
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	h := http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}
	if err := httpDo(ctx, i.client, http.MethodPost, tokenURL, h, strings.NewReader(form.Encode()), &out); err != nil {
		return "", fmt.Errorf("intune token: %w", err)
	}
	if out.AccessToken == "" {
		return "", fmt.Errorf("intune token: empty access_token")
	}
	return out.AccessToken, nil
}

func (i *intune) TestConnection(ctx context.Context) error {
	_, err := i.token(ctx)
	return err
}

func (i *intune) ListDevices(ctx context.Context) ([]Device, error) {
	tok, err := i.token(ctx)
	if err != nil {
		return nil, err
	}
	return i.listWithToken(ctx, tok)
}

// listWithToken pages the Graph managedDevices endpoint with a resolved token.
// Split from ListDevices so the graph mapping is testable without the external
// login.microsoftonline.com token endpoint.
func (i *intune) listWithToken(ctx context.Context, tok string) ([]Device, error) {
	auth := http.Header{"Authorization": {"Bearer " + tok}, "Accept": {"application/json"}}

	next := i.base + "/v1.0/deviceManagement/managedDevices?$select=id,deviceName,serialNumber,emailAddress,complianceState,lastSyncDateTime&$top=200"
	var devices []Device
	for next != "" {
		var page struct {
			Value []struct {
				ID               string `json:"id"`
				DeviceName       string `json:"deviceName"`
				SerialNumber     string `json:"serialNumber"`
				EmailAddress     string `json:"emailAddress"`
				ComplianceState  string `json:"complianceState"`
				LastSyncDateTime string `json:"lastSyncDateTime"`
			} `json:"value"`
			NextLink string `json:"@odata.nextLink"`
		}
		if err := httpDo(ctx, i.client, http.MethodGet, next, auth, nil, &page); err != nil {
			return nil, err
		}
		for _, d := range page.Value {
			compliant := strings.EqualFold(d.ComplianceState, "compliant")
			risk := RiskLow
			if !compliant {
				risk = RiskHigh
			}
			devices = append(devices, Device{
				ExternalID: d.ID,
				Serial:     d.SerialNumber,
				Hostname:   d.DeviceName,
				Email:      d.EmailAddress,
				Compliant:  compliant,
				Risk:       risk,
				LastSeen:   d.LastSyncDateTime,
				Raw:        map[string]interface{}{"complianceState": d.ComplianceState},
			})
		}
		next = page.NextLink
	}
	return devices, nil
}

// ---------------------------------------------------------------------------
// Wazuh (open-source EDR/XDR)
//
// Endpoints run the Wazuh agent (Linux/Windows/macOS); agents enroll against a
// self-hosted Wazuh manager, and this connector reads agent health from the
// manager's REST API (default port 55000). Auth is basic api_user:api_token →
// short-lived JWT (POST /security/user/authenticate), then GET /agents pages
// through the fleet.
//
// Compliance mapping: an agent that is actively reporting ("active") passes;
// "disconnected" fails at high risk (the endpoint dropped off EDR coverage —
// exactly what a zero-trust posture check must catch); "never_connected" /
// "pending" fail as unknown (enrolled but not yet protected). Wazuh agents
// have no serial/email, so the natural match strategy is hostname (the agent
// name defaults to the endpoint's hostname).
//
// TLS: the manager API must present a certificate the access-service trusts —
// mount the Wazuh CA into the container trust store; verification is never
// skipped (consistent with the platform's production TLS posture).
// ---------------------------------------------------------------------------

type wazuh struct {
	cfg    Config
	base   string
	client *http.Client
}

func newWazuh(cfg Config) *wazuh {
	return &wazuh{cfg: cfg, base: strings.TrimRight(cfg.BaseURL, "/"), client: defaultClient()}
}

func (w *wazuh) Provider() string { return ProviderWazuh }

// token exchanges basic credentials for a Wazuh API JWT.
func (w *wazuh) token(ctx context.Context) (string, error) {
	if w.base == "" {
		return "", fmt.Errorf("wazuh base_url is required (e.g. https://wazuh-manager:55000)")
	}
	basic := base64.StdEncoding.EncodeToString([]byte(w.cfg.APIUser + ":" + w.cfg.APIToken))
	h := http.Header{"Authorization": {"Basic " + basic}, "Accept": {"application/json"}}
	var out struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	if err := httpDo(ctx, w.client, http.MethodPost, w.base+"/security/user/authenticate", h, nil, &out); err != nil {
		return "", fmt.Errorf("wazuh token: %w", err)
	}
	if out.Data.Token == "" {
		return "", fmt.Errorf("wazuh token: empty token")
	}
	return out.Data.Token, nil
}

func (w *wazuh) TestConnection(ctx context.Context) error {
	_, err := w.token(ctx)
	return err
}

func (w *wazuh) ListDevices(ctx context.Context) ([]Device, error) {
	tok, err := w.token(ctx)
	if err != nil {
		return nil, err
	}
	auth := http.Header{"Authorization": {"Bearer " + tok}, "Accept": {"application/json"}}

	const pageSize = 500
	var devices []Device
	offset := 0
	for {
		endpoint := fmt.Sprintf(
			"%s/agents?offset=%d&limit=%d&select=id,name,ip,status,lastKeepAlive,os.name,os.version",
			w.base, offset, pageSize)
		var resp struct {
			Data struct {
				AffectedItems []struct {
					ID            string `json:"id"`
					Name          string `json:"name"`
					IP            string `json:"ip"`
					Status        string `json:"status"`
					LastKeepAlive string `json:"lastKeepAlive"`
					OS            struct {
						Name    string `json:"name"`
						Version string `json:"version"`
					} `json:"os"`
				} `json:"affected_items"`
				TotalAffectedItems int `json:"total_affected_items"`
			} `json:"data"`
		}
		if err := httpDo(ctx, w.client, http.MethodGet, endpoint, auth, nil, &resp); err != nil {
			return nil, err
		}
		for _, a := range resp.Data.AffectedItems {
			// Agent 000 is the Wazuh manager itself, not an endpoint.
			if a.ID == "000" {
				continue
			}
			var compliant bool
			var risk string
			switch strings.ToLower(a.Status) {
			case "active":
				compliant, risk = true, RiskLow
			case "disconnected":
				// EDR coverage dropped — fail hard so continuous-verify severs.
				compliant, risk = false, RiskHigh
			default: // never_connected, pending
				compliant, risk = false, RiskUnknown
			}
			devices = append(devices, Device{
				ExternalID: a.ID,
				Hostname:   a.Name, // agent name defaults to the endpoint hostname
				Compliant:  compliant,
				Risk:       risk,
				LastSeen:   a.LastKeepAlive,
				Raw: map[string]interface{}{
					"status": a.Status,
					"ip":     a.IP,
					"os":     strings.TrimSpace(a.OS.Name + " " + a.OS.Version),
				},
			})
		}
		offset += len(resp.Data.AffectedItems)
		if len(resp.Data.AffectedItems) < pageSize || offset >= resp.Data.TotalAffectedItems {
			break
		}
	}
	return devices, nil
}

// ---------------------------------------------------------------------------
// Jamf Pro (macOS/iOS MDM)
// ---------------------------------------------------------------------------

type jamf struct {
	cfg    Config
	base   string
	client *http.Client
}

func newJamf(cfg Config) *jamf {
	return &jamf{cfg: cfg, base: strings.TrimRight(cfg.BaseURL, "/"), client: defaultClient()}
}

func (j *jamf) Provider() string { return ProviderJamf }

// token gets a Jamf Pro bearer token from basic credentials.
func (j *jamf) token(ctx context.Context) (string, error) {
	basic := base64.StdEncoding.EncodeToString([]byte(j.cfg.APIUser + ":" + j.cfg.APIToken))
	h := http.Header{"Authorization": {"Basic " + basic}, "Accept": {"application/json"}}
	var out struct {
		Token string `json:"token"`
	}
	if err := httpDo(ctx, j.client, http.MethodPost, j.base+"/api/v1/auth/token", h, nil, &out); err != nil {
		return "", fmt.Errorf("jamf token: %w", err)
	}
	if out.Token == "" {
		return "", fmt.Errorf("jamf token: empty token")
	}
	return out.Token, nil
}

func (j *jamf) TestConnection(ctx context.Context) error {
	if j.base == "" {
		return fmt.Errorf("jamf base_url is required")
	}
	_, err := j.token(ctx)
	return err
}

func (j *jamf) ListDevices(ctx context.Context) ([]Device, error) {
	tok, err := j.token(ctx)
	if err != nil {
		return nil, err
	}
	auth := http.Header{"Authorization": {"Bearer " + tok}, "Accept": {"application/json"}}

	var devices []Device
	page := 0
	for {
		endpoint := fmt.Sprintf("%s/api/v1/computers-inventory?section=GENERAL&section=HARDWARE&page=%d&page-size=200", j.base, page)
		var resp struct {
			TotalCount int `json:"totalCount"`
			Results    []struct {
				ID      string `json:"id"`
				General struct {
					Name            string `json:"name"`
					LastContactTime string `json:"lastContactTime"`
				} `json:"general"`
				Hardware struct {
					SerialNumber string `json:"serialNumber"`
				} `json:"hardware"`
				UserAndLocation struct {
					Email string `json:"email"`
				} `json:"userAndLocation"`
			} `json:"results"`
		}
		if err := httpDo(ctx, j.client, http.MethodGet, endpoint, auth, nil, &resp); err != nil {
			return nil, err
		}
		if len(resp.Results) == 0 {
			break
		}
		for _, r := range resp.Results {
			// Jamf inventory presence implies managed; compliance modeled as
			// managed=compliant here (smart-group-driven compliance can refine).
			devices = append(devices, Device{
				ExternalID: r.ID,
				Serial:     r.Hardware.SerialNumber,
				Hostname:   r.General.Name,
				Email:      r.UserAndLocation.Email,
				Compliant:  true,
				Risk:       RiskLow,
				LastSeen:   r.General.LastContactTime,
				Raw:        map[string]interface{}{"managed": true},
			})
		}
		if len(devices) >= resp.TotalCount || len(resp.Results) < 200 {
			break
		}
		page++
	}
	return devices, nil
}
