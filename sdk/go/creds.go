package kepr

import "encoding/json"

// CredInfo is one credential's metadata as List reports it. It never
// carries a value.
type CredInfo struct {
	Name            string   `json:"name"`
	Size            uint64   `json:"size"`
	Modified        string   `json:"modified"`
	ExpiresAt       string   `json:"expires_at,omitempty"`
	RecordType      string   `json:"record_type,omitempty"`
	BoundHosts      []string `json:"bound_hosts,omitempty"`
	Sealed          bool     `json:"sealed,omitempty"`
	RequiresConsent bool     `json:"requires_consent,omitempty"`
	RequiresFIDO2   bool     `json:"requires_fido2,omitempty"`
	// Tags and Folder are filled by daemons that support them (plan T5.01).
	Tags   []string `json:"tags,omitempty"`
	Folder string   `json:"folder,omitempty"`
}

// Credentials returns every credential's metadata, typed.
func (c *Client) Credentials() ([]CredInfo, error) {
	r, err := c.expect(map[string]any{"cmd": "list"}, "list_ok")
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(r["credentials"])
	if err != nil {
		return nil, &Error{"malformed reply"}
	}
	var out []CredInfo
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, &Error{"malformed reply"}
	}
	return out, nil
}

// Info returns one credential's metadata, or nil when there is none by
// that name.
func (c *Client) Info(name string) (*CredInfo, error) {
	n, err := upper(name)
	if err != nil {
		return nil, err
	}
	all, err := c.Credentials()
	if err != nil {
		return nil, err
	}
	for i := range all {
		if all[i].Name == n {
			return &all[i], nil
		}
	}
	return nil, nil
}
