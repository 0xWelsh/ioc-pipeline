package model

type IOC struct {
	Value      string `json:"value"`
	Type       string `json:"type"` // url, ip, domain, hash
	Source     string `json:"source"`
	ThreatType string `json:"threat_type,omitempty"`
	FirstSeen  string `json:"first_seen,omitempty"`
	LastSeen   string `json:"last_seen,omitempty"`
	// Enrichment is populated for a bounded subset when API keys are configured.
	Enrichment *Enrichment `json:"enrichment,omitempty"`
}
