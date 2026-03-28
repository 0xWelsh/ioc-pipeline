package model

type IOC struct {
	Value       string   `json:"value"`
	Type        string   `json:"type"` // url, ip, domain, hash
	Source      string   `json:"source,omitempty"`
	Sources     []string `json:"sources,omitempty"`
	ThreatType  string   `json:"threat_type,omitempty"`
	ThreatTypes []string `json:"threat_types,omitempty"`
	FirstSeen   string   `json:"first_seen,omitempty"`
	SeenCount   int      `json:"seen_count,omitempty"`
}
