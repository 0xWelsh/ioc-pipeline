package model

// Enrichment holds optional third-party context for researchers (VT, OTX, etc.).
type Enrichment struct {
	EnrichedAt   string     `json:"enriched_at,omitempty"`
	VirusTotal   *VTReport  `json:"virus_total,omitempty"`
	OTX          *OTXReport `json:"otx,omitempty"`
	Tags         []string   `json:"tags,omitempty"`
	MITRETactics []string   `json:"mitre_tactics,omitempty"`
}

// VTReport summarizes VirusTotal v3 last_analysis_stats (engine consensus).
type VTReport struct {
	Malicious    int    `json:"malicious"`
	Suspicious   int    `json:"suspicious"`
	Harmless     int    `json:"harmless"`
	Undetected   int    `json:"undetected"`
	AnalysisDate string `json:"analysis_date,omitempty"`
	Permalink    string `json:"permalink,omitempty"`
}

// OTXReport summarizes AlienVault OTX pulse visibility for the indicator.
type OTXReport struct {
	PulseCount int      `json:"pulse_count"`
	PulseNames []string `json:"pulse_names,omitempty"`
}
