package enrich

import (
	"os"
	"strconv"
	"time"
)

// Config drives optional VirusTotal + OTX lookups (rate-limited for free tiers).
type Config struct {
	VTAPIKey      string
	OTXAPIKey     string
	MaxItems      int
	Sleep         time.Duration // pause after OTX (and other non-VT calls)
	VTMinInterval time.Duration // pause after each VirusTotal request (free tier: max 4 lookups/min)
}

// FromEnv reads VT_API_KEY, OTX_API_KEY, ENRICH_MAX, ENRICH_SLEEP_MS, VT_MIN_INTERVAL_MS.
// If ENRICH_MAX is unset and at least one API key is set, defaults to 12 candidates.
// Set ENRICH_MAX=0 to force-disable enrichment even when keys are present.
//
// VirusTotal free “standard” API allows 4 lookups/min; default VT_MIN_INTERVAL_MS is 16000
// so consecutive VT calls stay under that ceiling (15s minimum spacing).
func FromEnv() Config {
	explicit := os.Getenv("ENRICH_MAX")
	max, _ := strconv.Atoi(explicit)
	sleepMs, _ := strconv.Atoi(os.Getenv("ENRICH_SLEEP_MS"))
	if sleepMs <= 0 {
		sleepMs = 2000
	}
	vtGapMs, _ := strconv.Atoi(os.Getenv("VT_MIN_INTERVAL_MS"))
	if vtGapMs <= 0 {
		vtGapMs = 16000
	}
	cfg := Config{
		VTAPIKey:      os.Getenv("VT_API_KEY"),
		OTXAPIKey:     os.Getenv("OTX_API_KEY"),
		MaxItems:      max,
		Sleep:         time.Duration(sleepMs) * time.Millisecond,
		VTMinInterval: time.Duration(vtGapMs) * time.Millisecond,
	}
	if explicit == "" && (cfg.VTAPIKey != "" || cfg.OTXAPIKey != "") {
		cfg.MaxItems = 12
	}
	return cfg
}

func (c Config) Enabled() bool {
	return c.MaxItems > 0 && (c.VTAPIKey != "" || c.OTXAPIKey != "")
}
