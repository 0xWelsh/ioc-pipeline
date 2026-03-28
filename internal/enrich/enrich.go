package enrich

import (
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	"ioc-pipeline/internal/model"
)

// Apply enriches up to cfg.MaxItems IoCs (priority: hash, ip, domain, url).
func Apply(iocs []model.IOC, cfg Config) {
	if !cfg.Enabled() {
		return
	}

	client := &http.Client{Timeout: 25 * time.Second}
	now := time.Now().UTC().Format(time.RFC3339)
	indices := selectIndices(iocs, cfg.MaxItems)

	for _, idx := range indices {
		ioc := &iocs[idx]
		if ioc.Enrichment == nil {
			ioc.Enrichment = &model.Enrichment{EnrichedAt: now}
		} else {
			ioc.Enrichment.EnrichedAt = now
		}

		tagSet := make(map[string]struct{})
		addTag(tagSet, ioc.ThreatType)

		if cfg.VTAPIKey != "" {
			rep, err := vtFetch(client, cfg.VTAPIKey, ioc.Type, ioc.Value)
			if err != nil {
				log.Printf("enrich VT %s %s: %v", ioc.Type, ioc.Value, err)
			} else if rep != nil {
				ioc.Enrichment.VirusTotal = rep
			}
			// Free VirusTotal API: 4 lookups/min — use VTMinInterval, not the shorter OTX delay.
			time.Sleep(cfg.VTMinInterval)
		}

		if cfg.OTXAPIKey != "" {
			rep, tags, mitre, err := otxFetch(client, cfg.OTXAPIKey, ioc.Type, ioc.Value)
			if err != nil {
				log.Printf("enrich OTX %s %s: %v", ioc.Type, ioc.Value, err)
			} else if rep != nil {
				ioc.Enrichment.OTX = rep
			}
			for _, t := range tags {
				addTag(tagSet, t)
			}
			if len(mitre) > 0 {
				merged := mergeUnique(ioc.Enrichment.MITRETactics, mitre)
				sort.Strings(merged)
				ioc.Enrichment.MITRETactics = merged
			}
			time.Sleep(cfg.Sleep)
		}

		ioc.Enrichment.Tags = tagsFromSet(tagSet)
	}
}

func addTag(set map[string]struct{}, raw string) {
	t := strings.TrimSpace(strings.ToLower(raw))
	if t == "" {
		return
	}
	set[t] = struct{}{}
}

func tagsFromSet(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for t := range set {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

func mergeUnique(a, b []string) []string {
	seen := make(map[string]struct{})
	for _, s := range a {
		s = strings.TrimSpace(s)
		if s != "" {
			seen[s] = struct{}{}
		}
	}
	for _, s := range b {
		s = strings.TrimSpace(s)
		if s != "" {
			seen[s] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	return out
}

func selectIndices(iocs []model.IOC, max int) []int {
	if max <= 0 {
		return nil
	}
	order := []string{"hash", "ip", "domain", "url"}
	out := make([]int, 0, max)
	for _, typ := range order {
		for i := range iocs {
			if iocs[i].Type != typ {
				continue
			}
			out = append(out, i)
			if len(out) >= max {
				return out
			}
		}
	}
	return out
}

// Summary returns a one-line status for logs.
func Summary(cfg Config) string {
	if !cfg.Enabled() {
		return "enrichment disabled (set VT_API_KEY and/or OTX_API_KEY; optional ENRICH_MAX)"
	}
	parts := []string{fmt.Sprintf("max=%d", cfg.MaxItems)}
	if cfg.VTAPIKey != "" {
		parts = append(parts, fmt.Sprintf("VT=on(interval=%s)", cfg.VTMinInterval))
	}
	if cfg.OTXAPIKey != "" {
		parts = append(parts, "OTX=on")
	}
	return strings.Join(parts, " ")
}
