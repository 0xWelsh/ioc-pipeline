package dedup

import (
	"sort"
	"strings"

	"ioc-pipeline/internal/model"
)

func Process(iocs []model.IOC) []model.IOC {
	merged := make(map[string]model.IOC, len(iocs))

	for _, ioc := range iocs {
		key := dedupKey(ioc)
		existing, ok := merged[key]
		if !ok {
			ioc.Sources = uniqueSorted(append(ioc.Sources, ioc.Source))
			ioc.ThreatTypes = uniqueSorted(append(ioc.ThreatTypes, ioc.ThreatType))
			ioc.Source = firstOrEmpty(ioc.Sources)
			ioc.ThreatType = firstOrEmpty(ioc.ThreatTypes)
			ioc.SeenCount = 1
			merged[key] = ioc
			continue
		}

		existing.Sources = uniqueSorted(append(append(existing.Sources, existing.Source, ioc.Source), ioc.Sources...))
		existing.ThreatTypes = uniqueSorted(append(append(existing.ThreatTypes, existing.ThreatType, ioc.ThreatType), ioc.ThreatTypes...))
		existing.Source = firstOrEmpty(existing.Sources)
		existing.ThreatType = firstOrEmpty(existing.ThreatTypes)
		if existing.FirstSeen == "" || (ioc.FirstSeen != "" && ioc.FirstSeen < existing.FirstSeen) {
			existing.FirstSeen = ioc.FirstSeen
		}
		existing.SeenCount++
		merged[key] = existing
	}

	out := make([]model.IOC, 0, len(merged))
	for _, ioc := range merged {
		out = append(out, ioc)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Type == out[j].Type {
			return strings.ToLower(out[i].Value) < strings.ToLower(out[j].Value)
		}
		return out[i].Type < out[j].Type
	})

	return out
}

func dedupKey(ioc model.IOC) string {
	return strings.ToLower(ioc.Type) + "|" + normalizeValue(ioc.Type, ioc.Value)
}

func normalizeValue(iocType, value string) string {
	v := strings.TrimSpace(value)
	switch strings.ToLower(iocType) {
	case "domain", "url", "hash":
		return strings.ToLower(v)
	default:
		return v
	}
}

func uniqueSorted(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		trimmed := strings.TrimSpace(v)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	sort.Strings(out)
	return out
}

func firstOrEmpty(in []string) string {
	if len(in) == 0 {
		return ""
	}
	return in[0]
}
