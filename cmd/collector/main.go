package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"ioc-pipeline/internal/dedup"
	"ioc-pipeline/internal/fetch"
	"ioc-pipeline/internal/model"
)

func main() {
	fmt.Println("Starting IoC collection...")

	previous, _ := loadPreviousLatest("data/processed/latest.json")

	urls, err := fetch.URLhaus()
	if err != nil {
		log.Fatalf("URLhaus fetch failed: %v", err)
	}
	ips, err := fetch.FeodoTrackerIPs()
	if err != nil {
		log.Fatalf("FeodoTracker fetch failed: %v", err)
	}
	domains := fetch.DomainFromURLs(urls)

	all := append(urls, ips...)
	all = append(all, domains...)
	all = dedup.Process(all)

	grouped := map[string][]model.IOC{
		"urls":    {},
		"domains": {},
		"ips":     {},
		"hashes":  {},
	}

	for _, ioc := range all {
		switch ioc.Type {
		case "url":
			grouped["urls"] = append(grouped["urls"], ioc)
		case "domain":
			grouped["domains"] = append(grouped["domains"], ioc)
		case "hash":
			grouped["hashes"] = append(grouped["hashes"], ioc)
		case "ip":
			grouped["ips"] = append(grouped["ips"], ioc)
		}
	}

	if err := os.MkdirAll("data/processed", 0o755); err != nil {
		log.Fatalf("Failed creating data output dir: %v", err)
	}
	if err := os.MkdirAll("web/public/iocs", 0o755); err != nil {
		log.Fatalf("Failed creating web output dir: %v", err)
	}
	if err := os.MkdirAll("data/processed/history", 0o755); err != nil {
		log.Fatalf("Failed creating processed history dir: %v", err)
	}
	if err := os.MkdirAll("web/public/iocs/history", 0o755); err != nil {
		log.Fatalf("Failed creating web history dir: %v", err)
	}

	now := time.Now().UTC()
	timestamp := now.Format(time.RFC3339)
	latestPayload := map[string]any{
		"generated_at": timestamp,
		"total":        len(all),
		"iocs":         all,
	}
	if err := writeJSON("data/processed/latest.json", latestPayload); err != nil {
		log.Fatalf("Failed writing latest.json: %v", err)
	}
	if err := writeJSON("web/public/iocs/latest.json", latestPayload); err != nil {
		log.Fatalf("Failed writing web latest.json: %v", err)
	}

	deltaPayload := buildDeltaPayload(timestamp, previous, all)
	if err := writeJSON("data/processed/new_since_last.json", deltaPayload["new_since_last"]); err != nil {
		log.Fatalf("Failed writing new_since_last.json: %v", err)
	}
	if err := writeJSON("web/public/iocs/new_since_last.json", deltaPayload["new_since_last"]); err != nil {
		log.Fatalf("Failed writing web new_since_last.json: %v", err)
	}
	if err := writeJSON("data/processed/removed_since_last.json", deltaPayload["removed_since_last"]); err != nil {
		log.Fatalf("Failed writing removed_since_last.json: %v", err)
	}
	if err := writeJSON("web/public/iocs/removed_since_last.json", deltaPayload["removed_since_last"]); err != nil {
		log.Fatalf("Failed writing web removed_since_last.json: %v", err)
	}

	snapshotName := now.Format("20060102-150405") + ".json"
	if err := writeJSON(filepath.Join("data/processed/history", snapshotName), latestPayload); err != nil {
		log.Fatalf("Failed writing processed snapshot: %v", err)
	}
	if err := writeJSON(filepath.Join("web/public/iocs/history", snapshotName), latestPayload); err != nil {
		log.Fatalf("Failed writing web snapshot: %v", err)
	}

	for name, data := range grouped {
		if err := writeJSON(filepath.Join("data/processed", name+".json"), data); err != nil {
			log.Fatalf("Failed writing processed %s: %v", name, err)
		}
		if err := writeJSON(filepath.Join("web/public/iocs", name+".json"), data); err != nil {
			log.Fatalf("Failed writing web %s: %v", name, err)
		}
	}

	history, err := buildHistoryIndex("web/public/iocs/history")
	if err != nil {
		log.Fatalf("Failed building web history index: %v", err)
	}
	if err := writeJSON("web/public/iocs/history/index.json", map[string]any{
		"generated_at": timestamp,
		"snapshots":    history,
	}); err != nil {
		log.Fatalf("Failed writing web history index: %v", err)
	}

	if err := writeJSON("data/processed/history/index.json", map[string]any{
		"generated_at": timestamp,
		"snapshots":    history,
	}); err != nil {
		log.Fatalf("Failed writing processed history index: %v", err)
	}

	fmt.Printf(
		"Completed. URLs: %d, Domains: %d, IPs: %d, Hashes: %d, Total: %d\n",
		len(grouped["urls"]),
		len(grouped["domains"]),
		len(grouped["ips"]),
		len(grouped["hashes"]),
		len(all),
	)
}

func buildHistoryIndex(historyDir string) ([]map[string]string, error) {
	entries, err := os.ReadDir(historyDir)
	if err != nil {
		return nil, err
	}

	snapshots := make([]map[string]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if name == "index.json" || filepath.Ext(name) != ".json" {
			continue
		}
		ts := name[:len(name)-5]
		snapshots = append(snapshots, map[string]string{
			"file":      name,
			"path":      "/iocs/history/" + name,
			"timestamp": ts,
		})
	}

	sort.Slice(snapshots, func(i, j int) bool {
		return snapshots[i]["file"] > snapshots[j]["file"]
	})
	if len(snapshots) > 30 {
		snapshots = snapshots[:30]
	}

	return snapshots, nil
}

func writeJSON(path string, data any) error {
	file, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	file = append(file, '\n')
	return os.WriteFile(path, file, 0o644)
}

func loadPreviousLatest(path string) ([]model.IOC, error) {
	file, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var payload struct {
		IOCs []model.IOC `json:"iocs"`
	}
	if err := json.Unmarshal(file, &payload); err != nil {
		return nil, err
	}
	return payload.IOCs, nil
}

func buildDeltaPayload(generatedAt string, previous, current []model.IOC) map[string]map[string]any {
	prevMap := toIOCMap(previous)
	currMap := toIOCMap(current)

	newIOCs := make([]model.IOC, 0)
	removedIOCs := make([]model.IOC, 0)

	for key, ioc := range currMap {
		if _, ok := prevMap[key]; !ok {
			newIOCs = append(newIOCs, ioc)
		}
	}
	for key, ioc := range prevMap {
		if _, ok := currMap[key]; !ok {
			removedIOCs = append(removedIOCs, ioc)
		}
	}

	sort.Slice(newIOCs, func(i, j int) bool { return iocSortKey(newIOCs[i]) < iocSortKey(newIOCs[j]) })
	sort.Slice(removedIOCs, func(i, j int) bool { return iocSortKey(removedIOCs[i]) < iocSortKey(removedIOCs[j]) })

	return map[string]map[string]any{
		"new_since_last": {
			"generated_at": generatedAt,
			"total":        len(newIOCs),
			"iocs":         newIOCs,
		},
		"removed_since_last": {
			"generated_at": generatedAt,
			"total":        len(removedIOCs),
			"iocs":         removedIOCs,
		},
	}
}

func toIOCMap(iocs []model.IOC) map[string]model.IOC {
	out := make(map[string]model.IOC, len(iocs))
	for _, ioc := range iocs {
		key := strings.ToLower(ioc.Type) + "|" + strings.ToLower(strings.TrimSpace(ioc.Value))
		out[key] = ioc
	}
	return out
}

func iocSortKey(ioc model.IOC) string {
	return strings.ToLower(ioc.Type) + "|" + strings.ToLower(ioc.Value)
}
