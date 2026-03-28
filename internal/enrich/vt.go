package enrich

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"ioc-pipeline/internal/model"
)

func vtFetch(client *http.Client, apiKey, iocType, value string) (*model.VTReport, error) {
	var path string
	switch iocType {
	case "ip":
		path = "/api/v3/ip_addresses/" + url.PathEscape(value)
	case "domain":
		path = "/api/v3/domains/" + url.PathEscape(value)
	case "hash":
		path = "/api/v3/files/" + url.PathEscape(strings.ToLower(value))
	default:
		return nil, nil
	}

	req, err := http.NewRequest(http.MethodGet, "https://www.virustotal.com"+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-apikey", apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("virustotal: HTTP %d", resp.StatusCode)
	}

	var payload struct {
		Data struct {
			Attributes struct {
				LastAnalysisStats struct {
					Malicious  int `json:"malicious"`
					Suspicious int `json:"suspicious"`
					Harmless   int `json:"harmless"`
					Undetected int `json:"undetected"`
				} `json:"last_analysis_stats"`
				LastAnalysisDate *int64 `json:"last_analysis_date"`
			} `json:"attributes"`
			Links struct {
				Self string `json:"self"`
			} `json:"links"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}

	stats := payload.Data.Attributes.LastAnalysisStats
	out := &model.VTReport{
		Malicious:  stats.Malicious,
		Suspicious: stats.Suspicious,
		Harmless:   stats.Harmless,
		Undetected: stats.Undetected,
		Permalink:  payload.Data.Links.Self,
	}
	if payload.Data.Attributes.LastAnalysisDate != nil && *payload.Data.Attributes.LastAnalysisDate > 0 {
		out.AnalysisDate = time.Unix(*payload.Data.Attributes.LastAnalysisDate, 0).UTC().Format(time.RFC3339)
	}
	return out, nil
}
