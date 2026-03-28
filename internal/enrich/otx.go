package enrich

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"ioc-pipeline/internal/model"
)

func otxIndicatorType(iocType string) string {
	switch iocType {
	case "ip":
		return "IPv4"
	case "domain":
		return "domain"
	case "hash":
		return "FileHash-SHA256"
	case "url":
		return "url"
	default:
		return ""
	}
}

func otxFetch(client *http.Client, apiKey, iocType, value string) (*model.OTXReport, []string, []string, error) {
	indType := otxIndicatorType(iocType)
	if indType == "" {
		return nil, nil, nil, nil
	}

	enc := url.PathEscape(value)
	reqURL := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/%s/%s/general", indType, enc)

	req, err := http.NewRequest(http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, nil, nil, err
	}
	if apiKey != "" {
		req.Header.Set("X-OTX-API-KEY", apiKey)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil, nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil, nil, fmt.Errorf("otx: HTTP %d", resp.StatusCode)
	}

	var payload struct {
		PulseInfo struct {
			Count  int `json:"count"`
			Pulses []struct {
				Name      string   `json:"name"`
				Tags      []string `json:"tags"`
				AttackIds []struct {
					ID string `json:"id"`
				} `json:"attack_ids"`
			} `json:"pulses"`
		} `json:"pulse_info"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, nil, nil, err
	}

	tagSet := make(map[string]struct{})
	mitreSet := make(map[string]struct{})
	names := make([]string, 0, len(payload.PulseInfo.Pulses))

	for _, p := range payload.PulseInfo.Pulses {
		if p.Name != "" {
			names = append(names, p.Name)
		}
		for _, t := range p.Tags {
			t = strings.TrimSpace(t)
			if t != "" {
				tagSet[strings.ToLower(t)] = struct{}{}
			}
		}
		for _, a := range p.AttackIds {
			id := strings.TrimSpace(a.ID)
			if id != "" {
				mitreSet[id] = struct{}{}
			}
		}
	}

	tags := make([]string, 0, len(tagSet))
	for t := range tagSet {
		tags = append(tags, t)
	}
	sort.Strings(tags)

	mitre := make([]string, 0, len(mitreSet))
	for m := range mitreSet {
		mitre = append(mitre, m)
	}
	sort.Strings(mitre)

	report := &model.OTXReport{
		PulseCount: payload.PulseInfo.Count,
		PulseNames: names,
	}
	if report.PulseCount == 0 && len(names) > 0 {
		report.PulseCount = len(names)
	}

	return report, tags, mitre, nil
}
