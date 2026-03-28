package fetch

import (
	"encoding/json"
	"sort"
	"time"

	"ioc-pipeline/internal/model"
)

var urlhausEndpoint = "https://urlhaus.abuse.ch/downloads/json_recent/"

func URLhaus() ([]model.IOC, error) {
	body, err := getWithRetry(urlhausEndpoint)
	if err != nil {
		return nil, err
	}
	defer body.Close()

	var data map[string][]struct {
		URL       string `json:"url"`
		Threat    string `json:"threat"`
		DateAdded string `json:"dateadded"`
	}
	if err := json.NewDecoder(body).Decode(&data); err != nil {
		return nil, err
	}

	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	iocs := make([]model.IOC, 0, 1000)
	for _, k := range keys {
		for _, entry := range data[k] {
			if entry.URL == "" {
				continue
			}
			t, _ := time.Parse("2006-01-02 15:04:05 MST", entry.DateAdded)
			if t.IsZero() {
				t = time.Now().UTC()
			}

			iocs = append(iocs, model.IOC{
				Value:      entry.URL,
				Type:       "url",
				Source:     "URLhaus",
				ThreatType: entry.Threat,
				FirstSeen:  t.UTC().Format(time.RFC3339),
			})
		}
	}

	return iocs, nil
}
