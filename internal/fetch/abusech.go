package fetch

import (
	"bufio"
	"net/http"
	"net/url"
	"strings"

	"ioc-pipeline/internal/model"
)

func DomainFromURLs(urlIOCs []model.IOC) []model.IOC {
	domains := make([]model.IOC, 0, len(urlIOCs))
	for _, item := range urlIOCs {
		if item.Type != "url" || item.Value == "" {
			continue
		}
		parsed, err := url.Parse(item.Value)
		if err != nil || parsed.Hostname() == "" {
			continue
		}
		domains = append(domains, model.IOC{
			Value:      strings.ToLower(parsed.Hostname()),
			Type:       "domain",
			Source:     item.Source,
			ThreatType: item.ThreatType,
			FirstSeen:  item.FirstSeen,
		})
	}
	return domains
}

func FeodoTrackerIPs() ([]model.IOC, error) {
	resp, err := http.Get("https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	ips := make([]model.IOC, 0, 5000)
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ips = append(ips, model.IOC{
			Value:      line,
			Type:       "ip",
			Source:     "FeodoTracker",
			ThreatType: "botnet_c2",
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return ips, nil
}
