package fetch

import (
	"testing"

	"ioc-pipeline/internal/model"
)

func TestDomainFromURLs_ExtractsAndLowercases(t *testing.T) {
	in := []model.IOC{
		{Type: "url", Value: "HTTP://Sub.Example.COM/path", Source: "URLhaus", ThreatType: "malware", FirstSeen: "2026-01-01T00:00:00Z"},
		{Type: "url", Value: "://bad-url"},
		{Type: "ip", Value: "1.1.1.1"},
	}

	out := DomainFromURLs(in)
	if len(out) != 1 {
		t.Fatalf("expected 1 domain IOC, got %d", len(out))
	}
	if out[0].Value != "sub.example.com" {
		t.Fatalf("expected lowered hostname, got %s", out[0].Value)
	}
	if out[0].ThreatType != "malware" {
		t.Fatalf("expected threat_type propagation, got %s", out[0].ThreatType)
	}
}
