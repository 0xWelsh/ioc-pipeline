package dedup

import (
	"testing"

	"ioc-pipeline/internal/model"
)

func TestProcess_MergesSourcesThreatsAndSeenCount(t *testing.T) {
	in := []model.IOC{
		{Type: "domain", Value: "Example.com", Source: "URLhaus", ThreatType: "malware", FirstSeen: "2026-03-01T00:00:00Z"},
		{Type: "domain", Value: "example.com", Source: "Manual", ThreatType: "phishing", FirstSeen: "2026-03-02T00:00:00Z"},
	}

	out := Process(in)
	if len(out) != 1 {
		t.Fatalf("expected 1 IOC, got %d", len(out))
	}
	if out[0].SeenCount != 2 {
		t.Fatalf("expected seen_count=2, got %d", out[0].SeenCount)
	}
	if len(out[0].Sources) != 2 {
		t.Fatalf("expected 2 merged sources, got %v", out[0].Sources)
	}
	if len(out[0].ThreatTypes) != 2 {
		t.Fatalf("expected 2 merged threat types, got %v", out[0].ThreatTypes)
	}
	if out[0].FirstSeen != "2026-03-01T00:00:00Z" {
		t.Fatalf("expected earliest first_seen, got %s", out[0].FirstSeen)
	}
}

func TestProcess_DoesNotMergeAcrossTypes(t *testing.T) {
	in := []model.IOC{
		{Type: "url", Value: "example.com", Source: "A"},
		{Type: "domain", Value: "example.com", Source: "B"},
	}
	out := Process(in)
	if len(out) != 2 {
		t.Fatalf("expected 2 IOCs, got %d", len(out))
	}
}
