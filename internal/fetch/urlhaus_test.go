package fetch

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestURLhaus_ParsesJSONFeed(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"set":[{"url":"http://example.com/malware","threat":"malware_download","dateadded":"2026-03-20 12:00:00 UTC"}]}`))
	}))
	defer ts.Close()

	old := urlhausEndpoint
	urlhausEndpoint = ts.URL
	defer func() { urlhausEndpoint = old }()

	out, err := URLhaus()
	if err != nil {
		t.Fatalf("URLhaus returned error: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 IOC, got %d", len(out))
	}
	if out[0].Type != "url" || out[0].Source != "URLhaus" {
		t.Fatalf("unexpected parsed IOC: %+v", out[0])
	}
	if out[0].FirstSeen == "" {
		t.Fatalf("expected first_seen to be populated")
	}
}
