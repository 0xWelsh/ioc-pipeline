package fetch

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetWithRetry_StatusCodeError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	_, err := getWithRetry(ts.URL)
	if err == nil {
		t.Fatalf("expected error for non-200 response")
	}
}

func TestGetWithRetry_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer ts.Close()

	body, err := getWithRetry(ts.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer body.Close()

	b, _ := io.ReadAll(body)
	if string(b) != "ok" {
		t.Fatalf("unexpected body: %s", string(b))
	}
}
