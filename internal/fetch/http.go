package fetch

import (
	"fmt"
	"io"
	"net/http"
	"time"
)

var httpClient = &http.Client{Timeout: 25 * time.Second}

func getWithRetry(url string) (io.ReadCloser, error) {
	var lastErr error
	delays := []time.Duration{0, 500 * time.Millisecond, 1500 * time.Millisecond}

	for _, delay := range delays {
		if delay > 0 {
			time.Sleep(delay)
		}

		resp, err := httpClient.Get(url)
		if err != nil {
			lastErr = err
			continue
		}

		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("GET %s failed with status %d", url, resp.StatusCode)
			resp.Body.Close()
			continue
		}

		return resp.Body, nil
	}

	return nil, lastErr
}
