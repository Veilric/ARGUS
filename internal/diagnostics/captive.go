package diagnostics

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type CaptivePortalCheck struct{}

func (c *CaptivePortalCheck) ID() string          { return "captive_portal" }
func (c *CaptivePortalCheck) Name() string        { return "Captive Portal & HTTP Interception" }
func (c *CaptivePortalCheck) Description() string { return "Detects captive portal splash screens, Wi-Fi login walls, or HTTP hijacking" }

func (c *CaptivePortalCheck) Run(ctx context.Context, netCtx *NetworkContext) (*DiagnosticResult, error) {
	client := &http.Client{
		Timeout: 2 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	targetURL := "http://connectivitycheck.gstatic.com/generate_204"
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return &DiagnosticResult{
			ID:        c.ID(),
			Title:     c.Name(),
			Category:  CategoryInconclusive,
			Severity:  SeverityInfo,
			Summary:   "Could not verify captive portal (HTTP probe connection timed out)",
			Evidence:  []string{"Probe target: " + targetURL, "Error: " + err.Error()},
			Timestamp: time.Now(),
		}, nil
	}
	defer resp.Body.Close()

	evidence := []string{
		fmt.Sprintf("Probe Target: %s", targetURL),
		fmt.Sprintf("HTTP Status: %d %s", resp.StatusCode, resp.Status),
	}

	if resp.StatusCode == http.StatusNoContent {
		return &DiagnosticResult{
			ID:        c.ID(),
			Title:     c.Name(),
			Category:  CategoryHealthy,
			Severity:  SeverityNone,
			Summary:   "Direct Internet Egress Verified (No captive portal detected)",
			Evidence:  evidence,
			Timestamp: time.Now(),
		}, nil
	}

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		location := resp.Header.Get("Location")
		evidence = append(evidence, fmt.Sprintf("Redirect Location: %s", location))
		return &DiagnosticResult{
			ID:          c.ID(),
			Title:       c.Name(),
			Category:    CategoryConfirmed,
			Severity:    SeverityWarning,
			Summary:     "CAPTIVE PORTAL DETECTED: HTTP traffic is redirected to an authentication page",
			Evidence:    evidence,
			Remediation: fmt.Sprintf("Open a browser and navigate to %s to accept network terms or log in.", location),
			Timestamp:   time.Now(),
		}, nil
	}

	if resp.StatusCode == http.StatusOK {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		snippet := strings.TrimSpace(string(bodyBytes))
		evidence = append(evidence, "Expected 204 No Content, received 200 OK with body data")
		if len(snippet) > 100 {
			snippet = snippet[:100] + "..."
		}
		evidence = append(evidence, "Body snippet: "+snippet)
		return &DiagnosticResult{
			ID:          c.ID(),
			Title:       c.Name(),
			Category:    CategoryConfirmed,
			Severity:    SeverityWarning,
			Summary:     "HTTP INTERCEPTION DETECTED: Proxy or portal returned a modified page",
			Evidence:    evidence,
			Remediation: "Inspect network proxy settings or complete browser authentication wall.",
			Timestamp:   time.Now(),
		}, nil
	}

	return &DiagnosticResult{
		ID:        c.ID(),
		Title:     c.Name(),
		Category:  CategoryInconclusive,
		Severity:  SeverityInfo,
		Summary:   fmt.Sprintf("Unexpected HTTP response: %d", resp.StatusCode),
		Evidence:  evidence,
		Timestamp: time.Now(),
	}, nil
}
