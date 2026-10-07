package reporter

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/metrics"
)

type Host struct {
	Hostname        string `json:"hostname"`
	OperatingSystem string `json:"operatingSystem"`
	Architecture    string `json:"architecture"`
	AgentVersion    string `json:"agentVersion"`
}

type Enrollment struct {
	NodeID          string `json:"nodeId"`
	Token           string `json:"token"`
	IntervalSeconds int    `json:"intervalSeconds"`
}

type Heartbeat struct {
	NodeID string `json:"nodeId"`
	Host
	Metrics metrics.Snapshot `json:"metrics"`
	Results []CheckResult    `json:"results,omitempty"`
	Update  *UpdateFailure   `json:"update,omitempty"`
}

type UpdateFailure struct {
	Version string `json:"version"`
	Message string `json:"message"`
}

type HeartbeatResponse struct {
	OK              bool               `json:"ok"`
	IntervalSeconds int                `json:"intervalSeconds"`
	ConfigVersion   string             `json:"configVersion"`
	Update          *UpdateInstruction `json:"update,omitempty"`
	Actions         []ActionRequest    `json:"actions,omitempty"`
	Refresh         bool               `json:"refresh,omitempty"`
}

type UpdateInstruction struct {
	Version     string `json:"version"`
	RequestedAt string `json:"requestedAt"`
}

type ActionRequest struct {
	ID         string          `json:"id"`
	Kind       string          `json:"kind"`
	Name       string          `json:"name"`
	Action     string          `json:"action"`
	ExpiresAt  string          `json:"expiresAt"`
	Signed     json.RawMessage `json:"signed,omitempty"`
	Attachment string          `json:"attachment,omitempty"`
}

type ActionResult struct {
	ID         string `json:"id"`
	OK         bool   `json:"ok"`
	ExitCode   *int   `json:"exitCode"`
	Output     string `json:"output"`
	FinishedAt string `json:"finishedAt"`
}

type ServiceEntry struct {
	Kind   string  `json:"kind"`
	Name   string  `json:"name"`
	State  string  `json:"state"`
	Since  *string `json:"since"`
	System bool    `json:"system"`
}

type StackEntry struct {
	Access    string   `json:"access,omitempty"`
	Public    []string `json:"public,omitempty"`
	Project   string   `json:"project"`
	Directory string   `json:"directory"`
	Running   int      `json:"running"`
	Total     int      `json:"total"`
	Compose   bool     `json:"compose"`
	Rollback  bool     `json:"rollback"`
}

type TrustReport struct {
	Version    int      `json:"version"`
	Core       []string `json:"core"`
	Access     []string `json:"access"`
	Passphrase bool     `json:"passphrase"`
	RequireUV  bool     `json:"requireUv,omitempty"`
}

type RemovedStack struct {
	Project   string `json:"project"`
	Directory string `json:"directory"`
	RemovedAt string `json:"removedAt"`
}

type Finding struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Detail   string `json:"detail"`
}

type Platform struct {
	Family   *string `json:"family"`
	Name     string  `json:"name"`
	Verified bool    `json:"verified"`
	Checked  string  `json:"checked"`
}

type SecurityReport struct {
	CheckedAt  string    `json:"checkedAt"`
	Findings   []Finding `json:"findings"`
	Recipes    []string  `json:"recipes"`
	Lockdown   bool      `json:"lockdown"`
	RebootHour *int      `json:"rebootHour"`
	Platform   *Platform `json:"platform,omitempty"`
}

type VaultReport struct {
	Set      string         `json:"set"`
	Holders  int            `json:"holders"`
	Previous *VaultPrevious `json:"previous,omitempty"`
}

type VaultPrevious struct {
	Set     string `json:"set"`
	Holders int    `json:"holders"`
}

type VaultSlot struct {
	Report *VaultReport
}

func (s VaultSlot) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.Report)
}

type InventoryReport struct {
	Hash     string          `json:"hash"`
	Docker   string          `json:"docker,omitempty"`
	SealKey  string          `json:"sealKey,omitempty"`
	Security *SecurityReport `json:"security,omitempty"`
	Vault    *VaultSlot      `json:"vault,omitempty"`
	Removed  *[]RemovedStack `json:"removed,omitempty"`
	Services *[]ServiceEntry `json:"services,omitempty"`
	Stacks   *[]StackEntry   `json:"stacks,omitempty"`
	Trust    *TrustReport    `json:"trust,omitempty"`
}

type ActionsReport struct {
	NodeID    string           `json:"nodeId"`
	Results   []ActionResult   `json:"results,omitempty"`
	Inventory *InventoryReport `json:"inventory,omitempty"`
}

type ActionsResponse struct {
	OK            bool    `json:"ok"`
	InventoryHash *string `json:"inventoryHash"`
}

type Check struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Kind           string `json:"kind"`
	Target         string `json:"target"`
	TimeoutSeconds int    `json:"timeoutSeconds"`
}

type AgentConfig struct {
	NodeID          string  `json:"nodeId"`
	IntervalSeconds int     `json:"intervalSeconds"`
	Checks          []Check `json:"checks"`
	ConfigVersion   string  `json:"configVersion"`
}

type CheckResult struct {
	CheckID   string  `json:"checkId"`
	Status    string  `json:"status"`
	LatencyMS *int64  `json:"latencyMs"`
	Message   *string `json:"message"`
	CheckedAt string  `json:"checkedAt"`
}

type Client struct {
	endpoint   string
	token      string
	version    string
	httpClient *http.Client
}

type ResponseError struct {
	Status int
	Body   string
}

func (e *ResponseError) Error() string {
	return fmt.Sprintf("Krynodes returned HTTP %d", e.Status)
}

func TLSConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13}
}

func New(endpoint, token, version string) *Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = TLSConfig()
	return &Client{
		endpoint:   strings.TrimRight(endpoint, "/"),
		token:      token,
		version:    version,
		httpClient: &http.Client{Timeout: 35 * time.Second, Transport: transport},
	}
}

func (c *Client) Enroll(ctx context.Context, host Host) (Enrollment, error) {
	var enrollment Enrollment
	err := c.doJSON(ctx, http.MethodPost, "/api/agent/enroll", host, &enrollment)
	return enrollment, err
}

func (c *Client) doJSON(ctx context.Context, method, path string, input, output any) error {
	var body []byte
	var err error
	if input != nil {
		body, err = json.Marshal(input)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
	}

	for attempt := 0; attempt < 3; attempt++ {
		request, requestErr := http.NewRequestWithContext(
			ctx,
			method,
			c.endpoint+path,
			bytes.NewReader(body),
		)
		if requestErr != nil {
			return fmt.Errorf("create request: %w", requestErr)
		}
		request.Header.Set("Authorization", "Bearer "+c.token)
		request.Header.Set("Accept", "application/json")
		request.Header.Set("User-Agent", "kry-agent/"+c.version)
		if input != nil {
			request.Header.Set("Content-Type", "application/json")
		}

		response, requestErr := c.httpClient.Do(request)
		if requestErr != nil {
			if attempt < 2 && waitForRetry(ctx, attempt) {
				continue
			}
			return fmt.Errorf("send request: %w", requestErr)
		}

		data, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		response.Body.Close()
		if readErr != nil {
			return fmt.Errorf("read response: %w", readErr)
		}
		if response.StatusCode >= 200 && response.StatusCode < 300 {
			if output != nil && len(data) > 0 {
				if err := json.Unmarshal(data, output); err != nil {
					return fmt.Errorf("decode response: %w", err)
				}
			}
			return nil
		}
		if response.StatusCode >= 500 && attempt < 2 && waitForRetry(ctx, attempt) {
			continue
		}
		return &ResponseError{Status: response.StatusCode, Body: string(data)}
	}
	return fmt.Errorf("request retries exhausted")
}

func waitForRetry(ctx context.Context, attempt int) bool {
	timer := time.NewTimer(time.Duration(1<<attempt) * time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
