package tailscale

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	defaultBase = "https://api.tailscale.com"
	apiTimeout  = 30 * time.Second
	maxBody     = 4 << 20
)

var ErrChanged = errors.New("Your policy file changed while saving. Try again.")

type API struct {
	Base   string
	HTTP   *http.Client
	ID     string
	Secret string
	token  string
}

type Device struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Addresses []string `json:"addresses"`
	Tags      []string `json:"tags"`
	User      bool     `json:"user"`
	Routes    []string `json:"routes"`
}

type apiReply struct {
	status int
	header http.Header
	body   []byte
}

func refusal(body []byte, status string) error {
	var parsed struct {
		Message string `json:"message"`
		Data    []struct {
			Errors []string `json:"errors"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &parsed) != nil || parsed.Message == "" {
		return fmt.Errorf("Tailscale answered %s", status)
	}
	reasons := []string{parsed.Message}
	for _, entry := range parsed.Data {
		reasons = append(reasons, entry.Errors...)
	}
	return fmt.Errorf("Tailscale refused it: %s", strings.Join(reasons, "; "))
}

func (a *API) send(ctx context.Context, method, path string, body []byte, header map[string]string) (apiReply, error) {
	base := a.Base
	if base == "" {
		base = defaultBase
	}
	client := a.HTTP
	if client == nil {
		client = &http.Client{Timeout: apiTimeout}
	}
	request, err := http.NewRequestWithContext(ctx, method, base+path, bytes.NewReader(body))
	if err != nil {
		return apiReply{}, err
	}
	for name, value := range header {
		request.Header.Set(name, value)
	}
	response, err := client.Do(request)
	if err != nil {
		return apiReply{}, fmt.Errorf("Tailscale could not be reached: %w", errors.Unwrap(err))
	}
	defer response.Body.Close()
	read, err := io.ReadAll(io.LimitReader(response.Body, maxBody))
	return apiReply{status: response.StatusCode, header: response.Header, body: read}, err
}

func (a *API) Token(ctx context.Context) (string, error) {
	if a.token != "" {
		return a.token, nil
	}
	form := url.Values{"client_id": {a.ID}, "client_secret": {a.Secret}, "grant_type": {"client_credentials"}}
	reply, err := a.send(ctx, http.MethodPost, "/api/v2/oauth/token", []byte(form.Encode()), map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	if err != nil {
		return "", err
	}
	var parsed struct {
		AccessToken string `json:"access_token"`
	}
	if reply.status != http.StatusOK || json.Unmarshal(reply.body, &parsed) != nil || parsed.AccessToken == "" {
		return "", refusal(reply.body, http.StatusText(reply.status))
	}
	a.token = parsed.AccessToken
	return a.token, nil
}

func (a *API) call(ctx context.Context, method, path string, body []byte, header map[string]string) (apiReply, error) {
	token, err := a.Token(ctx)
	if err != nil {
		return apiReply{}, err
	}
	if header == nil {
		header = map[string]string{}
	}
	header["Authorization"] = "Bearer " + token
	if body != nil && header["Content-Type"] == "" {
		header["Content-Type"] = "application/json"
	}
	reply, err := a.send(ctx, method, path, body, header)
	if err == nil && (reply.status < 200 || reply.status > 299) && reply.status != http.StatusPreconditionFailed {
		err = refusal(reply.body, http.StatusText(reply.status))
	}
	return reply, err
}

func (a *API) Policy(ctx context.Context) ([]byte, string, error) {
	reply, err := a.call(ctx, http.MethodGet, "/api/v2/tailnet/-/acl", nil, map[string]string{"Accept": "application/hujson"})
	if err != nil {
		return nil, "", err
	}
	return reply.body, reply.header.Get("ETag"), nil
}

func (a *API) Validate(ctx context.Context, body []byte) error {
	reply, err := a.call(ctx, http.MethodPost, "/api/v2/tailnet/-/acl/validate", body, map[string]string{"Content-Type": "application/hujson"})
	if err != nil {
		return err
	}
	var parsed struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(reply.body, &parsed) == nil && parsed.Message != "" {
		return refusal(reply.body, "")
	}
	return nil
}

func (a *API) SetPolicy(ctx context.Context, body []byte, etag string) error {
	reply, err := a.call(ctx, http.MethodPost, "/api/v2/tailnet/-/acl", body, map[string]string{"Content-Type": "application/hujson", "If-Match": etag})
	if err != nil {
		return err
	}
	if reply.status == http.StatusPreconditionFailed {
		return ErrChanged
	}
	return nil
}

func (a *API) Devices(ctx context.Context) ([]Device, error) {
	reply, err := a.call(ctx, http.MethodGet, "/api/v2/tailnet/-/devices?fields=all", nil, nil)
	if err != nil {
		return nil, err
	}
	var parsed struct {
		Devices []struct {
			NodeID    string   `json:"nodeId"`
			Name      string   `json:"name"`
			Addresses []string `json:"addresses"`
			Tags      []string `json:"tags"`
			Routes    []string `json:"advertisedRoutes"`
		} `json:"devices"`
	}
	if err := json.Unmarshal(reply.body, &parsed); err != nil {
		return nil, fmt.Errorf("Tailscale's device list: %w", err)
	}
	devices := []Device{}
	for _, entry := range parsed.Devices {
		device := Device{ID: entry.NodeID, Name: label(entry.Name), Addresses: entry.Addresses, Tags: entry.Tags, User: len(entry.Tags) == 0, Routes: entry.Routes}
		if device.Addresses == nil {
			device.Addresses = []string{}
		}
		if device.Tags == nil {
			device.Tags = []string{}
		}
		if device.Routes == nil {
			device.Routes = []string{}
		}
		devices = append(devices, device)
	}
	return devices, nil
}

func (a *API) Tag(ctx context.Context, id string, tags []string) error {
	body, _ := json.Marshal(map[string][]string{"tags": tags})
	_, err := a.call(ctx, http.MethodPost, "/api/v2/device/"+url.PathEscape(id)+"/tags", body, nil)
	return err
}

func (a *API) NoExpiry(ctx context.Context, id string) error {
	_, err := a.call(ctx, http.MethodPost, "/api/v2/device/"+url.PathEscape(id)+"/key", []byte(`{"keyExpiryDisabled":true}`), nil)
	return err
}

func (a *API) Delete(ctx context.Context, id string) error {
	_, err := a.call(ctx, http.MethodDelete, "/api/v2/device/"+url.PathEscape(id), nil, nil)
	return err
}

func (a *API) AuthKey(ctx context.Context, tags []string, seconds int) (string, error) {
	type create struct {
		Reusable      bool     `json:"reusable"`
		Ephemeral     bool     `json:"ephemeral"`
		Preauthorized bool     `json:"preauthorized"`
		Tags          []string `json:"tags"`
	}
	asked := map[string]any{
		"capabilities":  map[string]any{"devices": map[string]any{"create": create{Preauthorized: true, Tags: tags}}},
		"expirySeconds": seconds,
		"description":   "Krynodes",
	}
	body, _ := json.Marshal(asked)
	reply, err := a.call(ctx, http.MethodPost, "/api/v2/tailnet/-/keys", body, nil)
	if err != nil {
		return "", err
	}
	var parsed struct {
		Key string `json:"key"`
	}
	if json.Unmarshal(reply.body, &parsed) != nil || parsed.Key == "" {
		return "", errors.New("Tailscale gave no auth key")
	}
	return parsed.Key, nil
}
