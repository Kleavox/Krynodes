package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/Kleavox/krynodes/agent/internal/reporter"
)

const (
	Mark        = "krynodes"
	DefaultBase = "https://api.cloudflare.com/client/v4"
	notFound    = "http_status:404"
)

type Client struct {
	Token string
	Base  string
	HTTP  *http.Client
}

type Zone struct {
	ID        string
	AccountID string
}

type Rule struct {
	Hostname string `json:"hostname,omitempty"`
	Service  string `json:"service"`
}

type Record struct {
	ID      string `json:"id,omitempty"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	Proxied bool   `json:"proxied"`
	Comment string `json:"comment,omitempty"`
	TTL     int    `json:"ttl,omitempty"`
}

type Policy struct {
	ID         string `json:"id,omitempty"`
	Name       string `json:"name,omitempty"`
	Decision   string `json:"decision,omitempty"`
	Reusable   bool   `json:"reusable,omitempty"`
	Precedence int    `json:"precedence,omitempty"`
	Include    []any  `json:"include,omitempty"`
	Exclude    []any  `json:"exclude,omitempty"`
	Require    []any  `json:"require,omitempty"`
}

type App struct {
	ID              string   `json:"id,omitempty"`
	Name            string   `json:"name"`
	Domain          string   `json:"domain"`
	Type            string   `json:"type,omitempty"`
	AUD             string   `json:"aud,omitempty"`
	SessionDuration string   `json:"session_duration,omitempty"`
	Policies        []Policy `json:"policies,omitempty"`
}

type envelope struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	Result json.RawMessage `json:"result"`
}

func (c *Client) do(ctx context.Context, method, path string, query url.Values, body, result any) error {
	base := c.Base
	if base == "" {
		base = DefaultBase
	}
	target := base + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	var payload io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		payload = bytes.NewReader(encoded)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, method, target, payload)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+c.Token)
	request.Header.Set("Content-Type", "application/json")
	client := c.HTTP
	if client == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = reporter.TLSConfig()
		client = &http.Client{Transport: transport}
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("cloudflare: %w", err)
	}
	defer response.Body.Close()
	var reply envelope
	if err := json.NewDecoder(io.LimitReader(response.Body, 4<<20)).Decode(&reply); err != nil {
		return fmt.Errorf("cloudflare answered %d", response.StatusCode)
	}
	if !reply.Success || response.StatusCode >= 300 {
		messages := []string{}
		for _, problem := range reply.Errors {
			messages = append(messages, problem.Message)
		}
		if len(messages) == 0 {
			messages = append(messages, fmt.Sprintf("HTTP %d", response.StatusCode))
		}
		return fmt.Errorf("cloudflare: %s", strings.Join(messages, "; "))
	}
	if result == nil {
		return nil
	}
	return json.Unmarshal(reply.Result, result)
}

func (c *Client) Zone(ctx context.Context, name string) (Zone, error) {
	var zones []struct {
		ID      string `json:"id"`
		Account struct {
			ID string `json:"id"`
		} `json:"account"`
	}
	if err := c.do(ctx, http.MethodGet, "/zones", url.Values{"name": {name}}, nil, &zones); err != nil {
		return Zone{}, err
	}
	if len(zones) == 0 {
		return Zone{}, fmt.Errorf("the zone %s is not in this Cloudflare account", name)
	}
	return Zone{ID: zones[0].ID, AccountID: zones[0].Account.ID}, nil
}

func (c *Client) findTunnel(ctx context.Context, account, name string) (string, error) {
	var tunnels []struct {
		ID string `json:"id"`
	}
	if err := c.do(ctx, http.MethodGet, "/accounts/"+account+"/cfd_tunnel", url.Values{"name": {name}, "is_deleted": {"false"}}, nil, &tunnels); err != nil {
		return "", err
	}
	if len(tunnels) == 0 {
		return "", nil
	}
	return tunnels[0].ID, nil
}

func (c *Client) Tunnel(ctx context.Context, account, name string) (string, error) {
	if id, err := c.findTunnel(ctx, account, name); err != nil || id != "" {
		return id, err
	}
	var created struct {
		ID string `json:"id"`
	}
	err := c.do(ctx, http.MethodPost, "/accounts/"+account+"/cfd_tunnel", nil, map[string]string{"name": name, "config_src": "cloudflare"}, &created)
	return created.ID, err
}

func (c *Client) TunnelToken(ctx context.Context, account, tunnel string) (string, error) {
	var token string
	err := c.do(ctx, http.MethodGet, "/accounts/"+account+"/cfd_tunnel/"+tunnel+"/token", nil, nil, &token)
	return token, err
}

func (c *Client) ingress(ctx context.Context, account, tunnel string) ([]Rule, error) {
	var configuration struct {
		Config struct {
			Ingress []Rule `json:"ingress"`
		} `json:"config"`
	}
	err := c.do(ctx, http.MethodGet, "/accounts/"+account+"/cfd_tunnel/"+tunnel+"/configurations", nil, nil, &configuration)
	return configuration.Config.Ingress, err
}

func (c *Client) setIngress(ctx context.Context, account, tunnel string, rules []Rule) error {
	kept := slices.DeleteFunc(rules, func(rule Rule) bool { return rule.Hostname == "" })
	kept = append(kept, Rule{Service: notFound})
	return c.do(ctx, http.MethodPut, "/accounts/"+account+"/cfd_tunnel/"+tunnel+"/configurations", nil, map[string]any{"config": map[string]any{"ingress": kept}}, nil)
}

func (c *Client) Route(ctx context.Context, account, tunnel, hostname, service string) error {
	rules, err := c.ingress(ctx, account, tunnel)
	if err != nil {
		return err
	}
	rules = slices.DeleteFunc(rules, func(rule Rule) bool { return rule.Hostname == hostname })
	return c.setIngress(ctx, account, tunnel, append(rules, Rule{Hostname: hostname, Service: service}))
}

func (c *Client) Unroute(ctx context.Context, account, tunnel, hostname string) error {
	rules, err := c.ingress(ctx, account, tunnel)
	if err != nil {
		return err
	}
	return c.setIngress(ctx, account, tunnel, slices.DeleteFunc(rules, func(rule Rule) bool { return rule.Hostname == hostname }))
}

func (c *Client) records(ctx context.Context, zone string, query url.Values) ([]Record, error) {
	var records []Record
	err := c.do(ctx, http.MethodGet, "/zones/"+zone+"/dns_records", query, nil, &records)
	return records, err
}

func (c *Client) Point(ctx context.Context, zone, hostname, tunnel string) error {
	target := tunnel + ".cfargotunnel.com"
	existing, err := c.records(ctx, zone, url.Values{"name": {hostname}})
	if err != nil {
		return err
	}
	for _, record := range existing {
		if record.Comment != Mark {
			return fmt.Errorf("%s already exists in DNS; pick another name", hostname)
		}
		if record.Type == "CNAME" && record.Content == target {
			return nil
		}
		if err := c.do(ctx, http.MethodDelete, "/zones/"+zone+"/dns_records/"+record.ID, nil, nil, nil); err != nil {
			return err
		}
	}
	return c.do(ctx, http.MethodPost, "/zones/"+zone+"/dns_records", nil, Record{Type: "CNAME", Name: hostname, Content: target, Proxied: true, Comment: Mark, TTL: 1}, nil)
}

func (c *Client) Unpoint(ctx context.Context, zone, hostname string) error {
	existing, err := c.records(ctx, zone, url.Values{"name": {hostname}})
	if err != nil {
		return err
	}
	for _, record := range existing {
		if record.Comment == Mark {
			if err := c.do(ctx, http.MethodDelete, "/zones/"+zone+"/dns_records/"+record.ID, nil, nil, nil); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *Client) apps(ctx context.Context, account string) ([]App, error) {
	var apps []App
	err := c.do(ctx, http.MethodGet, "/accounts/"+account+"/access/apps", url.Values{"per_page": {"1000"}}, nil, &apps)
	return apps, err
}

func (c *Client) Guard(ctx context.Context, account, domain, aud string) error {
	if err := c.Unguard(ctx, account, domain); err != nil {
		return err
	}
	apps, err := c.apps(ctx, account)
	if err != nil {
		return err
	}
	index := slices.IndexFunc(apps, func(app App) bool { return app.AUD == aud })
	if aud == "" || index < 0 {
		return fmt.Errorf("the dashboard's Access application was not found")
	}
	var dashboard []Policy
	if err := c.do(ctx, http.MethodGet, "/accounts/"+account+"/access/apps/"+apps[index].ID+"/policies", nil, nil, &dashboard); err != nil {
		return err
	}
	var policies []Policy
	for position, policy := range dashboard {
		if policy.Reusable {
			policies = append(policies, Policy{ID: policy.ID, Precedence: position + 1})
		} else {
			policies = append(policies, Policy{Name: policy.Name, Decision: policy.Decision, Include: policy.Include, Exclude: policy.Exclude, Require: policy.Require, Precedence: position + 1})
		}
	}
	if len(policies) == 0 {
		return fmt.Errorf("the dashboard's Access application has no policy to reuse")
	}
	return c.do(ctx, http.MethodPost, "/accounts/"+account+"/access/apps", nil, App{Name: Mark + " " + domain, Domain: domain, Type: "self_hosted", SessionDuration: "24h", Policies: policies}, nil)
}

func (c *Client) Unguard(ctx context.Context, account, domain string) error {
	apps, err := c.apps(ctx, account)
	if err != nil {
		return err
	}
	for _, app := range apps {
		if app.Name == Mark+" "+domain {
			if err := c.do(ctx, http.MethodDelete, "/accounts/"+account+"/access/apps/"+app.ID, nil, nil, nil); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *Client) Expires(ctx context.Context, account string) (string, error) {
	var verified struct {
		ExpiresOn string `json:"expires_on"`
	}
	err := c.do(ctx, http.MethodGet, "/accounts/"+account+"/tokens/verify", nil, nil, &verified)
	return verified.ExpiresOn, err
}

func (c *Client) Clean(ctx context.Context, account, zone, tunnelName string) error {
	tunnel, err := c.findTunnel(ctx, account, tunnelName)
	if err != nil || tunnel == "" {
		return err
	}
	records, err := c.records(ctx, zone, url.Values{"comment.exact": {Mark}})
	if err != nil {
		return err
	}
	var hosts []string
	for _, record := range records {
		if record.Comment == Mark && record.Content == tunnel+".cfargotunnel.com" {
			if err := c.do(ctx, http.MethodDelete, "/zones/"+zone+"/dns_records/"+record.ID, nil, nil, nil); err != nil {
				return err
			}
			hosts = append(hosts, record.Name)
		}
	}
	apps, err := c.apps(ctx, account)
	if err != nil {
		return err
	}
	for _, app := range apps {
		host, _, _ := strings.Cut(app.Domain, "/")
		if app.Name == Mark+" "+app.Domain && slices.Contains(hosts, host) {
			if err := c.do(ctx, http.MethodDelete, "/accounts/"+account+"/access/apps/"+app.ID, nil, nil, nil); err != nil {
				return err
			}
		}
	}
	return c.do(ctx, http.MethodDelete, "/accounts/"+account+"/cfd_tunnel/"+tunnel, url.Values{"cascade": {"true"}}, nil, nil)
}
