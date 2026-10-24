// Package profile parses the WhiteDNS soar:// profile and subscription formats.
// The bridge only needs the public tunnel identity, bootstrap resolvers and the
// Soar transport options; it never handles account private keys.
package profile

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"time"
)

const maxInput = 2 << 20

var linkPattern = regexp.MustCompile(`(?i)soar://[A-Za-z0-9+/_=-]+`)
var zoneLabelPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`)

// Settings mirrors the Soar options embedded in a WhiteDNS profile.
type Settings struct {
	Transport            string `json:"transport"`
	Discovery            bool   `json:"discovery"`
	Country              string `json:"country"`
	DiscoveryWant        int    `json:"discoveryWant"`
	DiscoveryConcurrency int    `json:"discoveryConcurrency"`
	DiscoveryPaceMs      int    `json:"discoveryPaceMs"`
	SafeQName            int    `json:"safeQName"`
	MaxQName             int    `json:"maxQName"`
	MaxAnswer            int    `json:"maxAnswer"`
	HoldMs               int    `json:"holdMs"`
	MaxInflight          int    `json:"maxInflight"`
	MaxPathWindow        int    `json:"maxPathWindow"`
	MaxStreams           int    `json:"maxStreams"`
	StreamWindowKiB      int    `json:"streamWindowKiB"`
	SendBufferKiB        int    `json:"sendBufferKiB"`
	SessionIdleSeconds   int    `json:"sessionIdleSeconds"`
	DialTimeoutSeconds   int    `json:"dialTimeoutSeconds"`
}

func DefaultSettings() Settings {
	return Settings{
		Transport: "auto", Discovery: true, Country: "IR", DiscoveryWant: 2,
		DiscoveryConcurrency: 2, DiscoveryPaceMs: 1000,
		SafeQName: 101, MaxQName: 253, MaxAnswer: 1232, HoldMs: 500,
		MaxInflight: 128, MaxPathWindow: 32, MaxStreams: 128,
		StreamWindowKiB: 256, SendBufferKiB: 64,
		SessionIdleSeconds: 90, DialTimeoutSeconds: 90,
	}
}

// UnmarshalJSON starts from the automatic defaults so an older profile that
// omits a field keeps the same behaviour as the desktop client.
func (s *Settings) UnmarshalJSON(raw []byte) error {
	type plain Settings
	value := plain(DefaultSettings())
	if err := json.Unmarshal(raw, &value); err != nil {
		return err
	}
	*s = Settings(value)
	return nil
}

func (s Settings) Validate() error {
	switch s.Transport {
	case "auto", "on", "only", "off":
	default:
		return errors.New("transport must be auto, on, only or off")
	}
	if s.Country != "" && (len(s.Country) != 2 || s.Country[0] < 'A' || s.Country[0] > 'Z' || s.Country[1] < 'A' || s.Country[1] > 'Z') {
		return errors.New("country must be a two-letter uppercase code or blank")
	}
	for _, bound := range []struct {
		name             string
		value, low, high int
	}{
		{"discoveryWant", s.DiscoveryWant, 1, 32},
		{"discoveryConcurrency", s.DiscoveryConcurrency, 1, 16},
		{"discoveryPaceMs", s.DiscoveryPaceMs, 100, 5000},
		{"safeQName", s.SafeQName, 101, 253},
		{"maxQName", s.MaxQName, s.SafeQName, 253},
		{"maxAnswer", s.MaxAnswer, 512, 1232},
		{"holdMs", s.HoldMs, 100, 1500},
		{"maxInflight", s.MaxInflight, 8, 1024},
		{"maxPathWindow", s.MaxPathWindow, 2, 128},
		{"maxStreams", s.MaxStreams, 8, 256},
		{"streamWindowKiB", s.StreamWindowKiB, 64, 1024},
		{"sendBufferKiB", s.SendBufferKiB, 32, 1024},
		{"sessionIdleSeconds", s.SessionIdleSeconds, 15, 110},
		{"dialTimeoutSeconds", s.DialTimeoutSeconds, 5, 120},
	} {
		if bound.value < bound.low || bound.value > bound.high {
			return fmt.Errorf("%s must be between %d and %d", bound.name, bound.low, bound.high)
		}
	}
	return nil
}

// Profile is the non-secret connection identity exported by the panel.
type Profile struct {
	ID        string
	Name      string
	Zone      string
	PublicKey string
	Resolvers []string
	Settings  Settings
}

type profilePayload struct {
	Schema     string `json:"schema"`
	Version    int    `json:"version"`
	ImportType string `json:"import_type"`
	Profile    struct {
		ID           string    `json:"id"`
		Name         string    `json:"name"`
		Resolvers    []string  `json:"resolvers"`
		SoarSettings *Settings `json:"soarSettings"`
		Server       struct {
			Domain        string   `json:"domain"`
			Domains       []string `json:"domains"`
			PublicKey     string   `json:"public_key"`
			EncryptionKey string   `json:"encryption_key"`
		} `json:"server"`
	} `json:"profile"`
}

// Load accepts a soar:// link, an HTTPS subscription URL, or a file containing
// either. Subscription bodies may be plain text or base64, matching the panel.
func Load(ctx context.Context, source string, client *http.Client) (Profile, error) {
	source = strings.TrimSpace(source)
	if source == "" {
		return Profile{}, errors.New("profile is empty")
	}
	if strings.HasPrefix(strings.ToLower(source), "soar://") {
		return ParseLink(source)
	}
	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		body, err := fetch(ctx, client, source)
		if err != nil {
			return Profile{}, err
		}
		if link := findLink(body); link != "" {
			return ParseLink(link)
		}
		return Profile{}, errors.New("subscription did not contain a soar:// profile")
	}
	data, err := os.ReadFile(source)
	if err != nil {
		return Profile{}, fmt.Errorf("read profile: %w", err)
	}
	if len(data) > maxInput {
		return Profile{}, errors.New("profile file is too large")
	}
	if link := findLink(data); link != "" {
		return ParseLink(link)
	}
	return Profile{}, errors.New("file did not contain a soar:// profile")
}

func fetch(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "text/plain, application/json;q=0.5, */*;q=0.1")
	req.Header.Set("User-Agent", "whitedns-bridge/0.1")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download subscription: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("subscription returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxInput+1))
	if err != nil {
		return nil, fmt.Errorf("read subscription: %w", err)
	}
	if len(body) > maxInput {
		return nil, errors.New("subscription is too large")
	}
	return body, nil
}

func findLink(body []byte) string {
	text := strings.TrimSpace(string(body))
	if link := linkPattern.FindString(text); link != "" {
		return link
	}
	// The panel returns a base64 body by default.
	for _, decode := range []func(string) ([]byte, error){
		base64.StdEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
		base64.URLEncoding.DecodeString,
		base64.RawURLEncoding.DecodeString,
	} {
		if raw, err := decode(text); err == nil {
			if link := linkPattern.FindString(string(raw)); link != "" {
				return link
			}
		}
	}
	return ""
}

// ParseLink decodes a single soar:// link.
func ParseLink(link string) (Profile, error) {
	link = strings.TrimSpace(link)
	if !strings.HasPrefix(strings.ToLower(link), "soar://") {
		return Profile{}, errors.New("not a soar:// profile link")
	}
	encoded := link[len("soar://"):]
	raw, err := decodeBase64(encoded)
	if err != nil {
		return Profile{}, errors.New("invalid soar:// payload")
	}
	var payload profilePayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return Profile{}, errors.New("invalid profile JSON")
	}
	if payload.Schema != "whitedns.profile" || payload.Version != 1 {
		return Profile{}, errors.New("unsupported profile schema or version")
	}
	if payload.ImportType != "" && !strings.EqualFold(payload.ImportType, "soar") {
		return Profile{}, errors.New("profile is not a Soar profile")
	}
	zone := strings.TrimSpace(payload.Profile.Server.Domain)
	if zone == "" && len(payload.Profile.Server.Domains) > 0 {
		zone = strings.TrimSpace(payload.Profile.Server.Domains[0])
	}
	zone = strings.ToLower(zone)
	if err := validateZone(zone); err != nil {
		return Profile{}, err
	}
	key := strings.TrimSpace(payload.Profile.Server.PublicKey)
	if key == "" {
		key = strings.TrimSpace(payload.Profile.Server.EncryptionKey)
	}
	decodedKey, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(decodedKey) != ed25519.PublicKeySize {
		return Profile{}, errors.New("profile does not contain a valid 32-byte Ed25519 public key")
	}
	settings := DefaultSettings()
	if payload.Profile.SoarSettings != nil {
		settings = *payload.Profile.SoarSettings
	}
	if err := settings.Validate(); err != nil {
		return Profile{}, fmt.Errorf("profile settings: %w", err)
	}
	resolvers, err := NormalizeResolvers(payload.Profile.Resolvers)
	if err != nil {
		return Profile{}, err
	}
	if len(resolvers) == 0 && !settings.Discovery {
		return Profile{}, errors.New("profile has no resolvers and discovery is disabled")
	}
	name := strings.TrimSpace(payload.Profile.Name)
	if name == "" {
		name = zone
	}
	return Profile{
		ID:        strings.TrimSpace(payload.Profile.ID),
		Name:      name,
		Zone:      zone,
		PublicKey: key,
		Resolvers: resolvers,
		Settings:  settings,
	}, nil
}

func decodeBase64(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	for _, decode := range []func(string) ([]byte, error){
		base64.RawURLEncoding.DecodeString,
		base64.URLEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
		base64.StdEncoding.DecodeString,
	} {
		if raw, err := decode(value); err == nil {
			return raw, nil
		}
	}
	return nil, errors.New("invalid base64")
}

func validateZone(zone string) error {
	if zone == "" || len(zone) > 45 || !strings.Contains(zone, ".") {
		return errors.New("profile needs one lowercase tunnel domain of at most 45 characters")
	}
	for _, label := range strings.Split(zone, ".") {
		if len(label) == 0 || len(label) > 63 || !zoneLabelPattern.MatchString(label) {
			return errors.New("invalid tunnel domain in profile")
		}
	}
	return nil
}

// Resolver list limits. The scanner can handle a large candidate file, but the
// running bridge only needs the working subset.
const (
	MaxResolverFileSize = 16 << 20
	MaxResolverEntries  = 8192
)

// ResolverList is the result of parsing a resolver text file. Invalid entries
// are reported separately so the scanner can continue with the valid ones.
type ResolverList struct {
	Resolvers  []string
	Invalid    []string
	Duplicates int
}

// NormalizeResolvers accepts the IP or IP:port forms used by the panel and adds
// the DNS port when it is omitted.
func NormalizeResolvers(values []string) ([]string, error) {
	if len(values) > MaxResolverEntries {
		return nil, errors.New("too many resolvers in profile")
	}
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, raw := range values {
		address, err := normalizeResolver(raw)
		if err != nil {
			return nil, err
		}
		if !seen[address] {
			seen[address] = true
			out = append(out, address)
		}
	}
	return out, nil
}

func normalizeResolver(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", errors.New("empty resolver in profile")
	}
	if ip, err := netip.ParseAddr(value); err == nil {
		return net.JoinHostPort(ip.String(), "53"), nil
	}
	if ap, err := netip.ParseAddrPort(value); err == nil && ap.Port() != 0 {
		return ap.String(), nil
	}
	return "", fmt.Errorf("resolver %q is not an IP or IP:port address", raw)
}

// ParseResolverList accepts one or more IP/IP:port entries per line. Blank
// lines and text after # are ignored. It is intentionally permissive: the
// scanner can report invalid entries and still test the valid ones.
func ParseResolverList(data []byte) (ResolverList, error) {
	if len(data) > MaxResolverFileSize {
		return ResolverList{}, errors.New("resolver file exceeds the 16 MiB input limit")
	}
	result := ResolverList{}
	seen := make(map[string]bool)
	for lineNo, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if line == "" {
			continue
		}
		fields := strings.FieldsFunc(line, func(r rune) bool {
			return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\r'
		})
		for _, raw := range fields {
			address, err := normalizeResolver(raw)
			if err != nil {
				result.Invalid = append(result.Invalid, fmt.Sprintf("line %d: %s", lineNo+1, raw))
				continue
			}
			if seen[address] {
				result.Duplicates++
				continue
			}
			seen[address] = true
			result.Resolvers = append(result.Resolvers, address)
			if len(result.Resolvers) > MaxResolverEntries {
				return ResolverList{}, fmt.Errorf("resolver file contains more than %d valid entries", MaxResolverEntries)
			}
		}
	}
	return result, nil
}

// LoadResolverCandidates reads a resolver text file for the scanner. Invalid
// lines are returned in the result instead of aborting the whole scan.
func LoadResolverCandidates(path string) (ResolverList, error) {
	file, err := os.Open(path)
	if err != nil {
		return ResolverList{}, fmt.Errorf("open resolver file: %w", err)
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		return ResolverList{}, fmt.Errorf("stat resolver file: %w", err)
	}
	if stat.Size() > MaxResolverFileSize {
		return ResolverList{}, errors.New("resolver file exceeds the 16 MiB input limit")
	}
	data, err := io.ReadAll(io.LimitReader(file, MaxResolverFileSize+1))
	if err != nil {
		return ResolverList{}, fmt.Errorf("read resolver file: %w", err)
	}
	return ParseResolverList(data)
}

// LoadResolverFile reads a strict runtime list. Any invalid line is an error so
// a typo cannot silently reduce the resolver set.
func LoadResolverFile(path string) ([]string, error) {
	list, err := LoadResolverCandidates(path)
	if err != nil {
		return nil, err
	}
	if len(list.Invalid) > 0 {
		return nil, fmt.Errorf("resolver file has %d invalid entries; first: %s", len(list.Invalid), list.Invalid[0])
	}
	if len(list.Resolvers) == 0 {
		return nil, errors.New("resolver file contains no valid resolvers")
	}
	return list.Resolvers, nil
}
