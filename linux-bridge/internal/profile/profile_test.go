package profile

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testKey(t *testing.T) string {
	t.Helper()
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	return base64.StdEncoding.EncodeToString(key)
}

func testLink(t *testing.T, mutate func(map[string]any)) string {
	t.Helper()
	body := map[string]any{
		"schema": "whitedns.profile", "version": 1,
		"profile": map[string]any{
			"id": "0123456789abcdef0123456789abcdef", "name": "bridge",
			"server":    map[string]string{"domain": "a1.example.org", "public_key": testKey(t)},
			"resolvers": []string{"1.1.1.1", "8.8.8.8:53"},
		},
	}
	if mutate != nil {
		mutate(body)
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return "soar://" + base64.RawURLEncoding.EncodeToString(raw)
}

func TestParseLinkDefaultsAndResolvers(t *testing.T) {
	p, err := ParseLink(testLink(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "bridge" || p.Zone != "a1.example.org" || len(p.Resolvers) != 2 {
		t.Fatalf("unexpected profile: %+v", p)
	}
	if p.Resolvers[0] != "1.1.1.1:53" || p.Resolvers[1] != "8.8.8.8:53" {
		t.Fatalf("resolvers not normalized: %v", p.Resolvers)
	}
	if p.Settings.Transport != "auto" || !p.Settings.Discovery || p.Settings.MaxStreams != 128 {
		t.Fatalf("defaults not applied: %+v", p.Settings)
	}
}

func TestParseLinkSettings(t *testing.T) {
	p, err := ParseLink(testLink(t, func(body map[string]any) {
		body["profile"].(map[string]any)["soarSettings"] = map[string]any{
			"transport": "only", "discovery": false, "country": "IR",
			"safeQName": 101, "maxQName": 253, "maxAnswer": 1232,
			"holdMs": 500, "maxInflight": 64, "maxPathWindow": 16,
			"maxStreams": 32, "streamWindowKiB": 256, "sendBufferKiB": 64,
			"sessionIdleSeconds": 90, "dialTimeoutSeconds": 30,
		}
	}))
	if err != nil {
		t.Fatal(err)
	}
	if p.Settings.Transport != "only" || p.Settings.Discovery || p.Settings.MaxStreams != 32 || p.Settings.DialTimeoutSeconds != 30 {
		t.Fatalf("settings not parsed: %+v", p.Settings)
	}
}

func TestLoadSubscription(t *testing.T) {
	link := testLink(t, nil)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(base64.StdEncoding.EncodeToString([]byte(link + "\n"))))
	}))
	defer server.Close()
	p, err := Load(context.Background(), server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if p.Zone != "a1.example.org" {
		t.Fatalf("unexpected zone %q", p.Zone)
	}
}

func TestParseLinkRejectsBadProfiles(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"bad zone", func(body map[string]any) {
			body["profile"].(map[string]any)["server"].(map[string]string)["domain"] = "bad_zone.example.org"
		}},
		{"bad key", func(body map[string]any) {
			body["profile"].(map[string]any)["server"].(map[string]string)["public_key"] = "AAAA"
		}},
		{"bad resolver", func(body map[string]any) {
			body["profile"].(map[string]any)["resolvers"] = []string{"dns.example.org"}
		}},
		{"no resolvers without discovery", func(body map[string]any) {
			body["profile"].(map[string]any)["resolvers"] = []string{}
			body["profile"].(map[string]any)["soarSettings"] = map[string]any{"discovery": false}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseLink(testLink(t, tc.mutate)); err == nil {
				t.Fatal("bad profile accepted")
			}
		})
	}
	if _, err := ParseLink("https://example.org/"); err == nil {
		t.Fatal("non-soar link accepted")
	}
}

func TestFindLinkPlainAndPadded(t *testing.T) {
	link := testLink(t, nil)
	if got := findLink([]byte("x\n" + link + "\n")); !strings.HasPrefix(got, "soar://") {
		t.Fatalf("plain link not found: %q", got)
	}
	if got := findLink([]byte(base64.StdEncoding.EncodeToString([]byte(link)))); !strings.HasPrefix(got, "soar://") {
		t.Fatalf("base64 link not found: %q", got)
	}
}
