// Command whitedns-bridge runs the WhiteDNS Soar client on a Linux server and
// exposes a loopback SOCKS5 listener. A local 3x-ui/Xray installation uses that
// listener as an outbound, so client VLESS traffic is carried over the DNS
// tunnel to the WhiteDNS server even when direct international access is cut.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/getlantern/soar"

	"whitedns-bridge/internal/profile"
	"whitedns-bridge/internal/socks"
)

var version = "0.1.0"

type options struct {
	profile         string
	profileFile     string
	listen          string
	username        string
	password        string
	resolvers       string
	resolverFile    string
	validate        bool
	startupCheck    bool
	maxConns        int
	dialTimeout     time.Duration
	logLevel        string
	printVersion    bool
	scanResolvers   bool
	scanOutput      string
	scanConcurrency int
	scanTimeout     time.Duration
	scanURL         string
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "whitedns-bridge: "+err.Error())
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	opts := options{}
	fs := flag.NewFlagSet("whitedns-bridge", flag.ContinueOnError)
	fs.StringVar(&opts.profile, "profile", env("WHITEDNS_PROFILE", ""), "soar:// link, subscription URL, or file")
	fs.StringVar(&opts.profileFile, "profile-file", env("WHITEDNS_PROFILE_FILE", "/etc/whitedns-bridge/profile"), "file containing a profile link")
	fs.StringVar(&opts.listen, "listen", env("WHITEDNS_SOCKS_LISTEN", "127.0.0.1:10886"), "loopback SOCKS5 listen address")
	fs.StringVar(&opts.username, "username", env("WHITEDNS_SOCKS_USER", ""), "optional SOCKS5 username (requires -password)")
	fs.StringVar(&opts.password, "password", env("WHITEDNS_SOCKS_PASS", ""), "optional SOCKS5 password (requires -username)")
	fs.StringVar(&opts.resolvers, "resolvers", env("WHITEDNS_RESOLVERS", ""), "comma/space separated resolver override (IP or IP:port)")
	fs.StringVar(&opts.resolverFile, "resolver-file", env("WHITEDNS_RESOLVER_FILE", ""), "text file of resolvers, one IP or IP:port per line")
	fs.BoolVar(&opts.validate, "validate", false, "load and validate the profile, then exit")
	fs.BoolVar(&opts.startupCheck, "check", true, "probe authenticated HTTPS through the tunnel after startup")
	fs.IntVar(&opts.maxConns, "max-conns", 0, "maximum concurrent SOCKS connections (default: profile maxStreams)")
	fs.DurationVar(&opts.dialTimeout, "dial-timeout", 0, "destination dial timeout (default: profile dialTimeoutSeconds)")
	fs.StringVar(&opts.logLevel, "log-level", env("WHITEDNS_LOG_LEVEL", "info"), "debug, info, warn or error")
	fs.BoolVar(&opts.printVersion, "version", false, "print version and exit")
	fs.BoolVar(&opts.scanResolvers, "scan-resolvers", false, "test resolver candidates through the tunnel and exit")
	fs.StringVar(&opts.scanOutput, "scan-output", "", "write working resolvers to this file instead of stdout")
	fs.IntVar(&opts.scanConcurrency, "scan-concurrency", 0, "resolver scan workers (default 8, maximum 64)")
	fs.DurationVar(&opts.scanTimeout, "scan-timeout", 0, "per-resolver scan timeout (default: profile dial timeout, capped at 30s)")
	fs.StringVar(&opts.scanURL, "scan-url", "https://example.com/", "HTTPS URL used to verify a resolver through the tunnel")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), `whitedns-bridge %s

Runs a headless WhiteDNS Soar client and a loopback SOCKS5 outbound for 3x-ui.

Examples:
  whitedns-bridge -profile 'soar://...'
  whitedns-bridge -profile-file /etc/whitedns-bridge/profile
  whitedns-bridge -profile 'https://panel.example/sub/TOKEN?format=plain'
  whitedns-bridge -profile-file /etc/whitedns-bridge/profile \\
    -resolver-file /etc/whitedns-bridge/resolvers.txt
  whitedns-bridge -profile-file /etc/whitedns-bridge/profile \\
    -resolver-file candidates.txt -scan-resolvers -scan-output good.txt

The listener must use a loopback address. Do not expose this SOCKS port
directly to the internet; SOCKS5 does not encrypt its credentials.
`, version)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if opts.printVersion {
		fmt.Println("whitedns-bridge " + version + " (Soar v0.2.3 + WhiteDNS transport fixes)")
		return nil
	}
	logger := newLogger(opts.logLevel)
	if opts.scanResolvers && opts.validate {
		return errors.New("-scan-resolvers and -validate cannot be used together")
	}
	if opts.resolvers != "" && opts.resolverFile != "" {
		return errors.New("use either -resolvers or -resolver-file, not both")
	}
	if opts.scanOutput != "" && !opts.scanResolvers {
		return errors.New("-scan-output requires -scan-resolvers")
	}
	source, err := profileSource(opts)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 20 * time.Second}
	p, err := profile.Load(ctx, source, client)
	if err != nil {
		return err
	}
	switch {
	case opts.resolvers != "":
		p.Resolvers, err = profile.NormalizeResolvers(splitResolvers(opts.resolvers))
		if err != nil {
			return err
		}
	case opts.resolverFile != "":
		if opts.scanResolvers {
			list, err := profile.LoadResolverCandidates(opts.resolverFile)
			if err != nil {
				return err
			}
			if len(list.Invalid) > 0 {
				logger.Warn("resolver file contains invalid entries; they will be skipped",
					"count", len(list.Invalid), "first", list.Invalid[0])
			}
			if len(list.Resolvers) == 0 {
				return errors.New("resolver file contains no valid resolvers")
			}
			p.Resolvers = list.Resolvers
		} else {
			p.Resolvers, err = profile.LoadResolverFile(opts.resolverFile)
			if err != nil {
				return err
			}
		}
	}
	if opts.validate {
		fmt.Printf("profile ok: name=%q zone=%s resolvers=%d discovery=%t transport=%s\n",
			p.Name, p.Zone, len(p.Resolvers), p.Settings.Discovery, p.Settings.Transport)
		return nil
	}
	if opts.scanResolvers {
		return runResolverScan(ctx, p, opts, logger)
	}
	if err := validateAuth(opts.username, opts.password); err != nil {
		return err
	}
	listen, err := validateListen(opts.listen)
	if err != nil {
		return err
	}

	soarLogger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	settings := p.Settings
	initial, discoveryCandidates, err := resolverPlan(p.Resolvers, settings.Discovery)
	if err != nil {
		return err
	}
	soarClient, err := soar.NewClient(buildSoarConfig(p, initial, discoveryCandidates, settings.Discovery, soarLogger))
	if err != nil {
		return fmt.Errorf("start Soar client: %w", err)
	}
	defer soarClient.Close()

	maxConns := opts.maxConns
	if maxConns == 0 {
		maxConns = settings.MaxStreams
	}
	dialTimeout := opts.dialTimeout
	if dialTimeout == 0 {
		dialTimeout = time.Duration(settings.DialTimeoutSeconds) * time.Second
	}
	server := socks.New(socks.Options{
		Dial:             soarClient.DialContext,
		Username:         opts.username,
		Password:         opts.password,
		MaxConnections:   maxConns,
		HandshakeTimeout: 10 * time.Second,
		DialTimeout:      dialTimeout,
		Logger:           logger,
	})
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", listen, err)
	}
	defer listener.Close()

	logger.Info("WhiteDNS bridge started",
		"name", p.Name, "zone", p.Zone, "listen", listener.Addr().String(),
		"auth", opts.username != "", "resolvers", len(p.Resolvers),
		"initial_resolvers", len(initial), "discovery_candidates", len(discoveryCandidates),
		"discovery", settings.Discovery, "max_conns", maxConns)
	if opts.username == "" {
		logger.Warn("SOCKS5 authentication is disabled; any local process can use the tunnel")
	}
	if opts.startupCheck {
		go readinessLoop(ctx, soarClient, logger)
	}
	go statsLoop(ctx, soarClient, server, logger)

	err = server.Serve(ctx, listener)
	if err != nil {
		return fmt.Errorf("SOCKS listener: %w", err)
	}
	logger.Info("WhiteDNS bridge stopped")
	return nil
}

func newLogger(level string) *slog.Logger {
	var value slog.Level
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		value = slog.LevelDebug
	case "warn", "warning":
		value = slog.LevelWarn
	case "error":
		value = slog.LevelError
	default:
		value = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: value}))
}

func profileSource(opts options) (string, error) {
	if strings.TrimSpace(opts.profile) != "" {
		return strings.TrimSpace(opts.profile), nil
	}
	file := strings.TrimSpace(opts.profileFile)
	if file == "" {
		return "", errors.New("provide -profile or -profile-file")
	}
	if _, err := os.Stat(file); err != nil {
		return "", fmt.Errorf("profile file %s: %w", file, err)
	}
	return file, nil
}

func validateAuth(username, password string) error {
	if (username == "") != (password == "") {
		return errors.New("SOCKS5 authentication requires both -username and -password")
	}
	if len(username) > 255 || len(password) > 255 {
		return errors.New("SOCKS5 username and password must each be at most 255 bytes")
	}
	return nil
}

func validateListen(value string) (string, error) {
	tcp, err := net.ResolveTCPAddr("tcp", value)
	if err != nil || tcp.Port < 1 || tcp.Port > 65535 {
		return "", errors.New("listen must be a loopback IP:port, for example 127.0.0.1:10886")
	}
	if tcp.IP == nil || !tcp.IP.IsLoopback() {
		return "", errors.New("the bridge only listens on loopback; put 3x-ui on the same server, or use SSH/WireGuard forwarding")
	}
	return tcp.String(), nil
}

func splitResolvers(value string) []string {
	return strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\t'
	})
}

const (
	// The running client uses every resolver up to this many initial paths.
	// Beyond that, discovery adds the rest as verified candidates. A very large
	// list is almost always the output of a scan, so keeping the fastest 128 is
	// the useful subset.
	maxRuntimeResolvers = 512
	maxInitialResolvers = 128
)

// resolverPlan splits a resolver list into initial paths and discovery
// candidates. A manual-only profile must fit in the initial-path limit because
// there is no discovery to add the remainder later.
func resolverPlan(resolvers []string, discovery bool) (initial, candidates []string, err error) {
	if len(resolvers) > maxRuntimeResolvers {
		return nil, nil, fmt.Errorf("resolver list has %d entries; keep at most %d", len(resolvers), maxRuntimeResolvers)
	}
	if len(resolvers) <= maxInitialResolvers {
		return resolvers, nil, nil
	}
	if !discovery {
		return nil, nil, fmt.Errorf("resolver list has %d entries but discovery is disabled; keep at most %d or enable discovery", len(resolvers), maxInitialResolvers)
	}
	return resolvers[:maxInitialResolvers], resolvers[maxInitialResolvers:], nil
}

func buildSoarConfig(p profile.Profile, initial, candidates []string, discovery bool, logger *slog.Logger) (soar.Config, error) {
	key, err := base64.StdEncoding.DecodeString(p.PublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return soar.Config{}, errors.New("profile public key is invalid")
	}
	settings := p.Settings
	return soar.Config{
		Zone:      p.Zone,
		ServerKey: ed25519.PublicKey(key),
		Resolvers: initial,
		TCP:       settings.Transport,
		Discovery: soar.Discovery{
			Enabled:     discovery,
			Country:     settings.Country,
			Candidates:  candidates,
			Want:        settings.DiscoveryWant,
			Concurrency: settings.DiscoveryConcurrency,
			Pace:        time.Duration(settings.DiscoveryPaceMs) * time.Millisecond,
		},
		SafeQName:     settings.SafeQName,
		MaxQName:      settings.MaxQName,
		MaxAnswer:     settings.MaxAnswer,
		Hold:          time.Duration(settings.HoldMs) * time.Millisecond,
		MaxInflight:   settings.MaxInflight,
		MaxPathWindow: settings.MaxPathWindow,
		MaxStreams:    settings.MaxStreams,
		StreamWindow:  uint64(settings.StreamWindowKiB) * 1024,
		SendBuffer:    settings.SendBufferKiB * 1024,
		SessionIdle:   time.Duration(settings.SessionIdleSeconds) * time.Second,
		StreamOnly: func(resolver string) bool {
			_, port, err := net.SplitHostPort(resolver)
			return err == nil && port == "853"
		},
		Logger: logger,
	}, nil
}

func env(name, fallback string) string {
	if value, ok := os.LookupEnv(name); ok {
		return value
	}
	return fallback
}

func readinessLoop(ctx context.Context, client *soar.Client, logger *slog.Logger) {
	attempt := 0
	for {
		attempt++
		probeCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		err := probeHTTPS(probeCtx, client.DialContext)
		cancel()
		if err == nil {
			logger.Info("authenticated HTTPS through the Soar tunnel succeeded", "attempt", attempt)
			return
		}
		logger.Warn("Soar tunnel is not ready yet", "attempt", attempt, "error", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(30 * time.Second):
		}
	}
}

func probeHTTPS(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error)) error {
	transport := &http.Transport{
		DialContext:           dial,
		DisableKeepAlives:     true,
		TLSHandshakeTimeout:   45 * time.Second,
		ResponseHeaderTimeout: 45 * time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}
	defer transport.CloseIdleConnections()
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/", nil)
	response, err := (&http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}).Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 400 {
		return fmt.Errorf("unexpected HTTPS status %d", response.StatusCode)
	}
	_, err = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
	return err
}

func statsLoop(ctx context.Context, client *soar.Client, server *socks.Server, logger *slog.Logger) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			stats := server.Stats()
			logger.Info("bridge stats",
				"active", stats.Active, "total", stats.Total,
				"upload_bytes", stats.Upload, "download_bytes", stats.Download,
				"established", client.Established())
		}
	}
}
