package panel

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// The SOCKS5 egress is deliberately small: CONNECT only, username/password
// authentication, and the same account policy as tunneled traffic. It exists so
// a 3x-ui/Xray installation can use the panel as an authenticated outbound
// without sharing an unrestricted proxy or a panel administrator password.
const (
	socksVersion        = 5
	socksAuthVersion    = 1
	socksAuthUserPass   = 2
	socksAuthNoAccept   = 0xff
	socksCommandConnect = 1
	socksAtypIPv4       = 1
	socksAtypDomain     = 3
	socksAtypIPv6       = 4
	socksMaxConns       = 512
	socksHandshakeTime  = 10 * time.Second
	socksDialTime       = 20 * time.Second
	socksAuthWindow     = 5 * time.Minute
	socksAuthFailures   = 10
)

const (
	socksSucceeded          = 0x00
	socksGeneralFailure     = 0x01
	socksNotAllowed         = 0x02
	socksNetworkUnreachable = 0x03
	socksHostUnreachable    = 0x04
	socksConnectionRefused  = 0x05
	socksTTLExpired         = 0x06
	socksCommandUnsupported = 0x07
	socksAtypUnsupported    = 0x08
)

type socksFailure struct {
	until time.Time
	count int
}

// SocksStatus is the public, non-secret state of the egress listener.
type SocksStatus struct {
	Enabled   bool   `json:"enabled"`
	Listening bool   `json:"listening"`
	Listen    string `json:"listen"`
	Active    int    `json:"active"`
	Total     uint64 `json:"total"`
	LastError string `json:"last_error,omitempty"`
}

// SocksServer owns at most one listener. Reconfiguration is atomic from the
// caller's perspective: a failed bind leaves the previous listener untouched.
type SocksServer struct {
	manager *Manager
	store   *Store

	mu        sync.Mutex
	ln        net.Listener
	listen    string
	bound     string
	enabled   bool
	closed    bool
	lastError string
	conns     map[net.Conn]string
	upstreams map[net.Conn]net.Conn
	failures  map[string]socksFailure
	total     atomic.Uint64
	wg        sync.WaitGroup
}

func NewSocksServer(m *Manager, s *Store) *SocksServer {
	return &SocksServer{manager: m, store: s, conns: map[net.Conn]string{}, upstreams: map[net.Conn]net.Conn{}, failures: map[string]socksFailure{}}
}

// Apply enables, disables or moves the listener. Callers may pass the whole
// Settings value; only the SOCKS fields are read.
func (x *SocksServer) Apply(enabled bool, listen string) error {
	listen = strings.TrimSpace(listen)
	if listen == "" {
		listen = DefaultSocksListen
	}
	x.mu.Lock()
	if x.closed {
		x.mu.Unlock()
		return errors.New("SOCKS5 service is shutting down")
	}
	if !enabled {
		stale := x.stopLocked()
		x.listen, x.lastError = listen, ""
		x.mu.Unlock()
		closeConns(stale)
		return nil
	}
	if x.ln != nil && x.listen == listen {
		x.enabled = true
		x.lastError = ""
		x.mu.Unlock()
		return nil
	}
	// A wildcard listener and a specific address on the same port overlap, so
	// the old socket must be released before the replacement can bind. This is
	// the common 127.0.0.1 -> 0.0.0.0 change made when 3x-ui runs elsewhere.
	rebind := x.ln != nil && sameListenPort(x.listen, listen)
	var oldListen string
	var stale []net.Conn
	if rebind {
		oldListen = x.listen
		stale = x.stopLocked()
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		if rebind {
			// Keep the persisted configuration serving if the new address is
			// invalid or occupied.
			if oldLn, retryErr := net.Listen("tcp", oldListen); retryErr == nil {
				x.ln, x.listen, x.enabled = oldLn, oldListen, true
				x.bound = oldLn.Addr().String()
				x.wg.Add(1)
				go x.accept(oldLn)
			}
		}
		x.lastError = err.Error()
		x.mu.Unlock()
		closeConns(stale)
		return fmt.Errorf("cannot listen for SOCKS5 on %s: %w", listen, err)
	}
	if !rebind {
		stale = x.stopLocked()
	}
	x.ln, x.listen, x.enabled, x.lastError = ln, listen, true, ""
	x.bound = ln.Addr().String()
	x.wg.Add(1)
	x.mu.Unlock()
	closeConns(stale)
	go x.accept(ln)
	return nil
}

func sameListenPort(a, b string) bool {
	_, ap, errA := net.SplitHostPort(a)
	_, bp, errB := net.SplitHostPort(b)
	portA, errC := strconv.Atoi(ap)
	portB, errD := strconv.Atoi(bp)
	return errA == nil && errB == nil && errC == nil && errD == nil && portA == portB
}

func (x *SocksServer) accept(ln net.Listener) {
	defer x.wg.Done()
	for {
		c, err := ln.Accept()
		if err != nil {
			x.mu.Lock()
			if x.ln == ln {
				x.lastError = err.Error()
			}
			x.mu.Unlock()
			return
		}
		x.mu.Lock()
		if x.closed || x.ln != ln || len(x.conns) >= socksMaxConns {
			x.mu.Unlock()
			c.Close()
			continue
		}
		x.conns[c] = ""
		x.total.Add(1)
		x.wg.Add(1)
		x.mu.Unlock()
		go x.serve(c)
	}
}

func (x *SocksServer) serve(c net.Conn) {
	defer x.wg.Done()
	defer x.drop(c)
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(socksHandshakeTime))
	clientID, target, err := x.handshake(c)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), socksDialTime)
	upstream, err := x.manager.DialForClient(ctx, clientID, "tcp", target)
	cancel()
	if err != nil {
		// The handshake deadline may already have expired while dialing.
		_ = c.SetWriteDeadline(time.Now().Add(socksHandshakeTime))
		_ = writeSocksReply(c, socksReplyFor(err))
		return
	}
	defer upstream.Close()
	x.mu.Lock()
	if _, live := x.conns[c]; !live {
		// The account was disconnected or the listener was reconfigured while
		// the destination was still being dialed.
		x.mu.Unlock()
		return
	}
	x.upstreams[c] = upstream
	x.mu.Unlock()
	_ = c.SetWriteDeadline(time.Now().Add(socksHandshakeTime))
	if err := writeSocksReply(c, socksSucceeded); err != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})
	pipeSocks(c, upstream)
}

// handshake performs method negotiation, authentication and the CONNECT
// request. Replies for rejected handshakes are written here; the caller only
// reports dial failures.
func (x *SocksServer) handshake(c net.Conn) (string, string, error) {
	var greeting [2]byte
	if _, err := io.ReadFull(c, greeting[:]); err != nil {
		return "", "", err
	}
	if greeting[0] != socksVersion || greeting[1] == 0 {
		return "", "", errors.New("invalid SOCKS greeting")
	}
	methods := make([]byte, int(greeting[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return "", "", err
	}
	offersPassword := false
	for _, m := range methods {
		if m == socksAuthUserPass {
			offersPassword = true
		}
	}
	if !offersPassword {
		_, _ = c.Write([]byte{socksVersion, socksAuthNoAccept})
		return "", "", errors.New("client does not offer username/password authentication")
	}
	if _, err := c.Write([]byte{socksVersion, socksAuthUserPass}); err != nil {
		return "", "", err
	}

	var auth [2]byte
	if _, err := io.ReadFull(c, auth[:]); err != nil {
		return "", "", err
	}
	if auth[0] != socksAuthVersion || auth[1] == 0 {
		return "", "", errors.New("invalid SOCKS authentication")
	}
	username := make([]byte, int(auth[1]))
	if _, err := io.ReadFull(c, username); err != nil {
		return "", "", err
	}
	// Associate the pending connection with its claimed account before the
	// password check. Rotation can then revoke an attempt that authenticated
	// with the previous epoch but has not finished dialing yet.
	x.bind(c, string(username))
	var passLen [1]byte
	if _, err := io.ReadFull(c, passLen[:]); err != nil {
		return "", "", err
	}
	password := make([]byte, int(passLen[0]))
	if _, err := io.ReadFull(c, password); err != nil {
		return "", "", err
	}
	remote := remoteHost(c.RemoteAddr())
	if !x.authorized(remote) {
		_, _ = c.Write([]byte{socksAuthVersion, 1})
		return "", "", ErrDenied
	}
	client, err := x.store.CheckSocks(string(username), string(password))
	if err != nil {
		x.authFailed(remote)
		_, _ = c.Write([]byte{socksAuthVersion, 1})
		return "", "", ErrDenied
	}
	x.authSucceeded(remote)
	if _, err := c.Write([]byte{socksAuthVersion, socksSucceeded}); err != nil {
		return "", "", err
	}

	var request [4]byte
	if _, err := io.ReadFull(c, request[:]); err != nil {
		return "", "", err
	}
	if request[0] != socksVersion {
		return "", "", errors.New("invalid SOCKS request")
	}
	if request[1] != socksCommandConnect {
		_ = writeSocksReply(c, socksCommandUnsupported)
		return "", "", errors.New("unsupported SOCKS command")
	}
	if request[2] != 0 {
		return "", "", errors.New("invalid SOCKS reserved byte")
	}
	host, err := readSocksHost(c, request[3])
	if err != nil {
		_ = writeSocksReply(c, socksAtypUnsupported)
		return "", "", err
	}
	var portRaw [2]byte
	if _, err := io.ReadFull(c, portRaw[:]); err != nil {
		return "", "", err
	}
	port := binary.BigEndian.Uint16(portRaw[:])
	if port == 0 {
		_ = writeSocksReply(c, socksNotAllowed)
		return "", "", errors.New("invalid SOCKS destination port")
	}
	return client.ID, net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

func readSocksHost(c io.Reader, atyp byte) (string, error) {
	switch atyp {
	case socksAtypIPv4:
		var raw [4]byte
		if _, err := io.ReadFull(c, raw[:]); err != nil {
			return "", err
		}
		return net.IP(raw[:]).String(), nil
	case socksAtypIPv6:
		var raw [16]byte
		if _, err := io.ReadFull(c, raw[:]); err != nil {
			return "", err
		}
		return net.IP(raw[:]).String(), nil
	case socksAtypDomain:
		var size [1]byte
		if _, err := io.ReadFull(c, size[:]); err != nil {
			return "", err
		}
		if size[0] == 0 {
			return "", errors.New("empty SOCKS destination host")
		}
		raw := make([]byte, int(size[0]))
		if _, err := io.ReadFull(c, raw); err != nil {
			return "", err
		}
		host := strings.ToLower(string(raw))
		if !validSocksHost(host) {
			return "", errors.New("invalid SOCKS destination host")
		}
		return host, nil
	default:
		return "", errors.New("unsupported SOCKS address type")
	}
}

func validSocksHost(host string) bool {
	if host == "" || len(host) > 253 || strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") {
		return false
	}
	for _, r := range host {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '.' || r == '_' {
			continue
		}
		return false
	}
	return !strings.Contains(host, "..")
}

func writeSocksReply(w io.Writer, code byte) error {
	_, err := w.Write([]byte{socksVersion, code, 0, socksAtypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}

// socksReplyFor maps policy and network failures onto the RFC 1928 reply set.
// Clients only use this for diagnostics, but an accurate code is important for
// 3x-ui health checks and Xray logs.
func socksReplyFor(err error) byte {
	if errors.Is(err, ErrDenied) {
		return socksNotAllowed
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return socksTTLExpired
	}
	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "denied"), strings.Contains(message, "stream limit"):
		return socksNotAllowed
	case strings.Contains(message, "refused"):
		return socksConnectionRefused
	case strings.Contains(message, "network is unreachable"):
		return socksNetworkUnreachable
	case strings.Contains(message, "no such host"), strings.Contains(message, "host is unreachable"):
		return socksHostUnreachable
	default:
		return socksGeneralFailure
	}
}

func pipeSocks(client, upstream net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, client)
		closeWrite(upstream)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, upstream)
		// Once the destination is done there is nothing left to send. Closing
		// the client also unblocks the request direction, so a stale or idle
		// connection cannot occupy one of the 512 slots after its account was
		// disabled or its upstream disappeared.
		_ = client.Close()
		done <- struct{}{}
	}()
	<-done
	<-done
}

func closeWrite(c net.Conn) {
	if v, ok := c.(interface{ CloseWrite() error }); ok {
		_ = v.CloseWrite()
	}
}

func remoteHost(a net.Addr) string {
	if a == nil {
		return ""
	}
	if host, _, err := net.SplitHostPort(a.String()); err == nil {
		return host
	}
	return a.String()
}

func (x *SocksServer) authorized(remote string) bool {
	x.mu.Lock()
	defer x.mu.Unlock()
	f := x.failures[remote]
	return time.Now().After(f.until) || f.count < socksAuthFailures
}

func (x *SocksServer) authFailed(remote string) {
	now := time.Now()
	x.mu.Lock()
	defer x.mu.Unlock()
	f := x.failures[remote]
	if now.After(f.until) {
		f = socksFailure{until: now.Add(socksAuthWindow)}
	}
	f.count++
	if len(x.failures) >= 1024 {
		for key, v := range x.failures {
			if now.After(v.until) {
				delete(x.failures, key)
			}
		}
		if len(x.failures) >= 1024 {
			x.failures = map[string]socksFailure{}
		}
	}
	x.failures[remote] = f
}

func (x *SocksServer) authSucceeded(remote string) {
	x.mu.Lock()
	delete(x.failures, remote)
	x.mu.Unlock()
}

func (x *SocksServer) bind(c net.Conn, clientID string) {
	x.mu.Lock()
	if _, ok := x.conns[c]; ok {
		x.conns[c] = clientID
	}
	x.mu.Unlock()
}

func (x *SocksServer) drop(c net.Conn) {
	x.mu.Lock()
	up := x.upstreams[c]
	delete(x.upstreams, c)
	delete(x.conns, c)
	x.mu.Unlock()
	if up != nil {
		_ = up.Close()
	}
}

// CloseClient revokes the SOCKS connections owned by an account. Tunnel streams
// are handled separately by Manager.Disconnect/Reconcile.
func (x *SocksServer) CloseClient(clientID string) {
	x.mu.Lock()
	var stale []net.Conn
	for c, id := range x.conns {
		if id == clientID {
			stale = append(stale, c)
			if up := x.upstreams[c]; up != nil {
				stale = append(stale, up)
				delete(x.upstreams, c)
			}
			delete(x.conns, c)
		}
	}
	x.mu.Unlock()
	closeConns(stale)
}

func (x *SocksServer) Status(cfg Settings) SocksStatus {
	status := SocksStatus{Enabled: cfg.SocksEnabled, Listen: cfg.SocksListen}
	if status.Listen == "" {
		status.Listen = DefaultSocksListen
	}
	if x == nil {
		return status
	}
	x.mu.Lock()
	status.Listening = x.ln != nil && x.enabled
	status.Active = len(x.conns)
	status.Total = x.total.Load()
	status.LastError = x.lastError
	if x.listen != "" {
		status.Listen = x.listen
	}
	if status.Listening && x.bound != "" {
		status.Listen = x.bound
	}
	x.mu.Unlock()
	return status
}

func (x *SocksServer) Close() {
	if x == nil {
		return
	}
	x.mu.Lock()
	x.closed = true
	stale := x.stopLocked()
	x.mu.Unlock()
	closeConns(stale)
	x.wg.Wait()
}

// stopLocked closes the listener and returns established connections for the
// caller to close after releasing the lock. It must be called with x.mu held.
func (x *SocksServer) stopLocked() []net.Conn {
	ln := x.ln
	x.ln, x.enabled = nil, false
	x.bound = ""
	stale := make([]net.Conn, 0, len(x.conns)*2)
	for c := range x.conns {
		stale = append(stale, c)
		if up := x.upstreams[c]; up != nil {
			stale = append(stale, up)
		}
		delete(x.conns, c)
		delete(x.upstreams, c)
	}
	if ln != nil {
		_ = ln.Close()
	}
	return stale
}

func closeConns(conns []net.Conn) {
	for _, c := range conns {
		_ = c.Close()
	}
}
