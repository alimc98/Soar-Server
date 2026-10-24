// Package socks implements the small, authenticated CONNECT-only SOCKS5
// listener used by the Linux bridge. It is bound to loopback by the command so
// only a local 3x-ui/Xray installation can use it.
package socks

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	version        = 5
	authVersion    = 1
	authUserPass   = 2
	authNoAccept   = 0xff
	commandConnect = 1
	atypIPv4       = 1
	atypDomain     = 3
	atypIPv6       = 4

	succeeded          = 0x00
	generalFailure     = 0x01
	notAllowed         = 0x02
	networkUnreachable = 0x03
	hostUnreachable    = 0x04
	connectionRefused  = 0x05
	ttlExpired         = 0x06
	commandUnsupported = 0x07
	atypUnsupported    = 0x08
)

type Options struct {
	Dial             func(ctx context.Context, network, address string) (net.Conn, error)
	Username         string
	Password         string
	MaxConnections   int
	HandshakeTimeout time.Duration
	DialTimeout      time.Duration
	Logger           *slog.Logger
}

type Stats struct {
	Active   int64
	Total    uint64
	Upload   int64
	Download int64
}

type Server struct {
	options Options

	slots    chan struct{}
	active   atomic.Int64
	total    atomic.Uint64
	upload   atomic.Int64
	download atomic.Int64
	wg       sync.WaitGroup
}

func New(options Options) *Server {
	if options.MaxConnections <= 0 {
		options.MaxConnections = 128
	}
	if options.HandshakeTimeout <= 0 {
		options.HandshakeTimeout = 10 * time.Second
	}
	if options.DialTimeout <= 0 {
		options.DialTimeout = 90 * time.Second
	}
	if options.Logger == nil {
		options.Logger = slog.Default()
	}
	return &Server{options: options, slots: make(chan struct{}, options.MaxConnections)}
}

// Serve accepts connections until ctx is cancelled or the listener fails.
// On cancellation it closes every accepted client, which also tears down the
// corresponding tunnel stream.
func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	var acceptErr error
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			acceptErr = err
			break
		}
		select {
		case s.slots <- struct{}{}:
		default:
			_ = conn.Close()
			continue
		}
		s.total.Add(1)
		s.active.Add(1)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { <-s.slots }()
			defer s.active.Add(-1)
			s.handle(ctx, conn)
		}()
	}
	cancel()
	s.wg.Wait()
	return acceptErr
}

func (s *Server) Stats() Stats {
	return Stats{
		Active:   s.active.Load(),
		Total:    s.total.Load(),
		Upload:   s.upload.Load(),
		Download: s.download.Load(),
	}
}

func (s *Server) handle(ctx context.Context, client net.Conn) {
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(s.options.HandshakeTimeout))

	if !s.negotiate(client) {
		return
	}
	target, ok := readRequest(client)
	if !ok {
		return
	}
	_ = client.SetDeadline(time.Time{})

	dialCtx, cancel := context.WithTimeout(ctx, s.options.DialTimeout)
	upstream, err := s.options.Dial(dialCtx, "tcp", target)
	cancel()
	if err != nil {
		_ = client.SetWriteDeadline(time.Now().Add(s.options.HandshakeTimeout))
		_ = writeReply(client, replyFor(err))
		return
	}
	defer upstream.Close()

	done := make(chan struct{})
	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			_ = client.Close()
			_ = upstream.Close()
			close(done)
		})
	}
	go func() {
		select {
		case <-ctx.Done():
			closeBoth()
		case <-done:
		}
	}()

	_ = client.SetWriteDeadline(time.Now().Add(s.options.HandshakeTimeout))
	if err := writeReply(client, succeeded); err != nil {
		return
	}
	_ = client.SetDeadline(time.Time{})

	copies := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(&counter{writer: upstream, value: &s.upload}, client)
		if half, ok := upstream.(interface{ CloseWrite() error }); ok {
			_ = half.CloseWrite()
		}
		copies <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(&counter{writer: client, value: &s.download}, upstream)
		// The destination is finished. Close the client so an idle upload side
		// cannot pin this tunnel stream forever.
		_ = client.Close()
		copies <- struct{}{}
	}()
	<-copies
	<-copies
	closeBoth()
}

func (s *Server) negotiate(client net.Conn) bool {
	var greeting [2]byte
	if _, err := io.ReadFull(client, greeting[:]); err != nil || greeting[0] != version || greeting[1] == 0 {
		return false
	}
	methods := make([]byte, int(greeting[1]))
	if _, err := io.ReadFull(client, methods); err != nil {
		return false
	}
	want := byte(0)
	if s.options.Username != "" {
		want = authUserPass
	}
	found := false
	for _, method := range methods {
		if method == want {
			found = true
			break
		}
	}
	if !found {
		_, _ = client.Write([]byte{version, authNoAccept})
		return false
	}
	if _, err := client.Write([]byte{version, want}); err != nil {
		return false
	}
	if want != authUserPass {
		return true
	}

	var header [2]byte
	if _, err := io.ReadFull(client, header[:]); err != nil || header[0] != authVersion || header[1] == 0 {
		return false
	}
	username := make([]byte, int(header[1]))
	if _, err := io.ReadFull(client, username); err != nil {
		return false
	}
	var size [1]byte
	if _, err := io.ReadFull(client, size[:]); err != nil || size[0] == 0 {
		return false
	}
	password := make([]byte, int(size[0]))
	if _, err := io.ReadFull(client, password); err != nil {
		return false
	}
	userOK := subtle.ConstantTimeCompare(username, []byte(s.options.Username)) == 1
	passOK := subtle.ConstantTimeCompare(password, []byte(s.options.Password)) == 1
	if !userOK || !passOK {
		_, _ = client.Write([]byte{authVersion, 1})
		return false
	}
	_, err := client.Write([]byte{authVersion, succeeded})
	return err == nil
}

func readRequest(client net.Conn) (string, bool) {
	var header [4]byte
	if _, err := io.ReadFull(client, header[:]); err != nil || header[0] != version || header[2] != 0 {
		return "", false
	}
	reply := func(code byte) { _ = writeReply(client, code) }
	if header[1] != commandConnect {
		reply(commandUnsupported)
		return "", false
	}
	var host string
	switch header[3] {
	case atypIPv4, atypIPv6:
		size := net.IPv4len
		if header[3] == atypIPv6 {
			size = net.IPv6len
		}
		raw := make([]byte, size)
		if _, err := io.ReadFull(client, raw); err != nil {
			return "", false
		}
		host = net.IP(raw).String()
	case atypDomain:
		var size [1]byte
		if _, err := io.ReadFull(client, size[:]); err != nil || size[0] == 0 {
			return "", false
		}
		raw := make([]byte, int(size[0]))
		if _, err := io.ReadFull(client, raw); err != nil {
			return "", false
		}
		host = string(raw)
		if strings.ContainsAny(host, "\x00\r\n") {
			reply(atypUnsupported)
			return "", false
		}
	default:
		reply(atypUnsupported)
		return "", false
	}
	var rawPort [2]byte
	if _, err := io.ReadFull(client, rawPort[:]); err != nil {
		return "", false
	}
	port := binary.BigEndian.Uint16(rawPort[:])
	if port == 0 {
		reply(notAllowed)
		return "", false
	}
	return net.JoinHostPort(host, strconv.Itoa(int(port))), true
}

func writeReply(w io.Writer, code byte) error {
	_, err := w.Write([]byte{version, code, 0, atypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}

func replyFor(err error) byte {
	if errors.Is(err, context.Canceled) {
		return generalFailure
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return ttlExpired
	}
	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "refused"):
		return connectionRefused
	case strings.Contains(message, "network is unreachable"):
		return networkUnreachable
	case strings.Contains(message, "no such host"), strings.Contains(message, "host is unreachable"):
		return hostUnreachable
	case strings.Contains(message, "denied"):
		return notAllowed
	default:
		return generalFailure
	}
}

type counter struct {
	writer io.Writer
	value  *atomic.Int64
}

func (c *counter) Write(p []byte) (int, error) {
	n, err := c.writer.Write(p)
	c.value.Add(int64(n))
	return n, err
}
