package socks

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/getlantern/soar"
)

// TestEndToEndSoarTunnel exercises the same path as the installed bridge:
// a local SOCKS client, the bridge SOCKS server, the Soar client, a local DNS
// tunnel server, and a TCP destination. This catches configuration mistakes
// that a fake dialer cannot.
func TestEndToEndSoarTunnel(t *testing.T) {
	echo := echoServer(t)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		_ = soar.Serve(ctx, packet, soar.ServerConfig{
			Zone:       "t.example.org",
			PrivateKey: private,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, address)
			},
		})
	}()
	t.Cleanup(func() { _ = packet.Close() })
	tunnel, err := soar.NewClient(soar.Config{
		Zone:      "t.example.org",
		ServerKey: public,
		Resolvers: []string{packet.LocalAddr().String()},
		TCP:       "off",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tunnel.Close() })

	_, proxy, _ := startServer(t, Options{
		Dial:             tunnel.DialContext,
		HandshakeTimeout: 5 * time.Second,
		DialTimeout:      20 * time.Second,
	})
	conn := dialProxy(t, proxy)
	if status := handshake(t, conn, "", ""); status != 0 {
		t.Fatalf("SOCKS handshake failed with %d", status)
	}
	if reply := request(t, conn, commandConnect, "127.0.0.1", portOf(t, echo)); reply != succeeded {
		t.Fatalf("CONNECT through Soar failed with %#x", reply)
	}
	payload := []byte("bridge end-to-end payload")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload corrupted: %q", got)
	}
}

func portOf(t *testing.T, address string) uint16 {
	t.Helper()
	_, raw, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(raw)
	if err != nil {
		t.Fatal(err)
	}
	return uint16(port)
}
