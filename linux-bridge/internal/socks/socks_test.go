package socks

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func echoServer(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return listener.Addr().String()
}

func startServer(t *testing.T, options Options) (*Server, string, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	server := New(options)
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("SOCKS server did not stop")
		}
	})
	return server, listener.Addr().String(), cancel
}

func dialProxy(t *testing.T, address string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	return conn
}

func handshake(t *testing.T, conn net.Conn, username, password string) byte {
	t.Helper()
	method := byte(0)
	if username != "" {
		method = 2
	}
	if _, err := conn.Write([]byte{5, 1, method}); err != nil {
		t.Fatal(err)
	}
	var selection [2]byte
	if _, err := io.ReadFull(conn, selection[:]); err != nil {
		t.Fatal(err)
	}
	if selection[0] != 5 || selection[1] != method {
		t.Fatalf("unexpected method selection: %v", selection)
	}
	if method == 0 {
		return 0
	}
	var auth bytes.Buffer
	auth.WriteByte(1)
	auth.WriteByte(byte(len(username)))
	auth.WriteString(username)
	auth.WriteByte(byte(len(password)))
	auth.WriteString(password)
	if _, err := conn.Write(auth.Bytes()); err != nil {
		t.Fatal(err)
	}
	var reply [2]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		t.Fatal(err)
	}
	return reply[1]
}

func request(t *testing.T, conn net.Conn, command byte, host string, port uint16) byte {
	t.Helper()
	var body bytes.Buffer
	body.Write([]byte{5, command, 0, 3, byte(len(host))})
	body.WriteString(host)
	_ = binary.Write(&body, binary.BigEndian, port)
	if _, err := conn.Write(body.Bytes()); err != nil {
		t.Fatal(err)
	}
	var reply [10]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		t.Fatal(err)
	}
	if reply[0] != 5 || reply[3] != 1 {
		t.Fatalf("unexpected reply: %v", reply)
	}
	return reply[1]
}

func TestAuthenticatedConnectAndMetering(t *testing.T) {
	echo := echoServer(t)
	server, proxy, _ := startServer(t, Options{
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, echo)
		},
		Username: "bridge-user", Password: "a-long-local-password",
	})
	conn := dialProxy(t, proxy)
	if status := handshake(t, conn, "bridge-user", "a-long-local-password"); status != 0 {
		t.Fatalf("authentication failed with %d", status)
	}
	if reply := request(t, conn, commandConnect, "example.org", 443); reply != succeeded {
		t.Fatalf("CONNECT failed with %#x", reply)
	}
	payload := []byte("payload through the DNS tunnel")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("echo payload corrupted")
	}
	stats := server.Stats()
	if stats.Upload < int64(len(payload)) || stats.Download < int64(len(payload)) || stats.Total != 1 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
	if stats.Active != 1 {
		t.Fatalf("active connections: %+v", stats)
	}
}

func TestRejectsWrongPasswordAndUnsupportedCommand(t *testing.T) {
	echo := echoServer(t)
	_, proxy, _ := startServer(t, Options{
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, echo)
		},
		Username: "bridge-user", Password: "correct-password",
	})
	bad := dialProxy(t, proxy)
	if status := handshake(t, bad, "bridge-user", "wrong-password"); status != 1 {
		t.Fatalf("wrong password status %d", status)
	}
	_ = bad.Close()

	conn := dialProxy(t, proxy)
	if status := handshake(t, conn, "bridge-user", "correct-password"); status != 0 {
		t.Fatalf("valid password status %d", status)
	}
	if reply := request(t, conn, 3, "example.org", 53); reply != commandUnsupported {
		t.Fatalf("UDP ASSOCIATE reply %#x", reply)
	}
}

func TestNoAuthMode(t *testing.T) {
	echo := echoServer(t)
	_, proxy, _ := startServer(t, Options{
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, echo)
		},
	})
	conn := dialProxy(t, proxy)
	if status := handshake(t, conn, "", ""); status != 0 {
		t.Fatalf("no-auth handshake failed with %d", status)
	}
	if reply := request(t, conn, commandConnect, "example.org", 443); reply != succeeded {
		t.Fatalf("CONNECT failed with %#x", reply)
	}
}

func TestCancelClosesActiveConnection(t *testing.T) {
	echo := echoServer(t)
	server, proxy, cancel := startServer(t, Options{
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, echo)
		},
	})
	conn := dialProxy(t, proxy)
	if status := handshake(t, conn, "", ""); status != 0 {
		t.Fatal("handshake failed")
	}
	if reply := request(t, conn, commandConnect, "example.org", 443); reply != succeeded {
		t.Fatalf("CONNECT failed with %#x", reply)
	}
	cancel()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("active connection survived shutdown")
	}
	deadline := time.Now().Add(2 * time.Second)
	for server.Stats().Active != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if server.Stats().Active != 0 {
		t.Fatalf("active counter did not drain: %+v", server.Stats())
	}
}
