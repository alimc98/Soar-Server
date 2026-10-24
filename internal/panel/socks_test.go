package panel

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func testSocksProxy(t *testing.T, m *Manager, s *Store) (*SocksServer, string) {
	t.Helper()
	x := NewSocksServer(m, s)
	if err := x.Apply(true, "127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(x.Close)
	status := x.Status(Settings{SocksEnabled: true, SocksListen: "127.0.0.1:0"})
	if !status.Listening || status.Listen == "" {
		t.Fatalf("SOCKS listener not ready: %+v", status)
	}
	return x, status.Listen
}

func socksNegotiate(t *testing.T, proxy, username, password string) (net.Conn, byte) {
	t.Helper()
	c, err := net.DialTimeout("tcp", proxy, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err = c.Write([]byte{socksVersion, 1, socksAuthUserPass}); err != nil {
		c.Close()
		t.Fatal(err)
	}
	var method [2]byte
	if _, err = io.ReadFull(c, method[:]); err != nil {
		c.Close()
		t.Fatal(err)
	}
	if method[0] != socksVersion || method[1] != socksAuthUserPass {
		c.Close()
		t.Fatalf("unexpected method reply: %v", method)
	}
	var auth bytes.Buffer
	auth.WriteByte(socksAuthVersion)
	auth.WriteByte(byte(len(username)))
	auth.WriteString(username)
	auth.WriteByte(byte(len(password)))
	auth.WriteString(password)
	if _, err = c.Write(auth.Bytes()); err != nil {
		c.Close()
		t.Fatal(err)
	}
	var reply [2]byte
	if _, err = io.ReadFull(c, reply[:]); err != nil {
		c.Close()
		t.Fatal(err)
	}
	return c, reply[1]
}

func socksConnect(t *testing.T, c net.Conn, host string, port uint16) byte {
	t.Helper()
	var request bytes.Buffer
	request.Write([]byte{socksVersion, socksCommandConnect, 0, socksAtypDomain, byte(len(host))})
	request.WriteString(host)
	_ = binary.Write(&request, binary.BigEndian, port)
	if _, err := c.Write(request.Bytes()); err != nil {
		t.Fatal(err)
	}
	var reply [10]byte
	if _, err := io.ReadFull(c, reply[:]); err != nil {
		t.Fatal(err)
	}
	if reply[0] != socksVersion || reply[3] != socksAtypIPv4 {
		t.Fatalf("unexpected SOCKS reply: %v", reply)
	}
	return reply[1]
}

func TestSocksEgressAuthenticationMeteringAndPolicy(t *testing.T) {
	s := testStore(t)
	a := account(t, s, 1<<20)
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	m := testManager(t, s, func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, echo.Addr().String())
	})
	x, proxy := testSocksProxy(t, m, s)
	username, password, _, err := s.SocksCredential(a.ID)
	if err != nil {
		t.Fatal(err)
	}

	bad, status := socksNegotiate(t, proxy, username, "definitely-the-wrong-password")
	if status != 1 {
		t.Fatal("wrong password accepted")
	}
	bad.Close()

	conn, status := socksNegotiate(t, proxy, username, password)
	if status != 0 {
		t.Fatal("valid SOCKS credential rejected")
	}
	defer conn.Close()
	if reply := socksConnect(t, conn, "example.org", 443); reply != socksSucceeded {
		t.Fatalf("CONNECT failed with reply %#x", reply)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	payload := []byte("socks payload through metered egress")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("SOCKS payload corrupted")
	}
	actual, err := s.Get(a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if actual.UploadBytes < int64(len(payload)) || actual.DownloadBytes < int64(len(payload)) {
		t.Fatalf("SOCKS traffic not metered: up=%d down=%d", actual.UploadBytes, actual.DownloadBytes)
	}

	denied, status := socksNegotiate(t, proxy, username, password)
	if status != 0 {
		t.Fatal("second authentication failed")
	}
	defer denied.Close()
	if reply := socksConnect(t, denied, "example.org", 22); reply != socksNotAllowed {
		t.Fatalf("port outside allowlist returned %#x", reply)
	}

	waitFor(t, func() bool { return x.Status(Settings{}).Active == 1 })
	if err := x.Apply(false, "127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("disabling the listener left a connection open")
	}
	if status := x.Status(Settings{}); status.Listening {
		t.Fatal("SOCKS listener still reports listening")
	}
}

func TestSocksRotationAndPerClientClose(t *testing.T) {
	s := testStore(t)
	a := account(t, s, 1<<20)
	m := testManager(t, s, func(context.Context, string, string) (net.Conn, error) {
		left, right := net.Pipe()
		go func() { io.Copy(io.Discard, right); right.Close() }()
		return left, nil
	})
	x, proxy := testSocksProxy(t, m, s)
	oldUser, oldPass, _, err := s.SocksCredential(a.ID)
	if err != nil {
		t.Fatal(err)
	}
	conn, status := socksNegotiate(t, proxy, oldUser, oldPass)
	if status != 0 {
		t.Fatal("initial credential rejected")
	}
	defer conn.Close()
	if reply := socksConnect(t, conn, "example.org", 443); reply != socksSucceeded {
		t.Fatalf("CONNECT failed with reply %#x", reply)
	}
	if _, err := s.RotateSocks(a.ID); err != nil {
		t.Fatal(err)
	}
	newUser, newPass, _, err := s.SocksCredential(a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if newUser != oldUser || newPass == oldPass {
		t.Fatal("SOCKS rotation did not change the password")
	}
	stale, status := socksNegotiate(t, proxy, oldUser, oldPass)
	if status == 0 {
		stale.Close()
		t.Fatal("rotated SOCKS password still accepted")
	}
	stale.Close()
	fresh, status := socksNegotiate(t, proxy, newUser, newPass)
	if status != 0 {
		t.Fatal("new SOCKS credential rejected")
	}
	fresh.Close()

	x.CloseClient(a.ID)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("CloseClient left the SOCKS connection open")
	}
}

func TestSocksAuthenticationThrottle(t *testing.T) {
	s := testStore(t)
	a := account(t, s, 0)
	m := testManager(t, s, nil)
	_, proxy := testSocksProxy(t, m, s)
	username, password, _, err := s.SocksCredential(a.ID)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < socksAuthFailures; i++ {
		c, status := socksNegotiate(t, proxy, username, "wrong-password-value")
		if status != 1 {
			t.Fatalf("attempt %d was not rejected", i)
		}
		c.Close()
	}
	blocked, status := socksNegotiate(t, proxy, username, password)
	if status != 1 {
		blocked.Close()
		t.Fatal("valid credential bypassed the authentication throttle")
	}
	blocked.Close()
}

func TestSocksListenerCanMoveHostOnSamePort(t *testing.T) {
	s := testStore(t)
	m := testManager(t, s, nil)
	x, proxy := testSocksProxy(t, m, s)
	_, port, err := net.SplitHostPort(proxy)
	if err != nil {
		t.Fatal(err)
	}
	if err := x.Apply(true, "0.0.0.0:"+port); err != nil {
		t.Fatal(err)
	}
	status := x.Status(Settings{SocksEnabled: true, SocksListen: "0.0.0.0:" + port})
	if !status.Listening {
		t.Fatalf("rebound listener is not listening: %+v", status)
	}
	c, err := net.DialTimeout("tcp", proxy, 2*time.Second)
	if err != nil {
		t.Fatalf("rebound listener is unreachable on the original address: %v", err)
	}
	c.Close()
	if !sameListenPort("127.0.0.1:1080", "0.0.0.0:1080") || sameListenPort("127.0.0.1:1080", "127.0.0.1:1081") {
		t.Fatal("sameListenPort comparison is wrong")
	}
}

func TestPipeSocksReleasesClientWhenUpstreamEnds(t *testing.T) {
	client, peer := net.Pipe()
	upstream, destination := net.Pipe()
	finished := make(chan struct{})
	go func() {
		pipeSocks(client, upstream)
		close(finished)
	}()
	_ = destination.Close()
	_ = peer.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := peer.Read(make([]byte, 1)); err == nil {
		t.Fatal("client side stayed open after the upstream ended")
	}
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("pipeSocks did not return after the upstream ended")
	}
	_ = peer.Close()
}

func TestSocksCredentialHTTP(t *testing.T) {
	b, s, _ := testBrowser(t)
	c := account(t, s, 0)
	b.login()
	raw := b.request("/api/clients/"+c.ID+"/socks", "GET", nil, 200)
	var cred struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.Unmarshal(raw, &cred); err != nil {
		t.Fatal(err)
	}
	username, password, _, err := s.SocksCredential(c.ID)
	if err != nil || cred.Username != username || cred.Password != password {
		t.Fatal("credential endpoint mismatch", err)
	}
	if strings.Contains(string(raw), "seed") {
		t.Fatal("credential endpoint exposed private key material")
	}
	rotated := b.request("/api/clients/"+c.ID+"/socks-rotate", "POST", nil, 200)
	var result struct {
		OK   bool   `json:"ok"`
		Epch uint64 `json:"socks_epoch"`
	}
	if err := json.Unmarshal(rotated, &result); err != nil || !result.OK || result.Epch != 1 {
		t.Fatalf("rotation response %s: %v", rotated, err)
	}
	served := b.request("/api/socks", "GET", nil, 200)
	if !strings.Contains(string(served), `"status"`) {
		t.Fatalf("status endpoint: %s", served)
	}
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met before deadline")
}
