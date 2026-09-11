package vpn

import (
	"crypto/tls"
	"net"
	"testing"
	"time"
)

func TestSniffSNI_ExtractsHostnameAndPeekedBytes(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	t.Cleanup(func() {
		_ = clientSide.Close()
		_ = serverSide.Close()
	})

	go func() {
		c := tls.Client(clientSide, &tls.Config{ServerName: "example.com", InsecureSkipVerify: true})
		_ = c.Handshake() // never completes (nothing answers); irrelevant to this test
	}()

	hostname, peeked, err := sniffSNI(serverSide)
	if err != nil {
		t.Fatalf("sniffSNI: %v", err)
	}
	if hostname != "example.com" {
		t.Errorf("hostname = %q, want example.com", hostname)
	}
	if len(peeked) == 0 {
		t.Error("expected non-empty peeked ClientHello bytes to replay")
	}
}

func TestSniffSNI_NonTLSInputErrors(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	t.Cleanup(func() {
		_ = clientSide.Close()
		_ = serverSide.Close()
	})

	go func() {
		_, _ = clientSide.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	}()

	_, _, err := sniffSNI(serverSide)
	if err == nil {
		t.Error("expected an error sniffing SNI from plain-HTTP input, got nil")
	}
}

// fakeConn is a minimal net.Conn over an in-memory pipe half, used so the
// forward test can assert on read/write without a real socket.
func TestRelay_UnmatchedForwardsToFallback(t *testing.T) {
	fallbackLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer fallbackLn.Close()

	fallbackReceived := make(chan []byte, 1)
	go func() {
		c, err := fallbackLn.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 4096)
		n, _ := c.Read(buf)
		got := make([]byte, n)
		copy(got, buf[:n])
		fallbackReceived <- got
		_, _ = c.Write([]byte("fallback-ack"))
	}()

	mgr := &Manager{}
	mgr.snap.Store(&snapshot{}) // no routes configured -> MatchProxyRoute always false
	r := &Relay{mgr: mgr, fallback: fallbackLn.Addr().String()}

	driverConn, relayInboundConn := net.Pipe()
	defer driverConn.Close()

	go r.forward(relayInboundConn, []byte("peeked-clienthello"), r.fallback)

	select {
	case got := <-fallbackReceived:
		if string(got) != "peeked-clienthello" {
			t.Errorf("fallback received %q, want %q", got, "peeked-clienthello")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("fallback never received the peeked bytes")
	}

	buf := make([]byte, 64)
	_ = driverConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := driverConn.Read(buf)
	if err != nil {
		t.Fatalf("reading fallback's reply back through the relay: %v", err)
	}
	if got := string(buf[:n]); got != "fallback-ack" {
		t.Errorf("relayed reply = %q, want %q", got, "fallback-ack")
	}
}
