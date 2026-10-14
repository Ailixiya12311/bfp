package session

import (
	"bfp/security"
	"context"
	"net"
	"testing"
)

func TestCredentialsRejectBadKeypairsAndAuthorizationBeforeListening(t *testing.T) {
	srv, client := newSecurityTestServer(t)
	serverCred := copyCredentials(srv.cfg.Credentials)
	badClient := copyCredentials(client)
	badClient.Public[0] ^= 1
	if _, e := NewClient(ClientConfig{Credentials: badClient}); e == nil {
		t.Fatal("inconsistent client keypair accepted")
	}
	badClient = copyCredentials(client)
	badClient.ServerPublic = make([]byte, 32)
	if _, e := NewClient(ClientConfig{Credentials: badClient}); e == nil {
		t.Fatal("low-order pinned server key accepted")
	}
	for _, authorized := range [][][]byte{nil, {make([]byte, 31)}, {make([]byte, 32)}, {client.Public, client.Public}} {
		badServer := copyCredentials(serverCred)
		badServer.AllowedClients = authorized
		if _, e := NewServer(ServerConfig{Listen: "invalid", Credentials: badServer, Backend: &net.Dialer{}}); e == nil || e.Error() != "session: invalid authorized device list" && e.Error() != "session: invalid authorized device key" {
			t.Fatal("invalid authorization was not rejected before listening")
		}
	}
}

func TestConstructorsCopyCredentialBuffers(t *testing.T) {
	srv, cred := newSecurityTestServer(t)
	cc := copyCredentials(cred)
	c, e := NewClient(ClientConfig{Credentials: cc})
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	cc.Admission[0] ^= 1
	cc.Private[0] ^= 1
	cc.ServerPublic[0] ^= 1
	if _, e := security.NewIKHandshake(true, keyPair(c.cfg.Credentials), c.cfg.Credentials.ServerPublic, nil); e != nil {
		t.Fatal("caller changed constructor-owned keypair")
	}
	if !equalSecret(c.cfg.Credentials.Admission, cred.Admission) || !equalSecret(c.cfg.Credentials.ServerPublic, cred.ServerPublic) {
		t.Fatal("client still aliases caller credential buffers")
	}
	sc := copyCredentials(srv.cfg.Credentials)
	other, e := NewServer(ServerConfig{Listen: "127.0.0.1:0", Credentials: sc, Backend: &net.Dialer{}})
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	sc.AllowedClients[0][0] ^= 1
	if !equalSecret(other.cfg.Credentials.AllowedClients[0], cred.Public) {
		t.Fatal("server still aliases caller authorized device key")
	}
	// Closed clients refuse a later connect without network side effects.
	c.Close()
	if _, e := c.Connect(context.Background()); e != ErrClosed {
		t.Fatal("closed client allowed reconnect")
	}
}
