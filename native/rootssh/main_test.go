package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/scrypt"
	gossh "golang.org/x/crypto/ssh"
)

func signer(t *testing.T) gossh.Signer {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	result, err := gossh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestAuthenticationAndCommands(t *testing.T) {
	key, wrongKey := signer(t), signer(t)
	salt := []byte("0123456789abcdef")
	hash, err := scrypt.Key([]byte("test-password"), salt, 32768, 8, 1, 32)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"key", "password", "both"} {
		t.Run(mode, func(t *testing.T) {
			cfg := config{Auth: mode}
			if mode != "password" {
				cfg.Keys = []string{string(gossh.MarshalAuthorizedKey(key.PublicKey()))}
			}
			if mode != "key" {
				cfg.Salt, cfg.Hash = hex.EncodeToString(salt), hex.EncodeToString(hash)
			}
			raw, _ := json.Marshal(cfg)
			c, err := parseConfig(raw)
			if err != nil {
				t.Fatal(err)
			}
			srv := server(c, signer(t), "/bin/sh", t.TempDir())
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			defer srv.Close()
			go srv.Serve(listener)
			cases := []struct {
				name, user string
				auth       []gossh.AuthMethod
				accept     bool
			}{
				{"key", "root", []gossh.AuthMethod{gossh.PublicKeys(key)}, mode != "password"},
				{"password", "root", []gossh.AuthMethod{gossh.Password("test-password")}, mode != "key"},
				{"wrong password", "root", []gossh.AuthMethod{gossh.Password("wrong")}, false},
				{"empty password", "root", []gossh.AuthMethod{gossh.Password("")}, false},
				{"wrong key", "root", []gossh.AuthMethod{gossh.PublicKeys(wrongKey)}, false},
				{"wrong user", "shell", []gossh.AuthMethod{gossh.PublicKeys(key), gossh.Password("test-password")}, false},
				{"no auth", "root", nil, false},
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					// Test-only host verification: no device credentials are involved.
					client, err := gossh.Dial("tcp", listener.Addr().String(), &gossh.ClientConfig{
						User: tc.user, Auth: tc.auth, HostKeyCallback: gossh.InsecureIgnoreHostKey(), Timeout: 3 * time.Second,
					})
					if !tc.accept {
						if err == nil {
							client.Close()
							t.Fatal("unauthorized login accepted")
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					defer client.Close()
					session, err := client.NewSession()
					if err != nil {
						t.Fatal(err)
					}
					output, err := session.Output("printf '\\000\\377payload'; exit 7")
					exit, ok := err.(*gossh.ExitError)
					if !ok || exit.ExitStatus() != 7 || string(output) != "\x00\xffpayload" {
						t.Fatalf("output=%q err=%v", output, err)
					}
					session.Close()
					session, err = client.NewSession()
					if err != nil {
						t.Fatal(err)
					}
					defer session.Close()
					if err = session.RequestPty("xterm", 24, 80, gossh.TerminalModes{}); err != nil {
						t.Fatal(err)
					}
					output, err = session.Output("printf terminal")
					if err != nil || string(output) != "terminal" {
						t.Fatalf("PTY output=%q err=%v", output, err)
					}
				})
			}
		})
	}
}

func TestInvalidAuthenticationFailsClosed(t *testing.T) {
	for _, raw := range []string{`{}`, `{"auth":"none"}`, `{"auth":"key"}`, `{"auth":"both"}`,
		`{"auth":"password"}`, `{"auth":"key","keys":["garbage"]}`} {
		if _, err := parseConfig([]byte(raw)); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
}

func TestHostKeyPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "host-key")
	first, err := hostKey(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := hostKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(first.PublicKey().Marshal()) != string(second.PublicKey().Marshal()) {
		t.Fatal("host identity changed")
	}
}
