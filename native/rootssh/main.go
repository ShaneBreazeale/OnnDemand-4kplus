// rootssh provides an SSH shell using the credentials of the process starting it.
// It never changes Android accounts, boot images, startup services, or SELinux.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
	ssh "github.com/gliderlabs/ssh"
	"golang.org/x/crypto/scrypt"
	gossh "golang.org/x/crypto/ssh"
)

type config struct {
	Auth string   `json:"auth"`
	Keys []string `json:"keys"`
	Salt string   `json:"password_salt"`
	Hash string   `json:"password_hash"`
}

type credentials struct {
	config
	keys       []gossh.PublicKey
	salt, hash []byte
}

func parseConfig(raw []byte) (*credentials, error) {
	c := &credentials{}
	if err := json.Unmarshal(raw, &c.config); err != nil {
		return nil, err
	}
	if c.Auth != "key" && c.Auth != "password" && c.Auth != "both" {
		return nil, errors.New("auth must be key, password, or both (key OR password)")
	}
	for _, line := range c.Keys {
		key, _, options, rest, err := gossh.ParseAuthorizedKey([]byte(line))
		if err != nil || len(options) != 0 || len(rest) != 0 {
			return nil, errors.New("invalid public key or unsupported key options")
		}
		c.keys = append(c.keys, key)
	}
	if c.Auth != "password" && len(c.keys) == 0 {
		return nil, errors.New("public key required")
	}
	if c.Auth == "password" && len(c.keys) != 0 {
		return nil, errors.New("password-only mode must not contain keys")
	}
	if c.Auth != "key" {
		var err error
		c.salt, err = hex.DecodeString(c.Salt)
		if err != nil || len(c.salt) != 16 {
			return nil, errors.New("invalid password salt")
		}
		c.hash, err = hex.DecodeString(c.Hash)
		if err != nil || len(c.hash) != 32 {
			return nil, errors.New("invalid password verifier")
		}
	} else if c.Salt != "" || c.Hash != "" {
		return nil, errors.New("key-only mode must not contain a password")
	}
	return c, nil
}

func (c *credentials) password(user, password string) bool {
	if user != "root" || c.Auth == "key" || password == "" || len(password) > 1024 {
		return false
	}
	value, err := scrypt.Key([]byte(password), c.salt, 32768, 8, 1, 32)
	return err == nil && subtle.ConstantTimeCompare(value, c.hash) == 1
}

func (c *credentials) publicKey(user string, key ssh.PublicKey) bool {
	if user != "root" || c.Auth == "password" {
		return false
	}
	for _, allowed := range c.keys {
		if ssh.KeysEqual(key, allowed) {
			return true
		}
	}
	return false
}

func hostKey(path string) (gossh.Signer, error) {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		_, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		der, err := x509.MarshalPKCS8PrivateKey(private)
		if err != nil {
			return nil, err
		}
		raw = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return nil, err
		}
		_, writeErr := file.Write(raw)
		closeErr := file.Close()
		if writeErr != nil {
			return nil, writeErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
	} else if err != nil {
		return nil, err
	}
	return gossh.ParsePrivateKey(raw)
}

func shellHandler(shell, home string) ssh.Handler {
	return func(s ssh.Session) {
		args := []string{"-i"}
		if s.RawCommand() != "" {
			args = []string{"-c", s.RawCommand()}
		}
		cmd := exec.CommandContext(s.Context(), shell, args...)
		cmd.Dir = home
		cmd.Env = append(os.Environ(), "HOME="+home, "USER=root", "LOGNAME=root", "SHELL="+shell)
		term, windows, hasPty := s.Pty()
		var err error
		if hasPty {
			cmd.Env = append(cmd.Env, "TERM="+term.Term)
			terminal, startErr := pty.StartWithSize(cmd, &pty.Winsize{Rows: uint16(term.Window.Height), Cols: uint16(term.Window.Width)})
			if startErr != nil {
				fmt.Fprintln(s.Stderr(), "could not open terminal:", startErr)
				s.Exit(1)
				return
			}
			defer terminal.Close()
			done := make(chan struct{})
			resized := make(chan struct{})
			go func() {
				defer close(resized)
				for {
					select {
					case w, ok := <-windows:
						if !ok {
							return
						}
						pty.Setsize(terminal, &pty.Winsize{Rows: uint16(w.Height), Cols: uint16(w.Width)})
					case <-done:
						return
					}
				}
			}()
			go io.Copy(terminal, s)
			io.Copy(s, terminal)
			err = cmd.Wait()
			close(done)
			<-resized // Stop ioctl/Fd access before closing the terminal.
		} else {
			cmd.Stdin, cmd.Stdout, cmd.Stderr = s, s, s.Stderr()
			err = cmd.Run()
		}
		code := 0
		if err != nil {
			code = 1
			var exit *exec.ExitError
			if errors.As(err, &exit) && exit.ExitCode() >= 0 {
				code = exit.ExitCode()
			}
		}
		s.Exit(code)
	}
}

func server(c *credentials, signer gossh.Signer, shell, home string) *ssh.Server {
	// Both handlers are always set. gliderlabs defaults to unauthenticated access
	// when all auth handlers are nil, so disabled methods explicitly reject.
	srv := &ssh.Server{
		Handler:              shellHandler(shell, home),
		PasswordHandler:      func(ctx ssh.Context, password string) bool { return c.password(ctx.User(), password) },
		PublicKeyHandler:     func(ctx ssh.Context, key ssh.PublicKey) bool { return c.publicKey(ctx.User(), key) },
		IdleTimeout:          15 * time.Minute,
		ServerConfigCallback: func(ctx ssh.Context) *gossh.ServerConfig { return &gossh.ServerConfig{MaxAuthTries: 3} },
	}
	// Bound expensive password verification across all connections.
	var auth sync.Mutex
	original := srv.PasswordHandler
	srv.PasswordHandler = func(ctx ssh.Context, password string) bool {
		auth.Lock()
		defer auth.Unlock()
		return original(ctx, password)
	}
	srv.AddHostKey(signer)
	return srv
}

func run() error {
	configuration := flag.String("config", "", "authentication JSON file")
	listen := flag.String("listen", "127.0.0.1:2222", "SSH listen address")
	key := flag.String("host-key", "", "persistent device host key file")
	shell := flag.String("shell", "/system/bin/sh", "session shell")
	pid := flag.String("pid-file", "", "PID file, created exclusively")
	check := flag.Bool("check-config", false, "validate authentication and exit")
	flag.Parse()
	raw, err := os.ReadFile(*configuration)
	if err != nil {
		return err
	}
	c, err := parseConfig(raw)
	if err != nil {
		return err
	}
	if *check {
		return nil
	}
	if os.Geteuid() != 0 {
		return errors.New("rootssh must be launched through the temporary-root loop")
	}
	if *key == "" || *pid == "" {
		return errors.New("host-key and pid-file are required")
	}
	signer, err := hostKey(*key)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	file, err := os.OpenFile(*pid, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer os.Remove(*pid)
	if _, err = fmt.Fprintf(file, "%d\n", os.Getpid()); err != nil {
		file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	fmt.Printf("rootssh listening=%s host_key=%s home=%s\n", listener.Addr(), gossh.FingerprintSHA256(signer.PublicKey()), filepath.Dir(*configuration))
	srv := server(c, signer, *shell, filepath.Dir(*configuration))
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(signals)
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-signals:
			srv.Close()
		case <-done:
		}
	}()
	err = srv.Serve(listener)
	if errors.Is(err, ssh.ErrServerClosed) {
		return nil
	}
	return err
}

func main() {
	if err := run(); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}
