package sshutils

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"path"

	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v2"
)

type serverConfig struct {
	ListenAddress string   `yaml:"listen_address"`
	HostKeys      []string `yaml:"host_keys"`
}

type loggingConfig struct {
	File string `yaml:"file"`
}

type commonAuthConfig struct {
	Enabled bool `yaml:"enabled"`
}

type keyboardInteractiveAuthQuestion struct {
	Text string `yaml:"text"`
	Echo bool   `yaml:"echo"`
}

type keyboardInteractiveAuthConfig struct {
	commonAuthConfig `yaml:",inline"`
	Instruction      string                            `yaml:"instruction"`
	Questions        []keyboardInteractiveAuthQuestion `yaml:"questions"`
}

type authConfig struct {
	MaxTries                int                           `yaml:"max_tries"`
	NoAuth                  bool                          `yaml:"no_auth"`
	PasswordAuth            commonAuthConfig              `yaml:"password_auth"`
	PublicKeyAuth           commonAuthConfig              `yaml:"public_key_auth"`
	KeyboardInteractiveAuth keyboardInteractiveAuthConfig `yaml:"keyboard_interactive_auth"`
}

type sshProtoConfig struct {
	Version        string   `yaml:"version"`
	Banner         string   `yaml:"banner"`
	RekeyThreshold uint64   `yaml:"rekey_threshold"`
	KeyExchanges   []string `yaml:"key_exchanges"`
	Ciphers        []string `yaml:"ciphers"`
	MACs           []string `yaml:"macs"`
}

type Config struct {
	Server   serverConfig   `yaml:"server"`
	Logging  loggingConfig  `yaml:"logging"`
	Auth     authConfig     `yaml:"auth"`
	SSHProto sshProtoConfig `yaml:"ssh_proto"`

	parsedHostKeys []ssh.Signer
	SSHConfig      *ssh.ServerConfig
	logFileHandle  io.WriteCloser
}

func (cfg *Config) setDefaults() {
	cfg.Server.ListenAddress = "127.0.0.1:2222"
	cfg.Auth.PasswordAuth.Enabled = true
	cfg.Auth.PublicKeyAuth.Enabled = true
	cfg.SSHProto.Version = "SSH-2.0-sshesame"
	cfg.SSHProto.Banner = "This is an SSH honeypot. Everything is logged and monitored."
}

type keySignature int

const (
	rsa_key keySignature = iota
	ecdsa_key
	ed25519_key
)

func (signature keySignature) String() string {
	switch signature {
	case rsa_key:
		return "rsa"
	case ecdsa_key:
		return "ecdsa"
	case ed25519_key:
		return "ed25519"
	default:
		return "unknown"
	}
}

func generateKey(dataDir string, signature keySignature) (string, error) {
	keyFile := path.Join(dataDir, fmt.Sprintf("host_%v_key", signature))
	if _, err := os.Stat(keyFile); err == nil {
		return keyFile, nil
	} else if !os.IsNotExist(err) {
		return "", err
	}
	slog.Info(fmt.Sprintf("Host key %q not found, generating it", keyFile))
	if _, err := os.Stat(path.Dir(keyFile)); os.IsNotExist(err) {
		if err := os.MkdirAll(path.Dir(keyFile), 0755); err != nil {
			return "", err
		}
	}
	var key interface{}
	err := errors.New("unsupported key type")
	switch signature {
	case rsa_key:
		key, err = rsa.GenerateKey(rand.Reader, 3072)
	case ecdsa_key:
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case ed25519_key:
		_, key, err = ed25519.GenerateKey(rand.Reader)
	}
	if err != nil {
		return "", err
	}
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}), 0600); err != nil {
		return "", err
	}
	return keyFile, nil
}

func loadKey(keyFile string) (ssh.Signer, error) {
	keyBytes, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(keyBytes)
}

func (cfg *Config) setDefaultHostKeys(dataDir string, signatures []keySignature) error {
	for _, signature := range signatures {
		keyFile, err := generateKey(dataDir, signature)
		if err != nil {
			return err
		}
		cfg.Server.HostKeys = append(cfg.Server.HostKeys, keyFile)
	}
	return nil
}

func (cfg *Config) parseHostKeys() error {
	for _, keyFile := range cfg.Server.HostKeys {
		signer, err := loadKey(keyFile)
		if err != nil {
			return err
		}
		cfg.parsedHostKeys = append(cfg.parsedHostKeys, signer)
	}
	return nil
}

// sets up the SSH configuration.
func (cfg *Config) setupSSHConfig() error {
	sshConfig := &ssh.ServerConfig{
		Config: ssh.Config{
			RekeyThreshold: cfg.SSHProto.RekeyThreshold,
			KeyExchanges:   cfg.SSHProto.KeyExchanges,
			Ciphers:        cfg.SSHProto.Ciphers,
			MACs:           cfg.SSHProto.MACs,
		},
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if !cfg.Auth.PasswordAuth.Enabled {
				return nil, errors.New("password authentication is disabled")
			}

			return nil, errors.New("password authentication is not implemented")
		},
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if !cfg.Auth.PublicKeyAuth.Enabled {
				return nil, errors.New("public key authentication is disabled")
			}

			return nil, errors.New("public key authentication is not implemented")
		},
		KeyboardInteractiveCallback: func(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			if !cfg.Auth.KeyboardInteractiveAuth.Enabled {
				return nil, errors.New("keyboard interactive authentication is disabled")
			}

			return nil, errors.New("keyboard interactive authentication is not implemented")
		},
		NoClientAuth:  cfg.Auth.NoAuth,
		MaxAuthTries:  cfg.Auth.MaxTries,
		ServerVersion: cfg.SSHProto.Version,
	}
	if err := cfg.parseHostKeys(); err != nil {
		return err
	}
	for _, key := range cfg.parsedHostKeys {
		sshConfig.AddHostKey(key)
	}
	cfg.SSHConfig = sshConfig
	return nil
}

// sets up the logging configuration.
func (cfg *Config) setupLogging() error {
	var logFile io.WriteCloser
	if cfg.Logging.File != "" {
		var err error
		logFile, err = os.OpenFile(cfg.Logging.File, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
	}
	if logFile == nil {
		log.SetOutput(os.Stdout)
	} else {
		log.SetOutput(logFile)
	}
	if cfg.logFileHandle != nil {
		cfg.logFileHandle.Close()
	}
	cfg.logFileHandle = logFile

	return nil
}

// loads the configuration from the given string.
func (cfg *Config) Load(configString string, dataDir string) error {
	*cfg = Config{}

	cfg.setDefaults()

	if err := yaml.UnmarshalStrict([]byte(configString), cfg); err != nil {
		return err
	}

	if len(cfg.Server.HostKeys) == 0 {
		slog.Info(fmt.Sprintf("No host keys configured, using keys at %q", dataDir))
		if err := cfg.setDefaultHostKeys(dataDir, []keySignature{rsa_key, ecdsa_key, ed25519_key}); err != nil {
			return err
		}
	}

	if err := cfg.setupSSHConfig(); err != nil {
		return err
	}
	if err := cfg.setupLogging(); err != nil {
		return err
	}

	return nil
}
