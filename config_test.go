package sshutils

import (
	"errors"
	"fmt"
	"os"
	"path"
	"reflect"
	"testing"

	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v2"
)

type mockFile struct {
	closed bool
}

func (file *mockFile) Write(p []byte) (n int, err error) {
	return 0, errors.New("")
}

func (file *mockFile) Close() error {
	if file.closed {
		return errors.New("")
	}
	file.closed = true
	return nil
}

func verifyConfig(t *testing.T, cfg *Config, expected *Config) {
	if !reflect.DeepEqual(cfg.Server, expected.Server) {
		t.Errorf("Server=%v, want %v", cfg.Server, expected.Server)
	}
	if !reflect.DeepEqual(cfg.Logging, expected.Logging) {
		t.Errorf("Logging=%v, want %v", cfg.Logging, expected.Logging)
	}
	if !reflect.DeepEqual(cfg.Auth, expected.Auth) {
		t.Errorf("Auth=%v, want %v", cfg.Auth, expected.Auth)
	}
	if !reflect.DeepEqual(cfg.SSHProto, expected.SSHProto) {
		t.Errorf("SSHProto=%v, want %v", cfg.SSHProto, expected.SSHProto)
	}

	if cfg.SSHConfig.RekeyThreshold != expected.SSHProto.RekeyThreshold {
		t.Errorf("sshConfig.RekeyThreshold=%v, want %v", cfg.SSHConfig.RekeyThreshold, expected.SSHProto.RekeyThreshold)
	}
	if !reflect.DeepEqual(cfg.SSHConfig.KeyExchanges, expected.SSHProto.KeyExchanges) {
		t.Errorf("sshConfig.KeyExchanges=%v, want %v", cfg.SSHConfig.KeyExchanges, expected.SSHProto.KeyExchanges)
	}
	if !reflect.DeepEqual(cfg.SSHConfig.Ciphers, expected.SSHProto.Ciphers) {
		t.Errorf("sshConfig.Ciphers=%v, want %v", cfg.SSHConfig.Ciphers, expected.SSHProto.Ciphers)
	}
	if !reflect.DeepEqual(cfg.SSHConfig.MACs, expected.SSHProto.MACs) {
		t.Errorf("sshConfig.MACs=%v, want %v", cfg.SSHConfig.MACs, expected.SSHProto.MACs)
	}
	if cfg.SSHConfig.NoClientAuth != expected.Auth.NoAuth {
		t.Errorf("sshConfig.NoClientAuth=%v, want %v", cfg.SSHConfig.NoClientAuth, expected.Auth.NoAuth)
	}
	if cfg.SSHConfig.MaxAuthTries != expected.Auth.MaxTries {
		t.Errorf("sshConfig.MaxAuthTries=%v, want %v", cfg.SSHConfig.MaxAuthTries, expected.Auth.MaxTries)
	}
	if (cfg.SSHConfig.PasswordCallback != nil) != expected.Auth.PasswordAuth.Enabled {
		t.Errorf("sshConfig.PasswordCallback=%v, want %v", cfg.SSHConfig.PasswordCallback != nil, expected.Auth.PasswordAuth.Enabled)
	}
	if (cfg.SSHConfig.PublicKeyCallback != nil) != expected.Auth.PublicKeyAuth.Enabled {
		t.Errorf("sshConfig.PasswordCallback=%v, want %v", cfg.SSHConfig.PublicKeyCallback != nil, expected.Auth.PublicKeyAuth.Enabled)
	}
	if (cfg.SSHConfig.KeyboardInteractiveCallback != nil) != expected.Auth.KeyboardInteractiveAuth.Enabled {
		t.Errorf("sshConfig.KeyboardInteractiveCallback=%v, want %v", cfg.SSHConfig.KeyboardInteractiveCallback != nil, expected.Auth.KeyboardInteractiveAuth.Enabled)
	}
	if cfg.SSHConfig.AuthLogCallback == nil {
		t.Errorf("sshConfig.AuthLogCallback=nil, want a callback")
	}
	if cfg.SSHConfig.ServerVersion != expected.SSHProto.Version {
		t.Errorf("sshConfig.ServerVersion=%v, want %v", cfg.SSHConfig.ServerVersion, expected.SSHProto.Version)
	}
	if (cfg.SSHConfig.BannerCallback != nil) != (expected.SSHProto.Banner != "") {
		t.Errorf("sshConfig.BannerCallback=%v, want %v", cfg.SSHConfig.BannerCallback != nil, expected.SSHProto.Banner != "")
	}
	if cfg.SSHConfig.GSSAPIWithMICConfig != nil {
		t.Errorf("sshConfig.GSSAPIWithMICConfig=%v, want nil", cfg.SSHConfig.GSSAPIWithMICConfig)
	}
	if len(cfg.parsedHostKeys) != len(expected.Server.HostKeys) {
		t.Errorf("len(parsedHostKeys)=%v, want %v", len(cfg.parsedHostKeys), len(expected.Server.HostKeys))
	}

	if expected.Logging.File == "" {
		if cfg.logFileHandle != nil {
			t.Errorf("logFileHandle=%v, want nil", cfg.logFileHandle)
		}
	} else {
		if cfg.logFileHandle == nil {
			t.Errorf("logFileHandle=nil, want a file")
		}
	}
}

func verifyDefaultKeys(t *testing.T, dataDir string) {
	files, err := os.ReadDir(dataDir)
	if err != nil {
		t.Fatalf("Faield to list directory: %v", err)
	}
	expectedKeys := map[string]string{
		"host_rsa_key":     "ssh-rsa",
		"host_ecdsa_key":   "ecdsa-sha2-nistp256",
		"host_ed25519_key": "ssh-ed25519",
	}
	keys := map[string]string{}
	for _, file := range files {
		keyBytes, err := os.ReadFile(path.Join(dataDir, file.Name()))
		if err != nil {
			t.Fatalf("Failed to read key: %v", err)
		}
		signer, err := ssh.ParsePrivateKey(keyBytes)
		if err != nil {
			t.Fatalf("Failed to parse private key: %v", err)
		}
		keys[file.Name()] = signer.PublicKey().Type()
	}
	if !reflect.DeepEqual(keys, expectedKeys) {
		t.Errorf("keys=%v, want %v", keys, expectedKeys)
	}
}

func TestDefaultConfig(t *testing.T) {
	dataDir := t.TempDir()
	cfg := &Config{}
	err := cfg.Load("", dataDir)
	if err != nil {
		t.Fatalf("Failed to get config: %v", err)
	}
	expectedConfig := &Config{}
	expectedConfig.Server.ListenAddress = "127.0.0.1:2222"
	expectedConfig.Server.HostKeys = []string{
		path.Join(dataDir, "host_rsa_key"),
		path.Join(dataDir, "host_ecdsa_key"),
		path.Join(dataDir, "host_ed25519_key"),
	}

	expectedConfig.Auth.PasswordAuth.Enabled = true
	expectedConfig.Auth.PublicKeyAuth.Enabled = true
	expectedConfig.SSHProto.Version = "SSH-2.0-sshesame"
	expectedConfig.SSHProto.Banner = "This is an SSH honeypot. Everything is logged and monitored."
	verifyConfig(t, cfg, expectedConfig)
	verifyDefaultKeys(t, dataDir)
}

func TestUserConfigDefaultKeys(t *testing.T) {
	logFile := path.Join(t.TempDir(), "test.log")
	cfgString := fmt.Sprintf(`
server:
  listen_address: 0.0.0.0:22
logging:
  file: %v
auth:
  max_tries: 234
  no_auth: true
  password_auth:
    enabled: false
  public_key_auth:
    enabled: false
  keyboard_interactive_auth:
    enabled: true
    instruction: instruction
    questions:
    - text: q1
      echo: true
    - text: q2
      echo: false
ssh_proto:
  version: SSH-2.0-test
  banner:
  rekey_threshold: 123
  key_exchanges: [kex]
  ciphers: [cipher]
  macs: [mac]
`, logFile)
	dataDir := t.TempDir()
	writeTestKeys(t, dataDir)
	cfg := &Config{}
	err := cfg.Load(cfgString, dataDir)
	if err != nil {
		t.Fatalf("Failed to get config: %v", err)
	}
	if cfg.logFileHandle != nil {
		cfg.logFileHandle.Close()
	}
	expectedConfig := &Config{}
	expectedConfig.Server.ListenAddress = "0.0.0.0:22"
	expectedConfig.Server.HostKeys = []string{
		path.Join(dataDir, "host_rsa_key"),
		path.Join(dataDir, "host_ecdsa_key"),
		path.Join(dataDir, "host_ed25519_key"),
	}
	expectedConfig.Logging.File = logFile
	expectedConfig.Auth.MaxTries = 234
	expectedConfig.Auth.NoAuth = true
	expectedConfig.Auth.KeyboardInteractiveAuth.Enabled = true
	expectedConfig.Auth.KeyboardInteractiveAuth.Instruction = "instruction"
	expectedConfig.Auth.KeyboardInteractiveAuth.Questions = []keyboardInteractiveAuthQuestion{
		{"q1", true},
		{"q2", false},
	}
	expectedConfig.SSHProto.Version = "SSH-2.0-test"
	expectedConfig.SSHProto.Banner = "Default banner"
	expectedConfig.SSHProto.RekeyThreshold = 123
	expectedConfig.SSHProto.KeyExchanges = []string{"kex"}
	expectedConfig.SSHProto.Ciphers = []string{"cipher"}
	expectedConfig.SSHProto.MACs = []string{"mac"}
	verifyConfig(t, cfg, expectedConfig)
	verifyDefaultKeys(t, dataDir)
}

func TestUserConfigCustomKeysAndServices(t *testing.T) {
	keyFile, err := generateKey(t.TempDir(), ecdsa_key)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	dataDir := t.TempDir()
	cfgString := fmt.Sprintf(`
server:
  host_keys: [%v]
`, keyFile)
	cfg := &Config{}
	err = cfg.Load(cfgString, dataDir)
	if err != nil {
		t.Fatalf("Failed to get config: %v", err)
	}
	expectedConfig := &Config{}
	expectedConfig.Server.ListenAddress = "127.0.0.1:2222"
	expectedConfig.Server.HostKeys = []string{keyFile}

	expectedConfig.Auth.PasswordAuth.Enabled = true
	expectedConfig.Auth.PublicKeyAuth.Enabled = true
	expectedConfig.SSHProto.Version = "SSH-2.0-sshesame"
	expectedConfig.SSHProto.Banner = "This is an SSH honeypot. Everything is logged and monitored."
	verifyConfig(t, cfg, expectedConfig)
	files, err := os.ReadDir(dataDir)
	if err != nil {
		t.Fatalf("Failed to read directory: %v", err)
	}
	if len(files) != 0 {
		t.Errorf("files=%v, want []", files)
	}
}

func TestSetupLoggingOldHandleClosed(t *testing.T) {
	file := &mockFile{}
	cfg := &Config{logFileHandle: file}
	if err := cfg.setupLogging(); err != nil {
		t.Fatalf("Failed to set up logging: %v", err)
	}
	if !file.closed {
		t.Errorf("file.closed=false, want true")
	}
}

func TestExistingKey(t *testing.T) {
	dataDir := path.Join(t.TempDir(), "keys")
	oldKeyFile, err := generateKey(dataDir, ed25519_key)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	oldKey, err := os.ReadFile(oldKeyFile)
	if err != nil {
		t.Fatalf("Failed to read key: %v", err)
	}
	newKeyFile, err := generateKey(dataDir, ed25519_key)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	newKey, err := os.ReadFile(newKeyFile)
	if err != nil {
		t.Fatalf("Failed to read key: %v", err)
	}
	if !reflect.DeepEqual(oldKey, newKey) {
		t.Errorf("oldKey!=newKey")
	}
}

func TestDefaultConfigFile(t *testing.T) {
	configBytes, err := os.ReadFile("config.yaml")
	if err != nil {
		t.Fatalf("Failed to read config file: %v", err)
	}
	cfg := &Config{}
	if err := yaml.UnmarshalStrict(configBytes, cfg); err != nil {
		t.Fatalf("Failed to unmarshal config: %v", err)
	}
	dataDir := t.TempDir()
	writeTestKeys(t, dataDir)
	if err := cfg.setDefaultHostKeys(dataDir, []keySignature{rsa_key, ecdsa_key, ed25519_key}); err != nil {
		t.Fatalf("Failed to set default host keys: %v", err)
	}
	if err := cfg.setupSSHConfig(); err != nil {
		t.Fatalf("Failed to setup SSH config: %v", err)
	}

	// The sample config has example keyboard interactive auth options set.
	// Since the auth method itself is disabled, this doesn't make a difference.
	// Unset them so they don't affect the comparison.
	cfg.Auth.KeyboardInteractiveAuth.Instruction = ""
	cfg.Auth.KeyboardInteractiveAuth.Questions = nil

	writeTestKeys(t, dataDir)
	defaultCfg := &Config{}
	err = defaultCfg.Load("", dataDir)
	if err != nil {
		t.Fatalf("Failed to get default config: %v", err)
	}
	verifyConfig(t, cfg, defaultCfg)
}

func TestUnspecifiedHostKeys(t *testing.T) {
	cfgString := `
server:
  host_keys: null
`
	dataDir := t.TempDir()
	writeTestKeys(t, dataDir)
	cfg := &Config{}
	if err := cfg.Load(cfgString, dataDir); err != nil {
		t.Fatalf("Failed to get config: %v", err)
	}
	if len(cfg.parsedHostKeys) != 3 {
		t.Errorf("len(cfg.parsedHostKeys)=%d, want 3", len(cfg.parsedHostKeys))
	}
}

func TestEmptyHostKeys(t *testing.T) {
	cfgString := `
server:
  host_keys: []
`
	dataDir := t.TempDir()
	writeTestKeys(t, dataDir)
	cfg := &Config{}
	if err := cfg.Load(cfgString, dataDir); err != nil {
		t.Fatalf("Failed to get config: %v", err)
	}
	if len(cfg.parsedHostKeys) != 3 {
		t.Errorf("len(cfg.parsedHostKeys)=%d, want 3", len(cfg.parsedHostKeys))
	}
}
