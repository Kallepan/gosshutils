package main

import (
	"flag"
	"log/slog"
	"os"
	"path"

	"github.com/kallepan/sshutils"
)

func handler(conn *sshutils.Conn) {
	defer conn.Close()
}

func main() {
	// Parse the command line arguments
	configFile := flag.String("config", "", "Path to the configuration file")
	dataDir := flag.String("data_dir", path.Join(path.Dir(*configFile), "data"), "Path to the data directory")
	flag.Parse()

	// load configFile
	configString := ""
	if *configFile != "" {
		configBytes, err := os.ReadFile(*configFile)
		if err != nil {
			slog.Error("Failed to read the configuration file", "error", err)
			panic(err)
		}
		configString = string(configBytes)
	}
	// Load the configuration
	cfg := &sshutils.Config{}
	if err := cfg.Load(configString, *dataDir); err != nil {
		slog.Error("Failed to load the configuration", "error", err)
		panic(err)
	}

	// Start the SSH server
	listener, err := sshutils.Listen("127.0.0.1:2222", cfg.SSHConfig)
	if err != nil {
		slog.Error("Failed to start the SSH server", "error", err)
		panic(err)
	}
	defer listener.Close()

	// Accept incoming connections
	for {
		conn, err := listener.Accept()
		if err != nil {
			slog.Warn("Failed to accept the incoming connection", "error", err)
			continue
		}
		go handler(conn)
	}
}
