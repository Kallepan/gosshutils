# Go SSH Utils

This project is a small wrapper around the [Go SSH package](https://godoc.org/golang.org/x/crypto/ssh), providing a simplified interface for establishing and managing SSH connections.

## Features

- Establish SSH connections with error handling.
- Send and receive requests over SSH.
- Open and manage channels within an SSH connection.
- Unmarshal payloads from SSH requests.
- Handle global and channel-specific SSH requests.


## Dependencies

- [Go SSH package](https://godoc.org/golang.org/x/crypto/ssh)

## Usage

Use [this](cmd/main.go) code to create an SSH server.
