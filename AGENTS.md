# Agent Guidelines for sshoq

This document provides essential information for agentic coding agents operating in the `sshoq` repository.

## 🛠 Build and Development

The project uses a `Makefile` for common tasks.

- **Build all binaries**: `make build` (outputs to `bin/`)
- **Build client only**: `make client`
- **Build server only**: `make server`
- **Lint**: `make lint` (currently runs `go fmt`)
- **Install binaries**: `make install` (installs `sshoq` and `sshoq-server` to `$GOPATH/bin`)

## 🧪 Testing

The project uses both standard Go tests and the [Ginkgo](https://onsi.github.io/ginkgo/) testing framework.

- **Run all tests**: `make test`
- **Run integration tests**: `make integration-tests` (requires specific environment variables, see `Makefile`)
- **Run a single package test**: `go test ./path/to/package`
- **Run a single Ginkgo spec**: `go run github.com/onsi/ginkgo/v2/ginkgo --focus "pattern" ./path/to/package`
- **Verbose output**: Add `-v` to `go test` or `-v` to `ginkgo`.

## 📏 Code Style & Conventions

### 1. Language & Version
- **Go 1.21+**
- Follow standard Go idioms as defined in "Effective Go".

### 2. Formatting & Imports
- Always run `go fmt ./...` after modifications.
- Group imports into three sections:
    1. Standard library
    2. Third-party libraries (e.g., `github.com/quic-go/quic-go`)
    3. Internal project packages (`github.com/h4sh5/sshoq/...`)

### 3. Naming Conventions
- **Exported Symbols**: `PascalCase`
- **Unexported Symbols**: `camelCase`
- **Constants**: `SCREAMING_SNAKE_CASE` is frequently used for protocol constants (e.g., `SSH_FRAME_TYPE`).
- **Receiver Names**: Short and consistent (e.g., `func (s *Server) ...`).

### 4. Error Handling
- Use the standard `if err != nil` pattern.
- Wrap errors with context when returning: `fmt.Errorf("context: %w", err)`.
- Use `errors.Is` and `errors.As` for error checking.

### 5. Logging
- Use `github.com/rs/zerolog/log` for logging.
- Prefer structured logging: `log.Info().Str("key", value).Msg("message")`.
- Avoid `fmt.Printf` for persistent logging.

### 6. Concurrency
- Use `context.Context` for cancellation and timeouts.
- Be mindful of race conditions; use `sync.Mutex` or `sync.RWMutex` as seen in `server.go`.

### 7. Protocol Logic
- Core SSH3 logic involves QUIC and HTTP/3 (via `quic-go`).
- Many protocol structures use `VarInt` for length-prefixing; see `util/varint.go`.

## 📂 Directory Structure
- `cmd/`: CLI entry points.
- `internal/`: Private library code.
- `auth/`: Authentication plugins (OIDC, Pubkey).
- `message/`: Protocol message definitions and parsing.
- `integration_tests/`: End-to-end testing logic.

## 🤖 Agent-Specific Instructions
- When adding new features, check `Makefile` to see if new dependencies or build steps are needed.
- If modifying the protocol, ensure `message/message_test.go` is updated and passing.
- Do not introduce new logging libraries; stick to `zerolog`.
