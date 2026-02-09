GOOS ?= $(go env GOOS)
GOARCH ?= $(go env GOARCH)
BUILDFLAGS ?=-ldflags "-X main.version=$(shell git describe --tags --always --dirty) -X main.buildDate=$(shell date +%Y-%m-%d)"

GO_OPTS?=CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS)
GO_TAGS?=
TEST_OPTS?=GOOS=$(GOOS) GOARCH=$(GOARCH)

default: build

clean:
	rm bin/*

build: sshoq sshoq-server

lint:
	go fmt ./...
	# FIXME: fix vet errors before turning this on
	# go vet ./...

test:
	$(TEST_OPTS) go test ./...
	$(TEST_OPTS) go run github.com/onsi/ginkgo/v2/ginkgo -r

integration-tests:
	CERT_PEM=$(CERT_PEM) \
		CERT_PRIV_KEY=$(CERT_PRIV_KEY) \
		ATTACKER_PRIVKEY=$(ATTACKER_PRIVKEY) \
		TESTUSER_PRIVKEY=$(TESTUSER_PRIVKEY) \
		TESTUSER_ED25519_PRIVKEY=$(TESTUSER_ED25519_PRIVKEY) \
		TESTUSER_ECDSA_PRIVKEY=$(TESTUSER_ECDSA_PRIVKEY) \
		TESTUSER_USERNAME=$(TESTUSER_USERNAME) \
		CC=$(CC) \
		CGO_ENABLED=1 \
		GOOS=$(GOOS) \
		SSH3_INTEGRATION_TESTS_WITH_SERVER_ENABLED=1 \
		go run github.com/onsi/ginkgo/v2/ginkgo ./integration_tests

install:
	$(GO_OPTS) go install $(BUILDFLAGS) ./cmd/sshoq
	$(GO_OPTS) go install $(BUILDFLAGS) ./cmd/sshoq-server
	echo You might want to copy sshoq-server into /usr/sbin/ if you are running it via systemd

sshoq: ./cmd/sshoq ./cmd/sshoq.go ./client/  message resources util internal auth cmd/plugin_endpoint
	$(GO_OPTS) go build -tags "$(GO_TAGS)" $(BUILD_FLAGS) -o bin/sshoq ./cmd/sshoq/

sshoq-server: ./cmd/sshoq-server ./cmd/sshoq-server.go message server_auth resources util internal auth cmd/plugin_endpoint 
	$(GO_OPTS) go build -tags "$(GO_TAGS)" $(BUILD_FLAGS) -o bin/sshoq-server ./cmd/sshoq-server/

