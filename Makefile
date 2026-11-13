GO ?= go
IMAGE ?= docker.home.arpa:5000/aivan-authz:latest

.PHONY: build test testdb lint image
build:   ; $(GO) build -trimpath -o bin/authz ./cmd/authz
test:    ; $(GO) test ./...
testdb:  ; AIVAN_TEST_DB_URL=$${AIVAN_TEST_DB_URL:-postgres://aivan_authz@localhost/aivan_authz_test} $(GO) test -tags integration ./...
lint:    ; $(GO) vet ./... && test -z "$$(gofmt -l .)"
image:   ; docker build -f deploy/Dockerfile -t $(IMAGE) .