GO ?= go
IMAGE ?= docker.home.arpa:5000/aivan-authz:latest

.PHONY: build build-gate build-admin test testdb lint image

# build produces both binaries for local use. Only the gate is ever put in an
# image; the admin binary is an operator tool and stays on the workstation
# (doc/schema-handover.md §4).
build: build-gate build-admin

build-gate:   ; $(GO) build -trimpath -o bin/authz ./cmd/authz-gate
build-admin:  ; $(GO) build -trimpath -o bin/authz-admin ./cmd/authz-admin

test:    ; $(GO) test ./...
testdb:  ; AIVAN_TEST_SUPERUSER_URL=$${AIVAN_TEST_SUPERUSER_URL:-postgres://postgres@localhost/postgres} \
           AIVAN_TEST_DB_URL=$${AIVAN_TEST_DB_URL:-postgres://aivan_authz@localhost/aivan_authz_test} \
           $(GO) test -tags integration ./...
lint:    ; $(GO) vet ./... && test -z "$$(gofmt -l .)"
image:   ; docker build -f deploy/Dockerfile -t $(IMAGE) .
