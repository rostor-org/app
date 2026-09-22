GO ?= go
export PATH := /opt/homebrew/opt/postgresql@17/bin:/opt/homebrew/bin:$(PATH)

.PHONY: build test vet agent lint-strings

build:
	$(GO) build -o bin/rostor ./cmd/rostor

agent:
	GOOS=windows GOARCH=amd64 $(GO) build -o bin/rostor-agent.exe ./cmd/rostor-agent

vet:
	$(GO) vet ./...

test:
	ROSTOR_TEST_DATABASE_URL=$${ROSTOR_TEST_DATABASE_URL:-postgres:///rostor_test?sslmode=disable} $(GO) test ./...

# M0 string-catalog lint (first cut): every code the server can emit must be
# in the catalog. Grep for Err("x.y") and s.writeErr(..., "x.y") sites.
lint-strings:
	@missing=0; for code in $$(grep -rhoE 'Err\("[a-z_.]+"|writeErr\([^,]+, [^,]+, [0-9]+, "[a-z_.]+"|Code: "[a-z_.]+"' internal cmd/rostor | grep -oE '"[a-z_.]+"' | tr -d '"' | sort -u); do \
		grep -q "\"$$code\"" internal/catalog/en.json || { echo "missing from catalog: $$code"; missing=1; }; done; exit $$missing
