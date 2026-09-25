GO ?= go
export PATH := /opt/homebrew/opt/postgresql@17/bin:/opt/homebrew/bin:$(PATH)

.PHONY: build test vet deputy lint-strings lint-ui-strings console

# Build the React console and stage it for embedding.
console:
	cd console && npm ci --silent && npm run build --silent
	rm -rf internal/console/dist && cp -R console/dist internal/console/dist && touch internal/console/dist/.gitkeep

build:
	$(GO) build -o bin/rostor ./cmd/rostor

deputy:
	GOOS=windows GOARCH=amd64 $(GO) build -o bin/rostor-deputy.exe ./cmd/rostor-deputy

vet:
	$(GO) vet ./...

test:
	ROSTOR_TEST_DATABASE_URL=$${ROSTOR_TEST_DATABASE_URL:-postgres:///rostor_test?sslmode=disable} $(GO) test ./...

# M0 string-catalog lint (first cut): every code the server can emit must be
# in the catalog. Grep for Err("x.y") and s.writeErr(..., "x.y") sites.
lint-strings:
	@missing=0; for code in $$(grep -rhoE 'Err\("[a-z_.]+"|writeErr\([^,]+, [^,]+, [0-9]+, "[a-z_.]+"|Code: "[a-z_.]+"' internal cmd/rostor | grep -oE '"[a-z_.]+"' | tr -d '"' | sort -u); do \
		grep -q "\"$$code\"" internal/catalog/en.json || { echo "missing from catalog: $$code"; missing=1; }; done; exit $$missing

# ---- Releases -------------------------------------------------------------
# make dist VERSION=v0.1.0            build signed-release artifacts into dist/
# make release VERSION=v0.1.0 [NOTES="..."]
#   creates the GitHub release, uploads the binaries, signs a manifest whose
#   file URLs are the GitHub asset API URLs (work for private and public
#   repos), uploads the manifest, and updates deploy/channels/stable.json.
#   The Windows install bundle (rostor-windows-amd64.zip) is built and
#   attached to the same release by the CI `windows-bundle` job on the tag
#   push; it is never part of dist/ or the manifest (the updater is for the
#   core only).
REPO      ?= rostor-org/app
CHANNEL   ?= stable
SIGNKEY   ?= $(HOME)/.rostor/release-signing.key
LDFLAGS    = -s -w -X main.version=$(VERSION)

.PHONY: dist release
# Every console string must exist in the server catalog the appliance serves,
# or the screen shows raw codes after an update (v0.6.0 shipped that way).
# Same check as CI, run before any release build.
lint-ui-strings:
	@python3 -c "import json,sys; s=json.load(open('internal/catalog/en.json')); u=json.load(open('console/catalog.en.json')); m=[k for k in u if k not in s]; print('missing from internal/catalog/en.json:', *m, sep='\n  ') if m else print('ok:', len(u), 'console codes present in the server catalog'); sys.exit(1 if m else 0)"

dist: console lint-ui-strings
	@test -n "$(VERSION)" || { echo "VERSION=vX.Y.Z is required"; exit 1; }
	rm -rf dist && mkdir -p dist
	GOOS=linux  GOARCH=amd64 CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o dist/rostor-linux-amd64 ./cmd/rostor
	GOOS=linux  GOARCH=arm64 CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o dist/rostor-linux-arm64 ./cmd/rostor
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o dist/rostor-deputy-windows-amd64.exe ./cmd/rostor-deputy
	$(GO) build -o bin/rostor-release ./cmd/rostor-release
	@ls -la dist

release: dist
	git pull --rebase --quiet
	gh release create $(VERSION) --repo $(REPO) --title "Rostor $(VERSION)" --notes "$(NOTES)" dist/rostor-linux-amd64 dist/rostor-linux-arm64 dist/rostor-deputy-windows-amd64.exe
	rm -f dist/*.zip
	URLMAP="$$(gh api repos/$(REPO)/releases/tags/$(VERSION) --jq '[.assets[] | "\(.name)=\(.url)"] | join(",")')"; \
	  bin/rostor-release manifest --key $(SIGNKEY) --channel $(CHANNEL) --version $(VERSION) --dir dist --url-map "$$URLMAP" --notes "$(NOTES)" $(if $(MIN_UPGRADE_FROM),--min-upgrade-from $(MIN_UPGRADE_FROM),) > dist/manifest-$(CHANNEL).json
	gh release upload $(VERSION) --repo $(REPO) --clobber dist/manifest-$(CHANNEL).json
	cp dist/manifest-$(CHANNEL).json deploy/channels/$(CHANNEL).json
	git add deploy/channels/$(CHANNEL).json && git commit -q -m "Release $(VERSION) to $(CHANNEL)" && git push
	@echo "released $(VERSION) to channel $(CHANNEL)"
	@echo "the Windows install bundle (rostor-windows-amd64.zip) is built by CI and attached to the $(VERSION) release by the windows-bundle job:"
	@echo "  gh run list --repo $(REPO) --workflow CI --branch $(VERSION)"
