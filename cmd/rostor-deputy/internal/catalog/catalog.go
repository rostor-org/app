// Package catalog is the deputy's bundled string catalog for deputy-local codes
// and the credential provider's UI labels (contract §2). Core renders text for
// its own codes; this catalog only covers what the deputy produces on its own
// (for example when core is unreachable). Nothing in the deputy formats
// sentences in code: every visible word is looked up here by code.
package catalog

import (
	"embed"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
)

//go:embed locales/*.json
var files embed.FS

// DefaultLocale is used when the requested locale has no bundle.
const DefaultLocale = "en-US"

type bundle struct {
	UI       map[string]string `json:"ui"`
	Messages map[string]string `json:"messages"`
}

var (
	once    sync.Once
	bundles map[string]bundle
	loadErr error
)

func load() {
	bundles = map[string]bundle{}
	entries, err := files.ReadDir("locales")
	if err != nil {
		loadErr = err
		return
	}
	for _, e := range entries {
		b, err := files.ReadFile("locales/" + e.Name())
		if err != nil {
			loadErr = err
			return
		}
		var bd bundle
		if err := json.Unmarshal(b, &bd); err != nil {
			loadErr = fmt.Errorf("catalog %s: %w", e.Name(), err)
			return
		}
		bundles[strings.TrimSuffix(e.Name(), ".json")] = bd
	}
}

// Resolve picks the best bundle for a BCP-47 tag: exact match, then language
// prefix, then DefaultLocale.
func resolve(locale string) (bundle, error) {
	once.Do(load)
	if loadErr != nil {
		return bundle{}, loadErr
	}
	if b, ok := bundles[locale]; ok {
		return b, nil
	}
	lang, _, _ := strings.Cut(locale, "-")
	for name, b := range bundles {
		if l, _, _ := strings.Cut(name, "-"); strings.EqualFold(l, lang) {
			return b, nil
		}
	}
	return bundles[DefaultLocale], nil
}

// UI returns the credential-provider labels for locale. Keys mirror the
// contract §2.1 reply so callers can copy them straight into the wire type.
func UI(locale string) (map[string]string, error) {
	b, err := resolve(locale)
	if err != nil {
		return nil, err
	}
	return b.UI, nil
}

// Message renders an deputy-local code. Unknown codes return the code itself:
// showing a stable identifier is better than inventing English, and the code
// is still traceable back to the catalog gap.
func Message(locale, code string) string {
	b, err := resolve(locale)
	if err != nil {
		return code
	}
	if m, ok := b.Messages[code]; ok {
		return m
	}
	return code
}
