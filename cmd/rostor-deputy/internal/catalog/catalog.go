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
// Entries may carry {name} placeholders (today only {tenant}); Fill renders
// them. The heading entries come in pairs — "heading" / "heading_no_tenant",
// "heading_badge" / "heading_badge_no_tenant" — so a tenant without a name
// gets a sentence that still reads well instead of a dangling "Sign in to".
func UI(locale string) (map[string]string, error) {
	b, err := resolve(locale)
	if err != nil {
		return nil, err
	}
	return b.UI, nil
}

// Fill substitutes {name} placeholders in a catalog entry with params.
// Unknown placeholders are left as written so a catalog gap stays visible
// rather than silently vanishing; no wording lives in code.
func Fill(s string, params map[string]string) string {
	if len(params) == 0 || !strings.Contains(s, "{") {
		return s
	}
	var sb strings.Builder
	for {
		open := strings.IndexByte(s, '{')
		if open < 0 {
			break
		}
		close := strings.IndexByte(s[open:], '}')
		if close < 0 {
			break
		}
		name := s[open+1 : open+close]
		v, ok := params[name]
		if !ok {
			sb.WriteString(s[:open+close+1])
		} else {
			sb.WriteString(s[:open])
			sb.WriteString(v)
		}
		s = s[open+close+1:]
	}
	sb.WriteString(s)
	return sb.String()
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
