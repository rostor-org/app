// Package catalog is the single string catalog (spec principle 10, §9). Code
// never contains user-facing sentences; it emits stable codes with parameters
// and callers ask the catalog to render them for a locale.
package catalog

import (
	"embed"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
)

//go:embed *.json
var files embed.FS

type Catalog struct {
	mu      sync.RWMutex
	locales map[string]map[string]string
}

func Load() (*Catalog, error) {
	c := &Catalog{locales: map[string]map[string]string{}}
	entries, err := files.ReadDir(".")
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		name := strings.TrimSuffix(e.Name(), ".json")
		raw, err := files.ReadFile(e.Name())
		if err != nil {
			return nil, err
		}
		m := map[string]string{}
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil, fmt.Errorf("catalog %s: %w", e.Name(), err)
		}
		c.locales[name] = m
	}
	if _, ok := c.locales["en"]; !ok {
		return nil, fmt.Errorf("catalog: en fallback missing")
	}
	return c, nil
}

// Render returns the template for code in the best-matching locale with
// {param} placeholders substituted. Unknown codes render as the code itself so
// a missing string is visible, never silent.
func (c *Catalog) Render(locale, code string, params map[string]any) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	tmpl, ok := c.lookup(locale, code)
	if !ok {
		return code
	}
	for k, v := range params {
		tmpl = strings.ReplaceAll(tmpl, "{"+k+"}", fmt.Sprint(v))
	}
	return tmpl
}

func (c *Catalog) lookup(locale, code string) (string, bool) {
	// "en-US" → "en-US", then "en", then fallback "en".
	for _, l := range []string{locale, strings.SplitN(locale, "-", 2)[0], "en"} {
		if m, ok := c.locales[l]; ok {
			if s, ok := m[code]; ok {
				return s, true
			}
		}
	}
	return "", false
}

// Has reports whether a code exists in the fallback locale; used by tests to
// keep every emitted code renderable.
func (c *Catalog) Has(code string) bool {
	_, ok := c.locales["en"][code]
	return ok
}
