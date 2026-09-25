package catalog

import (
	"strings"
	"testing"
)

func TestUIHasAllContractKeys(t *testing.T) {
	ui, err := UI("en-US")
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"tile_label", "username_label", "password_label", "submit_label", "connecting", "pin_label", "badge_hint"} {
		if ui[k] == "" {
			t.Errorf("missing ui key %q", k)
		}
	}
}

func TestUIHasBadgeFirstKeys(t *testing.T) {
	// The badge-first strings (§2.1 "ui and the default method") are their
	// own keys so the broker swaps labels without inventing text.
	ui, err := UI("en-US")
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"tile_label_badge", "username_label_badge", "badge_hint"} {
		if ui[k] == "" {
			t.Errorf("missing ui key %q", k)
		}
	}
	if ui["tile_label_badge"] == ui["tile_label"] || ui["username_label_badge"] == ui["username_label"] {
		t.Fatalf("badge-first strings must differ from the password ones: %+v", ui)
	}
}

func TestMessageLookup(t *testing.T) {
	if got := Message("en-US", "deputy.core_unreachable"); got == "" || got == "deputy.core_unreachable" {
		t.Fatalf("expected rendered text, got %q", got)
	}
	if got := Message("en-US", "no.such.code"); got != "no.such.code" {
		t.Fatalf("unknown code should echo itself, got %q", got)
	}
}

func TestLocaleFallback(t *testing.T) {
	for _, loc := range []string{"en", "en-GB", "fr-FR", ""} {
		ui, err := UI(loc)
		if err != nil {
			t.Fatal(err)
		}
		if ui["tile_label"] == "" {
			t.Errorf("locale %q did not fall back", loc)
		}
	}
}

func TestUIHasHeadingAndSwitchKeys(t *testing.T) {
	// v0.13.0: the heading carries the organisation name through a {tenant}
	// placeholder, with a no-tenant twin so an unnamed tenant never sees
	// "Sign in to " with nothing after it; the two command-link texts are
	// plain entries.
	ui, err := UI("en-US")
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"heading", "heading_badge", "heading_no_tenant", "heading_badge_no_tenant", "switch_to_username", "switch_to_badge"} {
		if ui[k] == "" {
			t.Errorf("missing ui key %q", k)
		}
	}
	for _, k := range []string{"heading", "heading_badge"} {
		if !strings.Contains(ui[k], "{tenant}") {
			t.Errorf("%s must carry the {tenant} placeholder, got %q", k, ui[k])
		}
	}
	for _, k := range []string{"heading_no_tenant", "heading_badge_no_tenant", "switch_to_username", "switch_to_badge"} {
		if strings.Contains(ui[k], "{") {
			t.Errorf("%s must not carry a placeholder, got %q", k, ui[k])
		}
	}
	if ui["switch_to_username"] == ui["switch_to_badge"] {
		t.Fatalf("the two link texts must differ: %+v", ui)
	}
}

func TestFill(t *testing.T) {
	ui, err := UI("en-US")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct{ in, tenant, want string }{
		{ui["heading"], "ChattLab", "Sign in to ChattLab"},
		{ui["heading_badge"], "ChattLab", "Tap your badge · ChattLab"},
		{ui["heading_no_tenant"], "", "Sign in"},
		{"{tenant}{tenant}", "x", "xx"},
		{"no placeholders", "x", "no placeholders"},
		{"{unknown} stays", "x", "{unknown} stays"},
		{"{unterminated", "x", "{unterminated"},
		{"a {tenant} b", "", "a  b"},
	}
	for _, c := range cases {
		if got := Fill(c.in, map[string]string{"tenant": c.tenant}); got != c.want {
			t.Errorf("Fill(%q, %q) = %q, want %q", c.in, c.tenant, got, c.want)
		}
	}
	if got := Fill("{tenant}", nil); got != "{tenant}" {
		t.Errorf("nil params: %q", got)
	}
}
