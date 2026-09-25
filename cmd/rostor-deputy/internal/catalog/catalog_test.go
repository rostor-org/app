package catalog

import "testing"

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
