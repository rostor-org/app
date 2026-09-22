package catalog

import "testing"

func TestUIHasAllContractKeys(t *testing.T) {
	ui, err := UI("en-US")
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"tile_label", "username_label", "password_label", "submit_label", "connecting"} {
		if ui[k] == "" {
			t.Errorf("missing ui key %q", k)
		}
	}
}

func TestMessageLookup(t *testing.T) {
	if got := Message("en-US", "agent.core_unreachable"); got == "" || got == "agent.core_unreachable" {
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
