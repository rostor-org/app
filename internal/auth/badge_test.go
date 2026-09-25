package auth

import "testing"

// Every reader names the same card once badge.format is wiegand26: a full
// UID (hex or decimal), the printed 24-bit number, a split facility:card,
// and a byte-reversed UID all reduce to the same facility:card.
func TestBadgeFormsWiegand(t *testing.T) {
	cases := []map[string]string{
		{"uid": "0A00 4A 1F 7E"},
		{"number": "0a004a1f7e"},
		{"number": "42954530686"}, // 0x0a004a1f7e in decimal: a reader typing the UID as a number
		{"number": "4857726"},     // low 24 bits in decimal, what a printed-number reader types
		{"number": "74:8062"},
		{"number": "74,8062"},
		{"facility": "074", "card": "08062"},
	}
	for _, c := range cases {
		// Enrolment stores exactly one reading.
		if f := badgeForms(StepInput{Fields: c}, "wiegand26", false); f["badge.wiegand26"] != "74:8062" || len(f) != 1 {
			t.Errorf("enrol %v → %v, want only 74:8062", c, f)
		}
		if f := badgeForms(StepInput{Fields: c}, "wiegand26", true); f["badge.wiegand26"] != "74:8062" {
			t.Errorf("present %v → %v, want 74:8062", c, f)
		}
	}
	// A byte-reversed reader presenting the card: the reversed reading is offered as the alternate.
	f := badgeForms(StepInput{Fields: map[string]string{"uid": "7e1f4a000a"}}, "wiegand26", true)
	if f["badge.wiegand26_rev"] != "74:8062" {
		t.Errorf("reversed uid → %v, want wiegand26_rev 74:8062", f)
	}
	// Enrolling from that reader stores only its own reading, never the phantom.
	if f := badgeForms(StepInput{Fields: map[string]string{"uid": "7e1f4a000a"}}, "wiegand26", false); len(f) != 1 {
		t.Errorf("enrol reversed uid → %v, want one form", f)
	}
	// With the format off, every form is kept, as before.
	all := badgeForms(StepInput{Fields: map[string]string{"uid": "0a004a1f7e"}}, "none", false)
	for _, k := range []string{"badge.uid", "badge.uid_rev", "badge.printed", "badge.wiegand26"} {
		if all[k] == "" {
			t.Errorf("format none should keep %s: %v", k, all)
		}
	}
}
