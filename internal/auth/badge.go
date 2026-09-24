package auth

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"

	"rostor.org/app/internal/crypto"
)

// BadgeMethod: an RFID/NFC card or fob (spec §7.2, first-class). A badge is
// possession only (AL1); with a PIN stored on the binding it is possession +
// knowledge (AL2). The same card can be observed in several forms by
// different readers, so a binding indexes every form it has been seen in
// and matches on any of them (see project memory "badge-login-plan").
type BadgeMethod struct {
	Provider crypto.Provider
}

type badgeMaterial struct {
	Forms   map[string]string `json:"forms"`              // kind → canonical value
	PINHash []byte            `json:"pin_hash,omitempty"` // provider password hash of the PIN
}

func (m *BadgeMethod) Describe() Description {
	return Description{Method: "badge", Properties: []string{"possession", "can-identify-user"}, Modes: []string{"inline"}, Assurance: "AL1"}
}

var (
	hexRe = regexp.MustCompile(`^[0-9a-f]{6,32}$`)
	decRe = regexp.MustCompile(`^[0-9]{1,20}$`)
)

// canonical forms from a presentation: uid (hex, lower, no separators),
// wiegand26 ("facility:card" decimal), printed (decimal). A bare "number"
// field is classified by shape: hex-looking → uid, decimal → printed.
func badgeForms(in StepInput) map[string]string {
	f := map[string]string{}
	norm := func(v string) string {
		return strings.ToLower(strings.NewReplacer(" ", "", ":", "", "-", "").Replace(strings.TrimSpace(v)))
	}
	if v := norm(in.Fields["uid"]); v != "" && hexRe.MatchString(v) {
		f["badge.uid"] = v
	}
	if v := strings.TrimSpace(in.Fields["printed"]); v != "" && decRe.MatchString(v) {
		f["badge.printed"] = strings.TrimLeft(v, "0")
	}
	if fc, cn := strings.TrimSpace(in.Fields["facility"]), strings.TrimSpace(in.Fields["card"]); fc != "" && cn != "" && decRe.MatchString(fc) && decRe.MatchString(cn) {
		f["badge.wiegand26"] = strings.TrimLeft(fc, "0") + ":" + strings.TrimLeft(cn, "0")
	}
	if v := strings.TrimSpace(in.Fields["number"]); v != "" {
		if decRe.MatchString(v) {
			n, err := strconv.ParseUint(v, 10, 64)
			if err == nil && n >= 1<<24 {
				// Too large for a printed number: a reader that types the
				// full UID in decimal. Keep it as the UID.
				if _, ok := f["badge.uid"]; !ok {
					f["badge.uid"] = strings.TrimLeft(strconv.FormatUint(n, 16), "0")
				}
			} else if _, ok := f["badge.printed"]; !ok {
				f["badge.printed"] = strings.TrimLeft(v, "0")
			}
		} else if h := norm(v); hexRe.MatchString(h) {
			if _, ok := f["badge.uid"]; !ok {
				f["badge.uid"] = h
			}
		}
	}
	// Some readers emit the UID with its bytes reversed. Index both orders
	// at enrollment so either kind of reader matches the same card.
	if uid, ok := f["badge.uid"]; ok && len(uid)%2 == 0 {
		rev := make([]byte, 0, len(uid))
		for i := len(uid) - 2; i >= 0; i -= 2 {
			rev = append(rev, uid[i], uid[i+1])
		}
		if r := strings.TrimLeft(string(rev), "0"); r != "" && r != uid {
			f["badge.uid_rev"] = r
		}
	}
	// Derivations that are deterministic for EM4100-style cards: the printed
	// number is the low 24 bits of the UID in decimal, and Wiegand-26 is
	// facility = bits 16..23, card = low 16 bits of that number.
	if uid, ok := f["badge.uid"]; ok && len(uid) >= 6 {
		if n, err := strconv.ParseUint(uid[len(uid)-6:], 16, 32); err == nil {
			if _, ok := f["badge.printed"]; !ok {
				f["badge.printed"] = strconv.FormatUint(n, 10)
			}
			if _, ok := f["badge.wiegand26"]; !ok {
				f["badge.wiegand26"] = strconv.FormatUint(n>>16, 10) + ":" + strconv.FormatUint(n&0xffff, 10)
			}
		}
	}
	if p, ok := f["badge.printed"]; ok {
		if n, err := strconv.ParseUint(p, 10, 64); err == nil && n < 1<<24 {
			if _, ok := f["badge.wiegand26"]; !ok {
				f["badge.wiegand26"] = strconv.FormatUint(n>>16, 10) + ":" + strconv.FormatUint(n&0xffff, 10)
			}
		}
	}
	return f
}

func (m *BadgeMethod) Enroll(ctx context.Context, in StepInput) ([]byte, []Identifier, error) {
	forms := badgeForms(in)
	if len(forms) == 0 {
		return nil, nil, errors.New("no card number")
	}
	mat := badgeMaterial{Forms: forms}
	if pin := strings.TrimSpace(in.Fields["pin"]); pin != "" {
		if len(pin) < 4 || !decRe.MatchString(pin) {
			return nil, nil, errors.New("pin must be at least 4 digits")
		}
		h, err := m.Provider.PasswordHash([]byte(pin))
		if err != nil {
			return nil, nil, err
		}
		mat.PINHash = h
	}
	raw, err := json.Marshal(mat)
	if err != nil {
		return nil, nil, err
	}
	var ids []Identifier
	for k, v := range forms {
		ids = append(ids, Identifier{Kind: k, Value: v})
	}
	return raw, ids, nil
}

func (m *BadgeMethod) Identify(in StepInput) []Identifier {
	var ids []Identifier
	for k, v := range badgeForms(in) {
		ids = append(ids, Identifier{Kind: k, Value: v})
	}
	return ids
}

func (m *BadgeMethod) Authenticate(ctx context.Context, bindingID string, sm SealedMaterial, in StepInput, _ map[string]any) (StepResult, error) {
	raw, err := sm.Read(ctx)
	if err != nil {
		return StepResult{}, err
	}
	var mat badgeMaterial
	if err := json.Unmarshal(raw, &mat); err != nil {
		return StepResult{Failed: true}, nil
	}
	// The presented card must match one of the stored forms; the core's
	// identifier lookup already guaranteed this, but the method re-checks so
	// it never trusts the caller's routing.
	presented := badgeForms(in)
	match := false
	for k, v := range presented {
		if mat.Forms[k] == v {
			match = true
			break
		}
		// A reversed-order reader presenting a card enrolled the other way.
		if k == "badge.uid" && mat.Forms["badge.uid_rev"] == v || k == "badge.uid_rev" && mat.Forms["badge.uid"] == v {
			match = true
			break
		}
	}
	if !match {
		return StepResult{Failed: true}, nil
	}
	props := []string{"possession", "can-identify-user"}
	assurance := "AL1"
	pin := strings.TrimSpace(in.Fields["pin"])
	if len(mat.PINHash) > 0 {
		if pin == "" {
			// Card matched but the binding wants a PIN: ask for it. Callers
			// that cannot prompt (a door) treat this as AL1 possession only
			// when their policy allows; the lock screen prompts.
			if in.Fields["allow_al1"] == "true" {
				return StepResult{Assertion: &Assertion{Method: "badge", BindingID: bindingID, At: time.Now().UTC(), Properties: props, Assurance: "AL1"}}, nil
			}
			return StepResult{Continue: map[string]any{"need": "pin"}}, nil
		}
		ok, err := m.Provider.PasswordVerify(mat.PINHash, []byte(pin))
		if err != nil {
			return StepResult{}, err
		}
		if !ok {
			return StepResult{Failed: true}, nil
		}
		props = append(props, "knowledge")
		assurance = "AL2"
	}
	return StepResult{Assertion: &Assertion{Method: "badge", BindingID: bindingID, At: time.Now().UTC(), Properties: props, Assurance: assurance}}, nil
}

// SetPIN returns the material with a new PIN hash (or none when pin is
// empty, which makes the badge possession-only again).
func (m *BadgeMethod) SetPIN(raw []byte, pin string) ([]byte, error) {
	var mat badgeMaterial
	if err := json.Unmarshal(raw, &mat); err != nil {
		return nil, err
	}
	pin = strings.TrimSpace(pin)
	if pin == "" {
		mat.PINHash = nil
	} else {
		if len(pin) < 4 || !decRe.MatchString(pin) {
			return nil, errors.New("pin must be at least 4 digits")
		}
		h, err := m.Provider.PasswordHash([]byte(pin))
		if err != nil {
			return nil, err
		}
		mat.PINHash = h
	}
	return json.Marshal(mat)
}
