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
	// Format is the tenant's badge number format (auth policy `badge.format`):
	// "none" keeps every form a card is seen in; "wiegand26" reduces every
	// presentation to facility:card so any reader matches any other and the
	// card is saved as Wiegand. Nil means "none".
	Format func(ctx context.Context) string
}

// BadgeFormats are the accepted values of the badge.format policy.
var BadgeFormats = []string{"none", "wiegand26"}

func (m *BadgeMethod) format(ctx context.Context) string {
	if m.Format == nil {
		return "none"
	}
	if f := m.Format(ctx); f == "wiegand26" {
		return f
	}
	return "none"
}

// wiegand26Of reduces a 24-bit (or longer) value to "facility:card".
func wiegand26Of(n uint64) string {
	n &= 0xffffff
	return strconv.FormatUint(n>>16, 10) + ":" + strconv.FormatUint(n&0xffff, 10)
}

// reduceToWiegand keeps only the Wiegand-26 reading of every form seen, so a
// full-UID reader, a printed-number reader and a Wiegand reader all name the
// same card. Enrolment stores that one reading. A presentation also carries
// the reading of the byte-reversed UID (wiegand26_rev), so a reversed reader
// matches a card enrolled the other way round without a phantom identifier
// ever being stored.
func reduceToWiegand(f map[string]string, presenting bool) map[string]string {
	out := map[string]string{}
	if v, ok := f["badge.wiegand26"]; ok {
		out["badge.wiegand26"] = v
	}
	if uid, ok := f["badge.uid_rev"]; ok && presenting && len(uid) >= 6 {
		if n, err := strconv.ParseUint(uid[len(uid)-6:], 16, 32); err == nil {
			if w := wiegand26Of(n); w != out["badge.wiegand26"] {
				out["badge.wiegand26_rev"] = w
			}
		}
	}
	return out
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
func badgeForms(in StepInput, format string, presenting bool) map[string]string {
	if format == "wiegand26" {
		// Readers set to Wiegand output type the pair run together, eight
		// digits: three of facility, five of card ("02622915" = 26:22915).
		// A ten-digit reading is the padded 24-bit value instead, which the
		// generic path handles. Eight digits is taken as the pair; at
		// presentation the plain-number reading is tried as well.
		if v := strings.TrimSpace(in.Fields["number"]); len(v) == 8 && decRe.MatchString(v) {
			fc, _ := strconv.ParseUint(v[:3], 10, 32)
			cn, _ := strconv.ParseUint(v[3:], 10, 32)
			if fc <= 255 && cn <= 65535 {
				out := map[string]string{"badge.wiegand26": strconv.FormatUint(fc, 10) + ":" + strconv.FormatUint(cn, 10)}
				if n, err := strconv.ParseUint(v, 10, 64); presenting && err == nil {
					if w := wiegand26Of(n); w != out["badge.wiegand26"] {
						out["badge.wiegand26_alt"] = w
					}
				}
				return out
			}
		}
		return reduceToWiegand(rawBadgeForms(in), presenting)
	}
	return rawBadgeForms(in)
}

func rawBadgeForms(in StepInput) map[string]string {
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
		// "74:8062", "74,8062" or "74-8062": a Wiegand reader that keeps the split.
		if parts := strings.FieldsFunc(v, func(r rune) bool { return r == ':' || r == ',' || r == '-' || r == ' ' }); len(parts) == 2 && decRe.MatchString(parts[0]) && decRe.MatchString(parts[1]) {
			if _, ok := f["badge.wiegand26"]; !ok {
				f["badge.wiegand26"] = strings.TrimLeft(parts[0], "0") + ":" + strings.TrimLeft(parts[1], "0")
			}
		} else if decRe.MatchString(v) {
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
	forms := badgeForms(in, m.format(ctx), false)
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
	for k, v := range badgeForms(in, m.format(context.Background()), true) {
		// Alternate readings (reversed bytes, plain-number) are looked up under the kind that is stored.
		if strings.HasPrefix(k, "badge.wiegand26_") {
			k = "badge.wiegand26"
		}
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
	presented := badgeForms(in, m.format(ctx), true)
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
		if strings.HasPrefix(k, "badge.wiegand26") && mat.Forms["badge.wiegand26"] == v {
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
