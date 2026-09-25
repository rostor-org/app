package trust

import (
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"time"

	"rostor.org/app/cmd/rostor-deputy/internal/enroll"
)

// Report is what `rostor-deputy trust` prints.
type Report struct {
	TrustVersion string
	CAs          []*x509.Certificate
	Device       *x509.Certificate
	DeviceIssuer *x509.Certificate // nil when no pinned CA signed the device certificate
	Staged       bool
	Errors       []string
}

// Inspect reads the files without touching core. Missing or unreadable
// files are reported, not fatal, so an operator sees whatever is there.
func Inspect(f Files) *Report {
	r := &Report{}
	if cfg, err := enroll.LoadConfig(f.DeputyJSON); err != nil {
		r.Errors = append(r.Errors, "deputy.json: "+err.Error())
	} else {
		r.TrustVersion = cfg.TrustVersion
	}
	if cas, err := LoadBundle(f); err != nil {
		r.Errors = append(r.Errors, "ca.crt: "+err.Error())
	} else {
		r.CAs = cas
	}
	if leaf, err := LoadLeaf(f); err != nil {
		r.Errors = append(r.Errors, "device.crt: "+err.Error())
	} else {
		r.Device = leaf
		r.DeviceIssuer = Issuer(leaf, r.CAs)
	}
	if _, err := os.Stat(f.DeviceCert + ".new"); err == nil {
		r.Staged = true
	}
	return r
}

// Write prints the report in a fixed, greppable layout.
func (r *Report) Write(w io.Writer, now time.Time) {
	v := r.TrustVersion
	if v == "" {
		v = "(none yet)"
	}
	fmt.Fprintf(w, "trust version:  %s\n", v)
	fmt.Fprintf(w, "pinned CAs:     %d\n", len(r.CAs))
	for i, ca := range r.CAs {
		fp := Fingerprint(ca)
		tag := ""
		if i == 0 {
			tag = "  (newest)"
		}
		fmt.Fprintf(w, "  %s  %s  expires %s%s\n", fp[:16], ca.Subject.CommonName, ca.NotAfter.UTC().Format("2006-01-02"), tag)
		fmt.Fprintf(w, "    sha256 %s\n", fp)
	}
	if r.Device != nil {
		d := r.Device
		fmt.Fprintf(w, "device cert:    %s (serial %s)\n", d.Subject.CommonName, d.SerialNumber)
		fmt.Fprintf(w, "  issuer:       %s", d.Issuer.CommonName)
		switch {
		case r.DeviceIssuer == nil:
			fmt.Fprint(w, "  [NOT in pinned bundle]")
		case len(r.CAs) > 0 && Fingerprint(r.DeviceIssuer) != Fingerprint(r.CAs[0]):
			fmt.Fprintf(w, "  [%s, not the newest CA]", Fingerprint(r.DeviceIssuer)[:16])
		default:
			fmt.Fprintf(w, "  [%s]", Fingerprint(r.DeviceIssuer)[:16])
		}
		fmt.Fprintln(w)
		fmt.Fprintf(w, "  expires:      %s (%s)\n", d.NotAfter.UTC().Format(time.RFC3339), remaining(d.NotAfter, now))
		if need, why := NeedsRenewal(d, r.CAs, now); need {
			fmt.Fprintf(w, "  renewal due:  yes, %s\n", why)
		} else {
			fmt.Fprintf(w, "  renewal due:  no\n")
		}
	}
	if r.Staged {
		fmt.Fprintln(w, "staged pair:    device.crt.new present (renewal in progress or interrupted)")
	}
	for _, e := range r.Errors {
		fmt.Fprintf(w, "error:          %s\n", e)
	}
}

func remaining(t, now time.Time) string {
	d := t.Sub(now)
	if d < 0 {
		return fmt.Sprintf("expired %d days ago", int(-d.Hours()/24))
	}
	return fmt.Sprintf("in %d days", int(d.Hours()/24))
}
