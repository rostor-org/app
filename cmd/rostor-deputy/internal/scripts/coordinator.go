package scripts

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"rostor.org/app/cmd/rostor-deputy/internal/core"
)

// Client is what the coordinator needs from core. *core.Client and
// core.Mock satisfy it; tests use a fake.
type Client interface {
	Scripts(ctx context.Context) ([]core.Script, error)
	ReportRun(ctx context.Context, id string, run core.ScriptRun) error
}

// Coordinator fetches, verifies, plans, runs and reports. One instance
// serves both the heartbeat (immediates) and logons (sign-in scripts); a
// mutex keeps runs one at a time across the two, which is what the contract
// promises the admin who ordered them.
type Coordinator struct {
	Client Client
	// CAFile is ca.crt; it is read at every fetch so a rotated bundle
	// applies without a restart, exactly like the mTLS pool does.
	CAFile string
	State  *State
	Runner *Runner
	Logger *log.Logger
	// Now is the clock for state stamps; nil means time.Now.
	Now func() time.Time

	// ReportTimeout bounds one report call; 0 means core.Timeout.
	ReportTimeout time.Duration

	mu sync.Mutex
}

// RunDue runs every immediate script whose version has not run yet, in
// order. Fetch and bundle errors are returned (the heartbeat logs them);
// per-script failures are logged, reported, and never stop the next script.
func (c *Coordinator) RunDue(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	verified, err := c.fetchVerified(ctx)
	if err != nil {
		return err
	}
	for _, s := range Plan(verified, c.State) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		rep := c.run(ctx, s, nil)
		// Mark before anything else can fail: a version runs once whatever
		// its outcome, and a lost report must not turn into a second run.
		if err := c.State.MarkImmediate(s.ID, s.Version); err != nil {
			c.logf("script %s: save state: %v", s.ID, err)
		}
		c.report(ctx, s, rep)
	}
	return nil
}

// RunSignin runs every sign-in script, in order, with the person's identity
// in the environment (§1.4). Called after the logon reply has been sent.
func (c *Coordinator) RunSignin(ctx context.Context, identifier, principalID, localAccount string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	verified, err := c.fetchVerified(ctx)
	if err != nil {
		return err
	}
	env := map[string]string{
		"ROSTOR_USER":          identifier,
		"ROSTOR_PRINCIPAL":     principalID,
		"ROSTOR_LOCAL_ACCOUNT": localAccount,
	}
	for _, s := range PlanSignin(verified) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		rep := c.run(ctx, s, env)
		rep.PrincipalID = principalID
		if err := c.State.MarkSignin(s.ID, c.now()); err != nil {
			c.logf("script %s: save state: %v", s.ID, err)
		}
		c.report(ctx, s, rep)
	}
	return nil
}

// fetchVerified returns the scripts whose signatures verify. Failures are
// logged per script and the script is dropped: an unsigned or altered body
// is never run, and a single bad entry must not block the others.
func (c *Coordinator) fetchVerified(ctx context.Context) ([]Script, error) {
	caPEMs, err := os.ReadFile(c.CAFile)
	if err != nil {
		return nil, fmt.Errorf("read trust bundle: %w", err)
	}
	list, err := c.Client.Scripts(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch scripts: %w", err)
	}
	verified := list[:0:0]
	for _, s := range list {
		if err := Verify(s, caPEMs); err != nil {
			c.logf("script %s (%q v%d, signer %s) refused: %v", s.ID, s.Name, s.Version, s.Signer, err)
			continue
		}
		if s.Language != "" && s.Language != "powershell" {
			c.logf("script %s (%q v%d) skipped: language %q not supported", s.ID, s.Name, s.Version, s.Language)
			continue
		}
		verified = append(verified, s)
	}
	return verified, nil
}

func (c *Coordinator) run(ctx context.Context, s Script, env map[string]string) Run {
	c.logf("script %s (%q v%d, %s): starting", s.ID, s.Name, s.Version, s.Mode)
	rep := c.Runner.Run(ctx, s, env)
	c.logf("%s", describe(s, rep))
	return rep
}

func (c *Coordinator) report(ctx context.Context, s Script, rep Run) {
	timeout := c.ReportTimeout
	if timeout == 0 {
		timeout = core.Timeout
	}
	// The report gets its own deadline: a cancelled run context must not
	// also lose the report that says it was cancelled.
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
	defer cancel()
	if err := c.Client.ReportRun(rctx, s.ID, rep); err != nil {
		c.logf("script %s: report run: %v", s.ID, err)
	}
}

func (c *Coordinator) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Coordinator) logf(format string, args ...any) {
	if c.Logger != nil {
		c.Logger.Printf(format, args...)
	}
}
