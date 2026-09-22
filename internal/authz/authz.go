// Package authz is the one authorization engine (spec §3): Check and Why.
// Default-deny, no deny rules, suspension evaluated before any grant.
// Conditions are CEL (D1) and are classified at write time as
// offline-evaluable or online-only (§3.1).
package authz

import (
	"context"
	"fmt"
	"strings"
	"time"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"

	"rostor.org/app/internal/directory"
)

// Reason is one link in the reason chain returned with every decision.
type Reason struct {
	Code   string         `json:"code"`
	Params map[string]any `json:"params"`
}

type Decision struct {
	Allow     bool     `json:"-"`
	Decision  string   `json:"decision"` // ALLOW | DENY
	Reasons   []Reason `json:"reason"`
	GrantID   string   `json:"grant_id,omitempty"`
	AsOf      time.Time `json:"as_of"`
}

// Presented describes how the principal proved identity for this check.
// Assurance is credential-intrinsic (D12) and is the only auth fact conditions
// may quantify over in this slice.
type Presented struct {
	Assurance  string
	Properties []string
}

var assuranceRank = map[string]int{"AL0": 0, "AL1": 1, "AL2": 2, "AL3": 3}

type Engine struct {
	env *cel.Env
}

// New builds the CEL environment. The exposed function subset is curated (D1):
// only these variables exist, and only the offline-evaluable ones for now.
func New() (*Engine, error) {
	env, err := cel.NewEnv(
		cel.Variable("now", cel.TimestampType),
		cel.Variable("assurance", cel.IntType),
		cel.Variable("properties", cel.ListType(cel.StringType)),
		cel.Variable("principal", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("resource", cel.MapType(cel.StringType, cel.DynType)),
	)
	if err != nil {
		return nil, err
	}
	return &Engine{env: env}, nil
}

// ValidateCondition parses and type-checks expr and returns its class. Every
// variable available in this slice is a pure function of snapshot data plus a
// clock, so all valid conditions are "offline"; online-only variables (live
// posture, approvals) will classify as "online" when they are added.
func (e *Engine) ValidateCondition(expr string) (string, error) {
	ast, iss := e.env.Compile(expr)
	if iss != nil && iss.Err() != nil {
		return "", iss.Err()
	}
	if ast.OutputType() != cel.BoolType {
		return "", fmt.Errorf("condition must be boolean, got %s", ast.OutputType())
	}
	return "offline", nil
}

func (e *Engine) eval(expr string, in map[string]any) (bool, error) {
	ast, iss := e.env.Compile(expr)
	if iss != nil && iss.Err() != nil {
		return false, iss.Err()
	}
	prg, err := e.env.Program(ast)
	if err != nil {
		return false, err
	}
	out, _, err := prg.Eval(in)
	if err != nil {
		return false, err
	}
	b, ok := out.(types.Bool)
	if !ok {
		return false, fmt.Errorf("condition did not produce bool")
	}
	return bool(b), nil
}

// Check answers "can principal do action on resource?" with a reason chain.
// It is also the body of Why: Why simply asks for every candidate, not the
// first match.
func (e *Engine) Check(ctx context.Context, q directory.Querier, tenantID string, p *directory.Principal, action, resourceType, resourceID string, pres Presented) (*Decision, error) {
	d, err := e.decide(ctx, q, tenantID, p, action, resourceType, resourceID, pres, false)
	if err != nil {
		return nil, err
	}
	return d.Decision, nil
}

type Explanation struct {
	Decision
	Principal  string              `json:"principal"`
	Action     string              `json:"action"`
	Resource   string              `json:"resource"`
	Groups     map[string][]string `json:"groups"`     // group → membership path
	Candidates []Candidate         `json:"candidates"` // every grant considered
}

type Candidate struct {
	Grant     directory.Grant `json:"grant"`
	Via       string          `json:"via"`
	Matched   bool            `json:"matched"`
	Condition string          `json:"condition_result,omitempty"`
}

// Why returns the full derivation (§3.1): which grants were considered, via
// which group path, and how each condition evaluated, with as-of timestamps.
func (e *Engine) Why(ctx context.Context, q directory.Querier, tenantID string, p *directory.Principal, action, resourceType, resourceID string, pres Presented) (*Explanation, error) {
	d, err := e.decide(ctx, q, tenantID, p, action, resourceType, resourceID, pres, true)
	if err != nil {
		return nil, err
	}
	return d.explanation, nil
}

type decided struct {
	*Decision
	explanation *Explanation
}

func (e *Engine) decide(ctx context.Context, q directory.Querier, tenantID string, p *directory.Principal, action, resourceType, resourceID string, pres Presented, explain bool) (*decided, error) {
	now := time.Now().UTC()
	d := &Decision{AsOf: now, Decision: "DENY"}
	ex := &Explanation{Principal: p.ID, Action: action, Resource: resourceType + ":" + resourceID}
	res := &decided{Decision: d, explanation: ex}
	defer func() { ex.Decision = *d }()

	// §3.2: suspension (and any non-active state) is evaluated before grants.
	if p.State == "suspended" {
		d.Reasons = []Reason{{Code: "principal.suspended", Params: map[string]any{}}}
		return res, nil
	}
	if p.State != "active" {
		d.Reasons = []Reason{{Code: "principal.not_active", Params: map[string]any{"state": p.State}}}
		return res, nil
	}

	chain, err := directory.ResourceChain(ctx, q, tenantID, resourceType, resourceID)
	if err != nil {
		return nil, err
	}
	roles, err := directory.RolesGranting(ctx, q, tenantID, resourceType, action)
	if err != nil {
		return nil, err
	}
	// Roles are per resource type; a grant on an ancestor of a different type
	// must name a role that grants the action on the *target* type. To keep
	// that explicit we also accept roles defined on each ancestor type.
	for _, r := range chain[1:] {
		more, err := directory.RolesGranting(ctx, q, tenantID, r.Type, action)
		if err != nil {
			return nil, err
		}
		roles = append(roles, more...)
	}
	paths, err := directory.GroupPaths(ctx, q, tenantID, p.ID)
	if err != nil {
		return nil, err
	}
	ex.Groups = paths
	subjects := []directory.Subject{{Kind: "principal", ID: p.ID}}
	for g := range paths {
		subjects = append(subjects, directory.Subject{Kind: "group", ID: g})
	}
	grants, err := directory.CandidateGrants(ctx, q, tenantID, subjects, chain, roles, now)
	if err != nil {
		return nil, err
	}
	if len(grants) == 0 {
		d.Reasons = []Reason{{Code: "grant.none", Params: map[string]any{"resource_type": resourceType}}}
		return res, nil
	}

	in := map[string]any{
		"now":        now,
		"assurance":  int64(assuranceRank[pres.Assurance]),
		"properties": nonNil(pres.Properties),
		"principal":  map[string]any{"id": p.ID, "username": p.Username, "attributes": p.Attributes},
		"resource":   map[string]any{"type": resourceType, "id": resourceID, "attributes": chain[0].Attributes},
	}
	var condFailed bool
	for _, g := range grants {
		via := "direct"
		if g.SubjectKind == "group" {
			via = "group:" + strings.Join(paths[g.SubjectID], "/")
		}
		c := Candidate{Grant: g, Via: via}
		ok := true
		if g.Condition != "" {
			ok, err = e.eval(g.Condition, in)
			if err != nil {
				c.Condition = "error: " + err.Error()
				ok = false
			} else if ok {
				c.Condition = "true"
			} else {
				c.Condition = "false"
			}
		}
		c.Matched = ok
		ex.Candidates = append(ex.Candidates, c)
		if ok && !d.Allow {
			d.Allow = true
			d.Decision = "ALLOW"
			d.GrantID = g.ID
			d.Reasons = []Reason{{Code: "grant.matched", Params: map[string]any{"grant_id": g.ID, "role": g.Role, "via": via,
				"resource": g.ResourceType + ":" + g.ResourceID}}}
			if !explain {
				return res, nil
			}
		}
		if !ok {
			condFailed = true
		}
	}
	if !d.Allow {
		if condFailed {
			d.Reasons = []Reason{{Code: "grant.condition_failed", Params: map[string]any{}}}
		} else {
			d.Reasons = []Reason{{Code: "grant.none", Params: map[string]any{"resource_type": resourceType}}}
		}
	}
	return res, nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
