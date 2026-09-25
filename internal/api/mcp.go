package api

// SPEC-agents: MCP on the core. A door into the same house, not a second
// house: every tool is an ordinary API call dispatched through the same mux
// under the caller's own credential, so it meets the same Check, the same
// owner attenuation, and lands in the same audit. Transport: MCP streamable
// HTTP, JSON responses only (no server-initiated stream in this slice).

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"

	"rostor.org/app/internal/audit"
	"rostor.org/app/internal/directory"
)

const mcpLatest = "2025-06-18"

var mcpVersions = map[string]bool{"2024-11-05": true, "2025-03-26": true, "2025-06-18": true}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// mcpTool maps a tool onto one API call. Path and Body build the request
// from the tool's arguments; the description comes from the catalog.
type mcpTool struct {
	Name   string
	Schema map[string]any
	Method string
	Path   func(a map[string]any) string
	Body   func(a map[string]any) any
}

func str(a map[string]any, k string) string {
	switch v := a[k].(type) {
	case string:
		return v
	case float64:
		return fmt.Sprint(int64(v))
	case bool:
		if v {
			return "1"
		}
	}
	return ""
}

func esc(s string) string { return url.PathEscape(s) }

func schema(props map[string]any, required ...string) map[string]any {
	out := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
	if len(required) > 0 {
		out["required"] = required
	}
	return out
}

func sProp(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }

// mcpTools is the tool table: name → API call. Descriptions live in the
// catalog under mcp.tool.<name>; property descriptions are short and
// technical (field names), so they stay here.
func (s *Server) mcpTools() []mcpTool {
	pick := func(a map[string]any, keys ...string) map[string]any {
		out := map[string]any{}
		for _, k := range keys {
			if v, ok := a[k]; ok && v != nil {
				out[k] = v
			}
		}
		return out
	}
	q := func(a map[string]any, keys ...string) string {
		v := url.Values{}
		for _, k := range keys {
			if x := str(a, k); x != "" {
				v.Set(k, x)
			}
		}
		if len(v) == 0 {
			return ""
		}
		return "?" + v.Encode()
	}
	return []mcpTool{
		{Name: "people_list", Schema: schema(map[string]any{"q": sProp("search by name or username")}), Method: "GET",
			Path: func(a map[string]any) string { return "/v1/admin/users" + q(a, "q") }},
		{Name: "person_get", Schema: schema(map[string]any{"id": sProp("principal id or username")}, "id"), Method: "GET",
			Path: func(a map[string]any) string { return "/v1/admin/users/" + esc(str(a, "id")) }},
		{Name: "person_create", Schema: schema(map[string]any{"username": sProp("lowercase username"), "display_name": sProp("display name")}, "username"), Method: "POST",
			Path: func(a map[string]any) string { return "/v1/admin/users" },
			Body: func(a map[string]any) any {
				return map[string]any{"username": str(a, "username"), "display_name": map[string]string{"en": str(a, "display_name")}}
			}},
		{Name: "person_state", Schema: schema(map[string]any{"id": sProp("principal id or username"), "state": map[string]any{"type": "string", "enum": []string{"active", "suspended"}}}, "id", "state"), Method: "POST",
			Path: func(a map[string]any) string { return "/v1/admin/users/" + esc(str(a, "id")) + "/state" },
			Body: func(a map[string]any) any { return pick(a, "state") }},
		{Name: "groups_list", Schema: schema(map[string]any{"q": sProp("search by name")}), Method: "GET",
			Path: func(a map[string]any) string { return "/v1/admin/groups" + q(a, "q") }},
		{Name: "group_get", Schema: schema(map[string]any{"name": sProp("group name")}, "name"), Method: "GET",
			Path: func(a map[string]any) string { return "/v1/admin/groups/" + esc(str(a, "name")) }},
		{Name: "group_create", Schema: schema(map[string]any{"name": sProp("group name")}, "name"), Method: "POST",
			Path: func(a map[string]any) string { return "/v1/admin/groups" }, Body: func(a map[string]any) any { return pick(a, "name") }},
		{Name: "group_add_member", Schema: schema(map[string]any{"group": sProp("group name"), "member": sProp("principal id or username")}, "group", "member"), Method: "POST",
			Path: func(a map[string]any) string { return "/v1/admin/groups/" + esc(str(a, "group")) + "/members" },
			Body: func(a map[string]any) any {
				return map[string]any{"member_kind": "principal", "member": str(a, "member")}
			}},
		{Name: "group_remove_member", Schema: schema(map[string]any{"group": sProp("group name"), "member": sProp("principal id or username")}, "group", "member"), Method: "DELETE",
			Path: func(a map[string]any) string { return "/v1/admin/groups/" + esc(str(a, "group")) + "/members" },
			Body: func(a map[string]any) any {
				return map[string]any{"member_kind": "principal", "member": str(a, "member")}
			}},
		{Name: "grants_list", Schema: schema(map[string]any{"q": sProp("search by subject, role or resource")}), Method: "GET",
			Path: func(a map[string]any) string { return "/v1/admin/grants" + q(a, "q") }},
		{Name: "grant_create", Schema: schema(map[string]any{
			"subject_kind": map[string]any{"type": "string", "enum": []string{"group", "principal"}}, "subject": sProp("group name, or principal id/username"),
			"role": sProp("role name defined for the resource type"), "resource_type": sProp("resource type"), "resource_id": sProp("resource id"),
			"condition": sProp("optional CEL condition"), "expires_at": sProp("optional RFC 3339 expiry")}, "subject_kind", "subject", "role", "resource_type", "resource_id"), Method: "POST",
			Path: func(a map[string]any) string { return "/v1/admin/grants" },
			Body: func(a map[string]any) any {
				return pick(a, "subject_kind", "subject", "role", "resource_type", "resource_id", "condition", "expires_at")
			}},
		{Name: "grant_revoke", Schema: schema(map[string]any{"id": sProp("grant id")}, "id"), Method: "DELETE",
			Path: func(a map[string]any) string { return "/v1/admin/grants/" + esc(str(a, "id")) }},
		{Name: "roles_list", Schema: schema(map[string]any{}), Method: "GET", Path: func(a map[string]any) string { return "/v1/admin/roles" }},
		{Name: "role_define", Schema: schema(map[string]any{"resource_type": sProp("resource type"), "name": sProp("role name"),
			"permissions": map[string]any{"type": "array", "items": map[string]any{"type": "string"}}}, "resource_type", "name", "permissions"), Method: "POST",
			Path: func(a map[string]any) string { return "/v1/admin/roles" }, Body: func(a map[string]any) any { return pick(a, "resource_type", "name", "permissions") }},
		{Name: "resources_list", Schema: schema(map[string]any{}), Method: "GET", Path: func(a map[string]any) string { return "/v1/admin/resources" }},
		{Name: "devices_list", Schema: schema(map[string]any{"q": sProp("search by device, type or id")}), Method: "GET",
			Path: func(a map[string]any) string { return "/v1/admin/devices" + q(a, "q") }},
		{Name: "why", Schema: schema(map[string]any{"principal": sProp("principal id or username"), "action": sProp("action, e.g. logon"),
			"resource_type": sProp("resource type"), "resource_id": sProp("resource id")}, "principal", "action", "resource_type", "resource_id"), Method: "GET",
			Path: func(a map[string]any) string {
				return "/v1/admin/why" + q(a, "principal", "action", "resource_type", "resource_id")
			}},
		{Name: "audit_list", Schema: schema(map[string]any{"q": sProp("search"), "limit": map[string]any{"type": "integer"}, "before": map[string]any{"type": "integer", "description": "page: rows before this seq"},
			"include_system": map[string]any{"type": "boolean"}}), Method: "GET",
			Path: func(a map[string]any) string {
				return "/v1/admin/audit" + q(a, "q", "limit", "before", "include_system")
			}},
		{Name: "audit_verify", Schema: schema(map[string]any{}), Method: "GET", Path: func(a map[string]any) string { return "/v1/admin/audit/verify" }},
		{Name: "agents_list", Schema: schema(map[string]any{"owner": sProp("owner id or username (admins)")}), Method: "GET",
			Path: func(a map[string]any) string { return "/v1/admin/agents" + q(a, "owner") }},
		{Name: "agent_get", Schema: schema(map[string]any{"id": sProp("agent id or username")}, "id"), Method: "GET",
			Path: func(a map[string]any) string { return "/v1/admin/agents/" + esc(str(a, "id")) }},
		{Name: "system_info", Schema: schema(map[string]any{}), Method: "GET", Path: func(a map[string]any) string { return "/v1/admin/system" }},
		{Name: "updates_status", Schema: schema(map[string]any{}), Method: "GET", Path: func(a map[string]any) string { return "/v1/admin/updates" }},
		{Name: "updates_check", Schema: schema(map[string]any{}), Method: "POST", Path: func(a map[string]any) string { return "/v1/admin/updates/check" }},
		{Name: "updates_apply", Schema: schema(map[string]any{}), Method: "POST", Path: func(a map[string]any) string { return "/v1/admin/updates/apply" }},
	}
}

func (s *Server) mcpToolList(loc string) []map[string]any {
	tools := s.mcpTools()
	sort.Slice(tools, func(i, j int) bool { return tools[i].Name < tools[j].Name })
	out := make([]map[string]any, 0, len(tools))
	for _, t := range tools {
		out = append(out, map[string]any{"name": t.Name, "description": s.Catalog.Render(loc, "mcp.tool."+t.Name, nil), "inputSchema": t.Schema})
	}
	return out
}

// dispatch runs one API call through the server's own mux with the caller's
// credential, exactly as an HTTP client would.
func (s *Server) dispatch(r *http.Request, method, path string, body any) (int, []byte) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req := httptest.NewRequestWithContext(r.Context(), method, path, rd)
	req.Header.Set("Authorization", r.Header.Get("Authorization"))
	req.Header.Set("Accept-Language", r.Header.Get("Accept-Language"))
	req.Header.Set("X-Requested-With", "rostor-console")
	req.Header.Set("Content-Type", "application/json")
	req.Host = r.Host
	req.RemoteAddr = r.RemoteAddr
	for _, c := range r.Cookies() {
		req.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	s.mux.ServeHTTP(rr, req)
	return rr.Code, rr.Body.Bytes()
}

func (s *Server) handleMCP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "DELETE":
		w.WriteHeader(204)
		return
	case "GET":
		// No server-initiated stream in this slice.
		w.Header().Set("Allow", "POST, DELETE")
		w.WriteHeader(405)
		return
	}
	p, _, ok := s.caller(w, r)
	if !ok {
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		s.writeErr(w, r, 400, "request.malformed", map[string]any{"field": "body"})
		return
	}
	raw = bytes.TrimSpace(raw)
	batch := len(raw) > 0 && raw[0] == '['
	var reqs []rpcRequest
	if batch {
		err = json.Unmarshal(raw, &reqs)
	} else {
		var one rpcRequest
		err = json.Unmarshal(raw, &one)
		reqs = []rpcRequest{one}
	}
	if err != nil {
		s.writeJSON(w, 400, rpcResponse{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{Code: -32700, Message: "parse error"}})
		return
	}
	var out []rpcResponse
	for _, rq := range reqs {
		resp := s.mcpCall(r, p, rq)
		if resp != nil {
			out = append(out, *resp)
		}
	}
	if len(out) == 0 {
		w.WriteHeader(202)
		return
	}
	if batch {
		s.writeJSON(w, 200, out)
		return
	}
	s.writeJSON(w, 200, out[0])
}

// mcpCall answers one JSON-RPC request; nil for notifications.
func (s *Server) mcpCall(r *http.Request, p *directory.Principal, rq rpcRequest) *rpcResponse {
	notification := len(rq.ID) == 0 || string(rq.ID) == "null"
	reply := func(result any, e *rpcError) *rpcResponse {
		if notification {
			return nil
		}
		return &rpcResponse{JSONRPC: "2.0", ID: rq.ID, Result: result, Error: e}
	}
	loc := locale(r)
	switch rq.Method {
	case "initialize":
		var params struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(rq.Params, &params)
		v := mcpLatest
		if mcpVersions[params.ProtocolVersion] {
			v = params.ProtocolVersion
		}
		return reply(map[string]any{
			"protocolVersion": v,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}, "resources": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": "rostor", "version": s.Version},
			"instructions":    s.Catalog.Render(loc, "mcp.instructions", map[string]any{"principal": p.Username}),
		}, nil)
	case "ping":
		return reply(map[string]any{}, nil)
	case "tools/list":
		return reply(map[string]any{"tools": s.mcpToolList(loc)}, nil)
	case "tools/call":
		var params struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		if err := json.Unmarshal(rq.Params, &params); err != nil {
			return reply(nil, &rpcError{Code: -32602, Message: "invalid params"})
		}
		if params.Arguments == nil {
			params.Arguments = map[string]any{}
		}
		var tool *mcpTool
		for _, t := range s.mcpTools() {
			if t.Name == params.Name {
				tt := t
				tool = &tt
			}
		}
		if tool == nil {
			return reply(nil, &rpcError{Code: -32602, Message: "unknown tool", Data: map[string]any{"name": params.Name}})
		}
		var body any
		if tool.Body != nil {
			body = tool.Body(params.Arguments)
		}
		status, res := s.dispatch(r, tool.Method, tool.Path(params.Arguments), body)
		outcome := "ok"
		if status == 401 || status == 403 {
			outcome = "deny"
		} else if status >= 400 {
			outcome = "error"
		}
		a := directory.Actor{Kind: p.Kind, ID: p.ID, CorrelationID: corrOf(r)}
		s.auditEvent(r.Context(), audit.Event{ActorKind: a.Kind, ActorID: a.ID, Action: "mcp.call", TargetType: "tool", TargetID: tool.Name,
			Outcome: outcome, Detail: map[string]any{"status": status, "owner_id": directory.OwnerID(p)}, CorrelationID: a.CorrelationID})
		text := strings.TrimSpace(string(res))
		if text == "" {
			text = fmt.Sprintf(`{"status":%d}`, status)
		}
		result := map[string]any{"content": []map[string]any{{"type": "text", "text": text}}, "isError": status >= 400}
		if json.Valid(res) && len(res) > 0 && res[0] == '{' {
			result["structuredContent"] = json.RawMessage(res)
		}
		return reply(result, nil)
	case "resources/list":
		return reply(map[string]any{"resources": []map[string]any{
			{"uri": "rostor://me", "name": "me", "description": s.Catalog.Render(loc, "mcp.resource.me", nil), "mimeType": "application/json"},
			{"uri": "rostor://catalog", "name": "catalog", "description": s.Catalog.Render(loc, "mcp.resource.catalog", nil), "mimeType": "application/json"},
		}}, nil)
	case "resources/read":
		var params struct {
			URI string `json:"uri"`
		}
		_ = json.Unmarshal(rq.Params, &params)
		var text string
		switch params.URI {
		case "rostor://me":
			b, _ := json.Marshal(map[string]any{"id": p.ID, "username": p.Username, "kind": p.Kind, "state": p.State, "owner_id": directory.OwnerID(p)})
			text = string(b)
		case "rostor://catalog":
			strs, _ := s.Catalog.Strings(loc)
			b, _ := json.Marshal(strs)
			text = string(b)
		default:
			return reply(nil, &rpcError{Code: -32002, Message: "resource not found", Data: map[string]any{"uri": params.URI}})
		}
		return reply(map[string]any{"contents": []map[string]any{{"uri": params.URI, "mimeType": "application/json", "text": text}}}, nil)
	default:
		if strings.HasPrefix(rq.Method, "notifications/") {
			return nil
		}
		return reply(nil, &rpcError{Code: -32601, Message: "method not found", Data: map[string]any{"method": rq.Method}})
	}
}
