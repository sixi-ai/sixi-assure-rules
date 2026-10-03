package rules

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"regexp"
	"slices"
	"strings"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common"
	"cel.dev/cel-go/common/ast"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/common/types/traits"
	"cel.dev/cel-go/ext"
	"cel.dev/cel-go/interpreter"

	"github.com/sixi-ai/sixi-assure-rules/model"
)

// CEL environment of docs/03. Three environments share the helper library and differ only in
// the scope variables they declare: node (n), edge (e), graph (none besides g and tenant).
//
// Nodes and edges are plain map[string]any values (so `e.from.type`, `n.attrs.x`, `e.auth` work
// with the standard map semantics); the graph is a custom ref.Val carrying the adjacency, the
// per-evaluation caches and the policy (so `regime()` and `required()` can be answered without
// rebuilding programs per tenant).

// Scope names.
const (
	ScopeNode  = "node"
	ScopeEdge  = "edge"
	ScopeGraph = "graph"
)

// DefaultCostLimit bounds the CEL runtime cost of one condition evaluation (per element).
const DefaultCostLimit uint64 = 1_000_000

// interruptCheckFrequency is how often (comprehension iterations) the runtime polls ctx.Done().
const interruptCheckFrequency uint = 100

var graphType = types.NewObjectType("sixi.Graph")

// inCallRe rewrites `.in(` to `.inEdges(`: `in` is a reserved word in CEL and cannot be used as a
// member-function name, while docs/03 spells the helper `g.in(nodeId, kind)`.
var inCallRe = regexp.MustCompile(`\.\s*in\s*\(`)

// rewriteSource applies the source-level aliases documented in rules/README.md.
func rewriteSource(src string) string {
	return inCallRe.ReplaceAllString(src, ".inEdges(")
}

type envSet struct {
	byScope map[string]*cel.Env
}

func (s *envSet) env(scope string) (*cel.Env, error) {
	e, ok := s.byScope[scope]
	if !ok {
		return nil, fmt.Errorf("unknown scope %q", scope)
	}
	return e, nil
}

// newEnvs builds the base environment and the three scoped extensions.
func newEnvs() (*envSet, error) {
	dyn := cel.DynType
	str := cel.StringType
	member := func(name, id string, args []*cel.Type, ret *cel.Type, opt cel.OverloadOpt) cel.EnvOption {
		return cel.Function(name, cel.MemberOverload(id, args, ret, opt))
	}
	base, err := cel.NewEnv(
		cel.Variable("g", dyn),
		cel.Variable("tenant", cel.MapType(str, dyn)),
		cel.Variable("kb", cel.MapType(str, dyn)),
		// prov: the computed provenance facts of ADR-086 §7 (ProvenanceVars), injected by provProgram from the graph.
		cel.Variable("prov", cel.MapType(str, dyn)),
		ext.Strings(),  // lowerAscii(), trim(), … for lookups into kb (ADR-035)
		ext.Bindings(), // cel.bind(name, value, expr): names a value once, e.g. the host of a hosted_on target (B3)
		cel.CrossTypeNumericComparisons(true),
		cel.Macros(policyMacro("regime"), policyMacro("required"), policyMacro("capped")),
		cel.Function("attr", cel.Overload("attr_dyn_string_dyn", []*cel.Type{dyn, str, dyn}, dyn, cel.FunctionBinding(attrFn))),
		member("has", "graph_has", []*cel.Type{dyn, str}, cel.BoolType, cel.BinaryBinding(graphBinary((*graphVal).has))),
		member("nodes", "graph_nodes", []*cel.Type{dyn, str}, cel.ListType(dyn), cel.BinaryBinding(graphBinary((*graphVal).nodesOf))),
		member("edges", "graph_edges", []*cel.Type{dyn, str}, cel.ListType(dyn), cel.BinaryBinding(graphBinary((*graphVal).edgesOf))),
		member("inEdges", "graph_in", []*cel.Type{dyn, str, str}, cel.ListType(dyn), cel.FunctionBinding(graphTernary((*graphVal).inOf))),
		member("out", "graph_out", []*cel.Type{dyn, str, str}, cel.ListType(dyn), cel.FunctionBinding(graphTernary((*graphVal).outOf))),
		member("outEdges", "graph_out_alias", []*cel.Type{dyn, str, str}, cel.ListType(dyn), cel.FunctionBinding(graphTernary((*graphVal).outOf))),
		member("reachable", "graph_reachable", []*cel.Type{dyn, str, str}, cel.BoolType, cel.FunctionBinding(graphTernary((*graphVal).reachableVal))),
		member("pathThrough", "graph_path_through", []*cel.Type{dyn, str, str, str}, cel.BoolType, cel.FunctionBinding(graphPathThrough)),
		member("pathAvoiding", "graph_path_avoiding", []*cel.Type{dyn, str, str, str}, cel.BoolType, cel.FunctionBinding(graphQuaternary((*graphVal).pathAvoidingType))),
		member("pathAvoidingAttr", "graph_path_avoiding_attr", []*cel.Type{dyn, str, str, str}, cel.BoolType, cel.FunctionBinding(graphQuaternary((*graphVal).pathAvoidingAttr))),
		member("dataFlows", "graph_data_flows", []*cel.Type{dyn, str, str}, cel.BoolType, cel.FunctionBinding(graphTernary((*graphVal).dataFlowsVal))),
		member("dataSources", "graph_data_sources", []*cel.Type{dyn, str, str}, cel.ListType(dyn), cel.FunctionBinding(graphTernary((*graphVal).dataSourcesVal))),
		member("dataZones", "graph_data_zones", []*cel.Type{dyn, str, str}, cel.ListType(dyn), cel.FunctionBinding(graphTernary((*graphVal).dataZonesVal))),
		member("writersInto", "graph_writers_into", []*cel.Type{dyn, str}, cel.ListType(dyn), cel.BinaryBinding(graphBinary((*graphVal).writersIntoVal))),
		member("upstreamAvoidingAttr", "graph_upstream_avoiding_attr", []*cel.Type{dyn, str, str}, cel.ListType(dyn), cel.FunctionBinding(graphTernary((*graphVal).upstreamAvoidingAttrVal))),
		cel.Function("upstreamAvoiding",
			cel.MemberOverload("graph_upstream_avoiding", []*cel.Type{dyn, str, cel.ListType(str), cel.ListType(str)}, cel.ListType(dyn), cel.FunctionBinding(graphUpstreamAvoiding)),
			// The attr form also blocks every node of attrTypes whose boolean attribute is true (AGT-003: an agent with
			// content_safety).
			cel.MemberOverload("graph_upstream_avoiding_attr_block", []*cel.Type{dyn, str, cel.ListType(str), cel.ListType(str), cel.ListType(str), str}, cel.ListType(dyn), cel.FunctionBinding(graphUpstreamAvoiding)),
			// The function-aware form (ADR-088 Amendments, B2b): a node of the types blocks when it credits the hop —
			// it declares every one of needFunctions in functions[], or it declares no functions and its kind is in
			// kinds (any kind when kinds is empty). A node of the types that does not credit is walked through, at
			// any chain length (AI-001, NET-003, STR-005, AGW-003, APX-004).
			cel.MemberOverload("graph_upstream_avoiding_functions", []*cel.Type{dyn, str, cel.ListType(str), cel.ListType(str), cel.ListType(str)}, cel.ListType(dyn), cel.FunctionBinding(graphUpstreamAvoiding))),
		member("regime", "graph_regime", []*cel.Type{dyn, str}, cel.BoolType, cel.BinaryBinding(graphBinary((*graphVal).regimeVal))),
		member("required", "graph_required", []*cel.Type{dyn, str}, cel.IntType, cel.BinaryBinding(graphBinary((*graphVal).requiredVal))),
		member("capped", "graph_capped", []*cel.Type{dyn, str}, cel.IntType, cel.BinaryBinding(graphBinary((*graphVal).cappedVal))),
		member("inZone", "node_in_zone", []*cel.Type{dyn, str}, cel.BoolType, cel.BinaryBinding(inZoneFn)),
	)
	if err != nil {
		return nil, fmt.Errorf("cel base env: %w", err)
	}
	nodeEnv, err := base.Extend(cel.Variable("n", cel.MapType(str, dyn)))
	if err != nil {
		return nil, fmt.Errorf("cel node env: %w", err)
	}
	edgeEnv, err := base.Extend(cel.Variable("e", cel.MapType(str, dyn)))
	if err != nil {
		return nil, fmt.Errorf("cel edge env: %w", err)
	}
	return &envSet{byScope: map[string]*cel.Env{ScopeNode: nodeEnv, ScopeEdge: edgeEnv, ScopeGraph: base}}, nil
}

// policyMacro rewrites the global call `name(x)` into the member call `g.name(x)` so the policy
// helpers can read the per-evaluation policy carried by the graph value.
func policyMacro(name string) cel.Macro {
	return cel.GlobalMacro(name, 1, func(eh cel.MacroExprFactory, _ ast.Expr, args []ast.Expr) (ast.Expr, *common.Error) {
		return eh.NewMemberCall(name, eh.NewIdent("g"), args[0]), nil
	})
}

// compile parses, checks and plans one expression for a scope.
func (s *envSet) compile(scope, src string, costLimit uint64) (cel.Program, *cel.Type, error) {
	env, err := s.env(scope)
	if err != nil {
		return nil, nil, err
	}
	a, iss := env.Compile(rewriteSource(src))
	if iss != nil && iss.Err() != nil {
		return nil, nil, iss.Err()
	}
	if costLimit == 0 {
		costLimit = DefaultCostLimit
	}
	prog, err := env.Program(a, cel.CostLimit(costLimit), cel.EvalOptions(cel.OptTrackCost), cel.InterruptCheckFrequency(interruptCheckFrequency))
	if err != nil {
		return nil, nil, err
	}
	return provProgram{prog}, a.OutputType(), nil
}

// provProgram resolves the `prov` variable (ADR-086 §7) from the graph of the activation, so every program the
// engine evaluates sees the provenance facts computed once per evaluation in buildGraph, beside `kb`. An activation
// without a graph (a program evaluated outside an evaluation) sees prov.available == false. Every other name
// resolves from the activation map unchanged, CEL unknowns included.
type provProgram struct{ cel.Program }

func (p provProgram) Eval(input any) (ref.Val, *cel.EvalDetails, error) {
	return p.Program.Eval(withProv(input))
}

func (p provProgram) ContextEval(ctx context.Context, input any) (ref.Val, *cel.EvalDetails, error) {
	return p.Program.ContextEval(ctx, withProv(input))
}

func withProv(input any) any {
	vars, ok := input.(map[string]any)
	if !ok {
		return input
	}
	if _, set := vars["prov"]; set {
		return input
	}
	return provActivation{vars: vars}
}

// provActivation is the activation map plus `prov`.
type provActivation struct{ vars map[string]any }

func (a provActivation) ResolveName(name string) (any, bool) {
	if name == "prov" {
		if g, ok := a.vars["g"].(*graphVal); ok && g.prov != nil {
			return g.prov, true
		}
		return noProv, true
	}
	v, ok := a.vars[name]
	return v, ok
}

func (provActivation) Parent() interpreter.Activation { return nil }

// noProv is `prov` without provenance facts: unavailable, no elements.
var noProv = map[string]any{"available": false, "as_of": "", "elements": map[string]any{}}

// ---- helper bindings --------------------------------------------------------------------------

func graphBinary(fn func(g *graphVal, arg string) ref.Val) func(ref.Val, ref.Val) ref.Val {
	return func(lhs, rhs ref.Val) ref.Val {
		g, ok := lhs.(*graphVal)
		if !ok {
			return types.NewErr("receiver is not the graph (got %s)", lhs.Type().TypeName())
		}
		s, ok := rhs.(types.String)
		if !ok {
			return types.NewErr("argument must be a string")
		}
		return fn(g, string(s))
	}
}

func graphTernary(fn func(g *graphVal, a, b string) ref.Val) func(...ref.Val) ref.Val {
	return func(args ...ref.Val) ref.Val {
		if len(args) != 3 {
			return types.NewErr("expected 3 arguments")
		}
		g, ok := args[0].(*graphVal)
		if !ok {
			return types.NewErr("receiver is not the graph (got %s)", args[0].Type().TypeName())
		}
		a, ok1 := args[1].(types.String)
		b, ok2 := args[2].(types.String)
		if !ok1 || !ok2 {
			return types.NewErr("arguments must be strings")
		}
		return fn(g, string(a), string(b))
	}
}

// graphQuaternary binds a graph member function taking three string arguments.
func graphQuaternary(fn func(g *graphVal, a, b, c string) bool) func(...ref.Val) ref.Val {
	return func(args ...ref.Val) ref.Val {
		if len(args) != 4 {
			return types.NewErr("expected 3 arguments")
		}
		g, ok := args[0].(*graphVal)
		if !ok {
			return types.NewErr("receiver is not the graph (got %s)", args[0].Type().TypeName())
		}
		a, ok1 := args[1].(types.String)
		b, ok2 := args[2].(types.String)
		c, ok3 := args[3].(types.String)
		if !ok1 || !ok2 || !ok3 {
			return types.NewErr("arguments must be strings")
		}
		return types.Bool(fn(g, string(a), string(b), string(c)))
	}
}

func graphPathThrough(args ...ref.Val) ref.Val {
	if len(args) != 4 {
		return types.NewErr("pathThrough expects 3 arguments")
	}
	g, ok := args[0].(*graphVal)
	if !ok {
		return types.NewErr("receiver is not the graph (got %s)", args[0].Type().TypeName())
	}
	from, ok1 := args[1].(types.String)
	to, ok2 := args[2].(types.String)
	via, ok3 := args[3].(types.String)
	if !ok1 || !ok2 || !ok3 {
		return types.NewErr("pathThrough arguments must be strings")
	}
	return types.Bool(g.pathThrough(string(from), string(to), string(via)))
}

// attrFn implements attr(x, key, default): x is a node, edge or the graph; missing or null → default.
func attrFn(args ...ref.Val) ref.Val {
	if len(args) != 3 {
		return types.NewErr("attr expects 3 arguments")
	}
	key, ok := args[1].(types.String)
	if !ok {
		return types.NewErr("attr key must be a string")
	}
	attrs, ok := attrsOf(args[0])
	if !ok {
		return types.NewErr("attr: first argument must be a node, edge or the graph (got %s)", args[0].Type().TypeName())
	}
	v, present := attrs[string(key)]
	if !present || v == nil {
		return args[2]
	}
	return types.DefaultTypeAdapter.NativeToValue(v)
}

// attrsOf extracts the attrs map of a node/edge map or of the graph value.
func attrsOf(v ref.Val) (map[string]any, bool) {
	switch x := v.(type) {
	case *graphVal:
		return x.attrs, true
	case traits.Mapper:
		if m, ok := x.Value().(map[string]any); ok {
			a, _ := m["attrs"].(map[string]any)
			return a, true
		}
		av, found := x.Find(types.String("attrs"))
		if !found {
			return map[string]any{}, true
		}
		if mm, ok := av.(traits.Mapper); ok {
			if m, ok := mm.Value().(map[string]any); ok {
				return m, true
			}
		}
		return map[string]any{}, true
	}
	return nil, false
}

// inZoneFn implements n.inZone(kind): the node belongs to a group of that kind. A workflow group is
// not in n.groups (it is no boundary, buildGraph); n.inZone("workflow") reads n.workflow_ids.
func inZoneFn(lhs, rhs ref.Val) ref.Val {
	kind, ok := rhs.(types.String)
	if !ok {
		return types.NewErr("inZone argument must be a string")
	}
	m, ok := lhs.(traits.Mapper)
	if !ok {
		return types.NewErr("inZone receiver must be a node")
	}
	nm, ok := m.Value().(map[string]any)
	if !ok {
		return types.NewErr("inZone receiver must be a node")
	}
	if string(kind) == model.GroupKindWorkflow {
		workflows, _ := nm["workflow_ids"].([]string)
		return types.Bool(len(workflows) > 0)
	}
	kinds, _ := nm["groups"].([]string)
	for _, k := range kinds {
		if k == string(kind) {
			return types.True
		}
	}
	return types.False
}

// ---- graph value --------------------------------------------------------------------------------

// graphVal is the CEL representation of the whole model plus the evaluation policy. It is built
// once per Evaluate call and is not safe for concurrent use (caches are unsynchronised).
type graphVal struct {
	id    string
	name  string
	attrs map[string]any

	nodes       []any
	edges       []any
	identities  []any // schema 1.1 identity entities (identityValue)
	groups      []any // every group (groupValue), so a condition reads a workflow's bounds (schema 1.2)
	nodeByID    map[string]map[string]any
	edgeByID    map[string]map[string]any
	nodesByType map[string][]any
	edgesByKind map[string][]any
	outEdges    map[string][]any
	inEdges     map[string][]any
	outAdj      map[string][]string
	inAdj       map[string][]string

	fwd       map[string]map[string]bool
	bwd       map[string]map[string]bool
	pathCache map[[3]string]bool

	// dataAdj follows the direction data moves (docs/03 dataFlows); avoid caches the walks of pathAvoiding and
	// pathAvoidingAttr keyed by {from, "type:"|"attr:" + name}, dataFwd those of dataFlows.
	dataAdj map[string][]string
	dataRev map[string][]string
	avoid   map[[2]string]map[string]bool
	// upAvoid caches upstreamAvoiding keyed by {id, blocked types, blocked kinds, attr types, blocking attr} (lists
	// joined with NUL); the function-aware form keys {id, types, kinds, "\x01functions", needed functions}.
	upAvoid map[[5]string][]any
	dataFwd map[string]map[string]bool
	dataBwd map[string]map[string]bool
	writers map[string][]any

	regimes map[string]bool
	policy  Policy
	table   *PolicyTable
	// prov is the `prov` variable of this evaluation (ProvenanceVars, ADR-086 §7).
	prov map[string]any
}

// buildGraph projects the architecture into CEL values (docs/03 environment).
func buildGraph(a *model.Architecture, p Policy, table *PolicyTable) *graphVal {
	if table == nil {
		table = DefaultPolicyTable()
	}
	g := &graphVal{
		id: a.ID, name: a.Name, attrs: normAttrs(a.Attrs),
		nodeByID: make(map[string]map[string]any, len(a.Nodes)), edgeByID: make(map[string]map[string]any, len(a.Edges)),
		nodesByType: map[string][]any{}, edgesByKind: map[string][]any{},
		outEdges: map[string][]any{}, inEdges: map[string][]any{}, outAdj: map[string][]string{}, inAdj: map[string][]string{},
		fwd: map[string]map[string]bool{}, bwd: map[string]map[string]bool{}, pathCache: map[[3]string]bool{},
		dataAdj: map[string][]string{}, dataRev: map[string][]string{}, avoid: map[[2]string]map[string]bool{},
		upAvoid: map[[5]string][]any{},
		dataFwd: map[string]map[string]bool{}, dataBwd: map[string]map[string]bool{}, writers: map[string][]any{},
		regimes: regimeSet(p.Regimes), policy: p, table: table,
		prov: ProvenanceVars(a, p.AsOf),
	}
	g.identities = make([]any, 0, len(a.Identities))
	for i := range a.Identities {
		g.identities = append(g.identities, identityValue(&a.Identities[i]))
	}
	groupKinds := map[string][]string{}
	groupIDs := map[string][]string{}
	notes := map[string]bool{}
	for i := range a.Nodes {
		if model.IsNote(a.Nodes[i].Type) {
			notes[a.Nodes[i].ID] = true
		}
	}
	g.groups = make([]any, 0, len(a.Groups))
	for i := range a.Groups {
		g.groups = append(g.groups, groupValue(&a.Groups[i], notes))
	}
	// A workflow group (schema 1.2, ADR-093 FS-06) lists the executors of one agent workflow; it is
	// not a security boundary. About fifteen pack conditions read "the two ends share no group id"
	// as crossing a boundary (DLG-003, WIS-011, ATA-*, STR-002, the C4 and NET checks), so a workflow
	// group stays out of n.groups and n.group_ids: drawing one never adds or hides a boundary
	// finding. Its membership is n.workflow_ids, g.groups[].node_ids and n.inZone("workflow").
	workflowIDs := map[string][]string{}
	for _, grp := range a.Groups {
		for _, nid := range grp.NodeIDs {
			if grp.Kind == model.GroupKindWorkflow {
				workflowIDs[nid] = append(workflowIDs[nid], grp.ID)
				continue
			}
			groupKinds[nid] = append(groupKinds[nid], grp.Kind)
			groupIDs[nid] = append(groupIDs[nid], grp.ID)
		}
	}
	// ADR-081: notes are annotations outside assessment by construction. They never enter the node
	// set, so no pack's `n`, `g.nodes`, `nodes(type)` or `has(type)` can see one (IMP-001 cannot fire on
	// a text box). Validation already refuses an edge to or from a note.
	nodes := model.AssessedNodes(a)
	g.nodes = make([]any, 0, len(nodes))
	for i := range nodes {
		n := &nodes[i]
		kinds := groupKinds[n.ID]
		if kinds == nil {
			kinds = []string{}
		}
		ids := groupIDs[n.ID]
		if ids == nil {
			ids = []string{}
		}
		workflows := workflowIDs[n.ID]
		if workflows == nil {
			workflows = []string{}
		}
		// description is model-authored free text. It is projected so rules can assess what the
		// architect declared a component does (docs/03 AGT-002); conditions read it only through
		// RE2 `matches`, which is linear-time and cannot be made to backtrack.
		m := map[string]any{
			"id": n.ID, "type": n.Type, "name": n.Name, "layer": n.Layer, "zone": n.Zone, "source": n.Source,
			"description": n.Description, "external_ref": n.ExternalRef,
			"attrs": derivedAttrs(normAttrs(n.Attrs)), "groups": kinds, "group_ids": ids,
			"workflow_ids": workflows,
			// Schema 1.1 (ADR-047 §1): the identity the node runs as (attrs.identity_id resolved), so a
			// condition reads n.identity.issuer or attr(n.identity, "credential_ttl", -1). A node without one
			// gets the empty identity (every field "", attrs empty), never a missing key.
			"identity": identityValue(a.IdentityOf(n)),
		}
		g.nodes = append(g.nodes, m)
		g.nodeByID[n.ID] = m
		g.nodesByType[n.Type] = append(g.nodesByType[n.Type], m)
	}
	g.edges = make([]any, 0, len(a.Edges))
	for i := range a.Edges {
		e := &a.Edges[i]
		m := map[string]any{
			"id": e.ID, "from": g.endpoint(e.From), "to": g.endpoint(e.To), "kind": e.Kind, "label": e.Label,
			"protocol": e.Protocol, "auth": e.Auth, "encryption": e.Encryption, "data_class": e.DataClass,
			// Schema 1.1: protocol is an enum; protocol_text is the spelling the author wrote (the 1.0
			// free text the migration mapped, read back from x_migrated_from, else the enum value), so a
			// name match such as DRF-004 still sees "ftp" where protocol says "other". Projection only.
			"protocol_text": e.ProtocolText(),
			"attrs":         normAttrs(e.Attrs),
		}
		g.edges = append(g.edges, m)
		g.edgeByID[e.ID] = m
		g.edgesByKind[e.Kind] = append(g.edgesByKind[e.Kind], m)
		g.outEdges[e.From] = append(g.outEdges[e.From], m)
		g.inEdges[e.To] = append(g.inEdges[e.To], m)
		g.outAdj[e.From] = append(g.outAdj[e.From], e.To)
		g.inAdj[e.To] = append(g.inAdj[e.To], e.From)
		switch e.Kind {
		case "reads", "subscribes":
			g.addData(e.To, e.From)
		case "calls":
			g.addData(e.From, e.To)
			g.addData(e.To, e.From)
		case "authenticates":
			// identity assertions, not data
		default: // writes, publishes, flows, delegates, executes
			g.addData(e.From, e.To)
		}
	}
	return g
}

// endpoint returns the node map for an edge endpoint, or a placeholder for dangling references
// (validation forbids them, but rules must never panic on bad data).
func (g *graphVal) endpoint(id string) map[string]any {
	if m, ok := g.nodeByID[id]; ok {
		return m
	}
	return map[string]any{"id": id, "type": "", "name": "", "layer": "", "zone": "", "source": "",
		"description": "", "external_ref": "", "attrs": map[string]any{}, "groups": []string{}, "group_ids": []string{},
		"workflow_ids": []string{}, "identity": identityValue(nil)}
}

// groupValue projects a group for CEL (schema 1.2, ADR-093 FS-06): id, kind, name, parent, the member
// node ids and the attributes, so a condition reads a workflow's bounds with attr(w, "max_iterations",
// -1) and its members with `n.id in w.node_ids`. A node's own memberships stay n.groups (kinds) and
// n.group_ids, workflows excepted (n.workflow_ids, see buildGraph). Notes are outside assessment (ADR-081), so a note's id is left out of node_ids.
func groupValue(grp *model.Group, notes map[string]bool) map[string]any {
	ids := make([]any, 0, len(grp.NodeIDs))
	for _, id := range grp.NodeIDs {
		if !notes[id] {
			ids = append(ids, id)
		}
	}
	return map[string]any{"id": grp.ID, "kind": grp.Kind, "name": grp.Name, "parent": grp.Parent,
		"node_ids": ids, "attrs": normAttrs(grp.Attrs)}
}

// identityValue projects an identity entity (schema 1.1) for CEL: every member at the top level
// ("" or 0 when not declared, so a condition never hits a missing key) and the declared members
// again under attrs, so attr(n.identity, "credential_ttl", -1) tells "not declared" from 0. x_
// extension values are left out: rules never read them (ADR-040 §5). The one exception is the
// boolean `migrated`: true when the 1.0 → 1.1 migration created the entity (attrs.x_migrated_from,
// docs/02 §8), so a rule tells "the architect left this fact out" from "the 1.0 model could not
// say it" without reading the id (an id prefix is not reserved by the schema).
func identityValue(id *model.Identity) map[string]any {
	declared := map[string]any{}
	str := func(k, v string) string {
		if v != "" {
			declared[k] = v
		}
		return v
	}
	num := func(k string, v *int64) int64 {
		if v == nil {
			return 0
		}
		declared[k] = *v
		return *v
	}
	if id == nil {
		id = &model.Identity{}
	}
	return map[string]any{
		"id": id.ID, "name": str("name", id.Name), "kind": str("kind", id.Kind), "ref": str("ref", id.Ref),
		"issuer": str("issuer", id.Issuer), "credential_type": str("credential_type", id.CredentialType),
		"credential_ttl": num("credential_ttl", id.CredentialTTL), "rotation_days": num("rotation_days", id.RotationDays),
		"sponsor": str("sponsor", id.Sponsor), "owner": str("owner", id.Owner), "blueprint": str("blueprint", id.Blueprint),
		"registry": str("registry", id.Registry), "federation": str("federation", id.Federation),
		"trust_domain": str("trust_domain", id.TrustDomain), "attrs": declared,
		"migrated": identityMigrated(id),
	}
}

// identityMigrated reports whether the identity carries the migration's x_migrated_from note.
func identityMigrated(id *model.Identity) bool {
	v, ok := id.Attrs[model.MigratedFromAttr]
	if !ok {
		return false
	}
	s, isStr := v.(string)
	return !isStr || strings.TrimSpace(s) != ""
}

func (g *graphVal) ConvertToNative(t reflect.Type) (any, error) {
	return nil, fmt.Errorf("graph cannot be converted to %v", t)
}

func (g *graphVal) ConvertToType(t ref.Type) ref.Val {
	switch t {
	case types.TypeType:
		return graphType
	case types.StringType:
		return types.String("graph(" + g.id + ")")
	}
	return types.NewErr("graph cannot be converted to %s", t.TypeName())
}

func (g *graphVal) Equal(o ref.Val) ref.Val {
	og, ok := o.(*graphVal)
	return types.Bool(ok && og == g)
}

func (g *graphVal) Type() ref.Type { return graphType }
func (g *graphVal) Value() any     { return g }

// Get implements traits.Indexer so `g.id`, `g.name`, `g.attrs`, `g.nodes`, `g.edges`,
// `g.identities` (schema 1.1) and `g.groups` (schema 1.2) resolve.
func (g *graphVal) Get(index ref.Val) ref.Val {
	key, ok := index.(types.String)
	if !ok {
		return types.NewErr("graph fields are addressed by name")
	}
	switch string(key) {
	case "id":
		return types.String(g.id)
	case "name":
		return types.String(g.name)
	case "attrs":
		return types.NewStringInterfaceMap(types.DefaultTypeAdapter, g.attrs)
	case "nodes":
		return types.NewDynamicList(types.DefaultTypeAdapter, g.nodes)
	case "edges":
		return types.NewDynamicList(types.DefaultTypeAdapter, g.edges)
	case "identities":
		return types.NewDynamicList(types.DefaultTypeAdapter, g.identities)
	case "groups":
		return types.NewDynamicList(types.DefaultTypeAdapter, g.groups)
	}
	return types.NewErr("no such graph field %q", string(key))
}

func (g *graphVal) has(nodeType string) ref.Val {
	return types.Bool(len(g.nodesByType[nodeType]) > 0)
}

func (g *graphVal) nodesOf(nodeType string) ref.Val {
	return listVal(g.nodesByType[nodeType])
}

func (g *graphVal) edgesOf(kind string) ref.Val {
	return listVal(g.edgesByKind[kind])
}

// inOf returns the inbound edges of nodeID with the given kind ("" or "*" = any kind).
func (g *graphVal) inOf(nodeID, kind string) ref.Val {
	return listVal(filterKind(g.inEdges[nodeID], kind))
}

// outOf returns the outbound edges of nodeID with the given kind ("" or "*" = any kind).
func (g *graphVal) outOf(nodeID, kind string) ref.Val {
	return listVal(filterKind(g.outEdges[nodeID], kind))
}

func filterKind(edges []any, kind string) []any {
	if kind == "" || kind == "*" {
		return edges
	}
	out := make([]any, 0, len(edges))
	for _, e := range edges {
		if m, ok := e.(map[string]any); ok && m["kind"] == kind {
			out = append(out, e)
		}
	}
	return out
}

func listVal(items []any) ref.Val {
	if items == nil {
		items = []any{}
	}
	return types.NewDynamicList(types.DefaultTypeAdapter, items)
}

func (g *graphVal) reachableVal(from, to string) ref.Val {
	return types.Bool(g.reachable(from, to))
}

// reachable reports whether `to` is reachable from `from` over zero or more directed edges
// (a node always reaches itself).
func (g *graphVal) reachable(from, to string) bool {
	if _, ok := g.nodeByID[from]; !ok {
		return false
	}
	return g.forward(from)[to]
}

// pathThrough reports whether some directed walk from→to passes through a node of type via.
// The endpoints count: a walk agent→human_step with via=human_step is satisfied by the endpoint
// (so a rule's own patch output, e.g. AI-003's inserted approval step, evaluates clean).
func (g *graphVal) pathThrough(from, to, via string) bool {
	key := [3]string{from, to, via}
	if v, ok := g.pathCache[key]; ok {
		return v
	}
	res := false
	if _, ok := g.nodeByID[from]; ok {
		f := g.forward(from)
		if f[to] {
			b := g.backward(to)
			for _, item := range g.nodesByType[via] {
				m, _ := item.(map[string]any)
				id, _ := m["id"].(string)
				if f[id] && b[id] {
					res = true
					break
				}
			}
		}
	}
	g.pathCache[key] = res
	return res
}

// pathAvoidingType reports whether some directed walk from→to never enters a node of type avoid. from itself is
// not checked; to is (a walk that ends on the avoided type does not avoid it). A node reaches itself.
func (g *graphVal) pathAvoidingType(from, to, avoid string) bool {
	return g.avoidingWalk(from, "type:"+avoid, func(m map[string]any) bool { return m["type"] == avoid })[to]
}

// pathAvoidingAttr reports whether some directed walk from→to never enters a node whose attribute attr is true —
// e.g. a command path on which no node declares command_validation. Endpoints as in pathAvoiding.
func (g *graphVal) pathAvoidingAttr(from, to, attr string) bool {
	return g.avoidingWalk(from, "attr:"+attr, func(m map[string]any) bool {
		attrs, _ := m["attrs"].(map[string]any)
		v, _ := attrs[attr].(bool)
		return v
	})[to]
}

func (g *graphVal) avoidingWalk(from, key string, blocked func(map[string]any) bool) map[string]bool {
	if _, ok := g.nodeByID[from]; !ok {
		return map[string]bool{}
	}
	ck := [2]string{from, key}
	if s, ok := g.avoid[ck]; ok {
		return s
	}
	seen := map[string]bool{from: true}
	queue := []string{from}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, next := range g.outAdj[cur] {
			if seen[next] {
				continue
			}
			if m, ok := g.nodeByID[next]; !ok || blocked(m) {
				continue
			}
			seen[next] = true
			queue = append(queue, next)
		}
	}
	g.avoid[ck] = seen
	return seen
}

// writersIntoVal lists, in model order, the ids of the nodes with a writes or executes edge into a node of the type
// — for "edge_device", the machine writers the OT pack starts from. Cached per type.
func (g *graphVal) writersIntoVal(targetType string) ref.Val {
	if w, ok := g.writers[targetType]; ok {
		return listVal(w)
	}
	seen := map[string]bool{}
	for _, item := range g.edges {
		e, _ := item.(map[string]any)
		if e["kind"] != "writes" && e["kind"] != "executes" {
			continue
		}
		to, _ := e["to"].(map[string]any)
		from, _ := e["from"].(map[string]any)
		if to["type"] == targetType {
			id, _ := from["id"].(string)
			seen[id] = true
		}
	}
	var out []any
	for _, item := range g.nodes {
		m, _ := item.(map[string]any)
		if id, _ := m["id"].(string); seen[id] {
			out = append(out, id)
		}
	}
	g.writers[targetType] = out
	return listVal(out)
}

// upstreamAvoidingAttrVal lists, in model order, the nodes c (as node values) for which g.pathAvoidingAttr(c, nodeID,
// attr) holds: nodeID itself and every node with a walk to it whose later nodes lack attr. One reverse walk replaces a
// forward walk per candidate.
func (g *graphVal) upstreamAvoidingAttrVal(nodeID, attr string) ref.Val {
	start, ok := g.nodeByID[nodeID]
	if !ok {
		return listVal(nil)
	}
	has := func(m map[string]any) bool {
		attrs, _ := m["attrs"].(map[string]any)
		v, _ := attrs[attr].(bool)
		return v
	}
	sources := map[string]bool{nodeID: true}
	if !has(start) {
		open := map[string]bool{nodeID: true}
		queue := []string{nodeID}
		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			for _, p := range g.inAdj[cur] {
				sources[p] = true
				if m, ok := g.nodeByID[p]; ok && !open[p] && !has(m) {
					open[p] = true
					queue = append(queue, p)
				}
			}
		}
	}
	var out []any
	for _, item := range g.nodes {
		m, _ := item.(map[string]any)
		if id, _ := m["id"].(string); sources[id] {
			out = append(out, m)
		}
	}
	return listVal(out)
}

// graphUpstreamAvoiding binds g.upstreamAvoiding(id, types, kinds), g.upstreamAvoiding(id, types, kinds,
// needFunctions) and g.upstreamAvoiding(id, types, kinds, attrTypes, attr) (ADR-088 §1 and Amendments).
func graphUpstreamAvoiding(args ...ref.Val) ref.Val {
	if len(args) != 4 && len(args) != 5 && len(args) != 6 {
		return types.NewErr("upstreamAvoiding expects 3, 4 or 5 arguments")
	}
	g, ok := args[0].(*graphVal)
	if !ok {
		return types.NewErr("receiver is not the graph (got %s)", args[0].Type().TypeName())
	}
	id, ok := args[1].(types.String)
	if !ok {
		return types.NewErr("upstreamAvoiding: the node id must be a string")
	}
	blockedTypes, err := stringList(args[2])
	if err != nil {
		return types.NewErr("upstreamAvoiding: types: %v", err)
	}
	blockedKinds, err := stringList(args[3])
	if err != nil {
		return types.NewErr("upstreamAvoiding: kinds: %v", err)
	}
	if len(args) == 5 {
		needFunctions, err := stringList(args[4])
		if err != nil || len(needFunctions) == 0 {
			return types.NewErr("upstreamAvoiding: needFunctions must be a non-empty list of strings")
		}
		return listVal(g.upstreamAvoidingFunctions(string(id), blockedTypes, blockedKinds, needFunctions))
	}
	var attrTypes []string
	blockAttr := ""
	if len(args) == 6 {
		if attrTypes, err = stringList(args[4]); err != nil || len(attrTypes) == 0 {
			return types.NewErr("upstreamAvoiding: attrTypes must be a non-empty list of strings")
		}
		a, ok := args[5].(types.String)
		if !ok || a == "" {
			return types.NewErr("upstreamAvoiding: the blocking attribute must be a non-empty string")
		}
		blockAttr = string(a)
	}
	return listVal(g.upstreamAvoiding(string(id), blockedTypes, blockedKinds, attrTypes, blockAttr))
}

// stringList converts a CEL list of strings.
func stringList(v ref.Val) ([]string, error) {
	l, ok := v.(traits.Lister)
	if !ok {
		return nil, fmt.Errorf("expected a list of strings (got %s)", v.Type().TypeName())
	}
	n, ok := l.Size().(types.Int)
	if !ok {
		return nil, fmt.Errorf("list size unavailable")
	}
	out := make([]string, 0, int(n))
	for i := types.Int(0); i < n; i++ {
		s, ok := l.Get(i).(types.String)
		if !ok {
			return nil, fmt.Errorf("element %d is not a string", i)
		}
		out = append(out, string(s))
	}
	return out, nil
}

// upstreamAvoiding lists, in model order, the nodes c (as node values) from which nodeID is reachable by a directed
// walk that never enters a blocked node: nodeID itself and every node with a walk to it whose later nodes (nodeID
// included) are all unblocked. A node is blocked when its type is in blockedTypes and, when blockedKinds is not
// empty, its attrs.kind is in blockedKinds (a gateway of no declared kind is then not blocked), or when its type is
// in attrTypes and its boolean attrs[blockAttr] is true (blockAttr "" blocks nothing). c itself is not checked, so a control can be its own source (a rule
// that reads the source's type or layer must exclude the controls itself, as NET-005 does); a blocked nodeID is only
// its own source. It generalises upstreamAvoidingAttr: one reverse walk answers "does some walk from a source of the
// rule's types reach this hop around every control", which is how the path rules of docs/03 read all paths (ADR-088 §1).
func (g *graphVal) upstreamAvoiding(nodeID string, blockedTypes, blockedKinds, attrTypes []string, blockAttr string) []any {
	key := [5]string{nodeID, strings.Join(blockedTypes, "\x00"), strings.Join(blockedKinds, "\x00"), strings.Join(attrTypes, "\x00"), blockAttr}
	return g.upstreamWalk(nodeID, key, func(m map[string]any) bool {
		t, _ := m["type"].(string)
		if blockAttr != "" && slices.Contains(attrTypes, t) {
			attrs, _ := m["attrs"].(map[string]any)
			if v, _ := attrs[blockAttr].(bool); v {
				return true
			}
		}
		if !slices.Contains(blockedTypes, t) {
			return false
		}
		if len(blockedKinds) == 0 {
			return true
		}
		attrs, _ := m["attrs"].(map[string]any)
		k, _ := attrs["kind"].(string)
		return slices.Contains(blockedKinds, k)
	})
}

// upstreamAvoidingFunctions is upstreamAvoiding where a node of blockedTypes blocks only when it credits the hop
// (ADR-088 Amendments, B2b "functions decide when declared"): it declares every one of needFunctions in its
// attrs.functions, or it declares none and its attrs.kind is in blockedKinds (any kind when blockedKinds is empty; a
// node of no declared kind is then credited only by an empty blockedKinds). A node of blockedTypes that does not
// credit the hop is walked through like any other, so the walk is exact at any chain length: the path rules no
// longer unroll it to a fixed depth in CEL.
func (g *graphVal) upstreamAvoidingFunctions(nodeID string, blockedTypes, blockedKinds, needFunctions []string) []any {
	// The fourth key slot names the form, so a function-aware walk never shares a cache entry with an attr walk.
	key := [5]string{nodeID, strings.Join(blockedTypes, "\x00"), strings.Join(blockedKinds, "\x00"), "\x01functions", strings.Join(needFunctions, "\x00")}
	return g.upstreamWalk(nodeID, key, func(m map[string]any) bool {
		t, _ := m["type"].(string)
		if !slices.Contains(blockedTypes, t) {
			return false
		}
		attrs, _ := m["attrs"].(map[string]any)
		if declared := declaredFunctions(attrs["functions"]); len(declared) > 0 {
			for _, f := range needFunctions {
				if !slices.Contains(declared, f) {
					return false
				}
			}
			return true
		}
		if len(blockedKinds) == 0 {
			return true
		}
		k, _ := attrs["kind"].(string)
		return slices.Contains(blockedKinds, k)
	})
}

// DerivedCredentialBrokerage is the boolean attribute the loader derives on a node whose functions[] (schema 1.1,
// gateway.functions) declares credential_brokerage (ADR-088 D1, WIS-005's second branch): a gateway that injects the
// secret per call is a broker on the path, so g.pathAvoidingAttr(from, to, "credential_brokerage") walks around it as
// g.pathAvoidingType walks around a credential_broker node. The model schema has no such node attribute; a value
// already present (an extension the schema does not reject) is kept.
const DerivedCredentialBrokerage = "credential_brokerage" // #nosec G101 -- an attribute name, not a credential

// derivedAttrs adds the attributes the loader derives from declared ones to a node's projected attrs (in place).
func derivedAttrs(attrs map[string]any) map[string]any {
	if _, declared := attrs[DerivedCredentialBrokerage]; !declared && slices.Contains(declaredFunctions(attrs["functions"]), "credential_brokerage") {
		attrs[DerivedCredentialBrokerage] = true
	}
	return attrs
}

// declaredFunctions reads attrs.functions (a list of strings once normalised; anything else declares none).
func declaredFunctions(v any) []string {
	var out []string
	switch l := v.(type) {
	case []any:
		for _, x := range l {
			if s, ok := x.(string); ok && s != "" {
				out = append(out, s)
			}
		}
	case []string:
		for _, s := range l {
			if s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

// upstreamWalk is the reverse walk behind both forms of upstreamAvoiding, cached under key: nodeID and every node
// with a directed walk to it whose later nodes (nodeID included) are all unblocked; a blocked nodeID is only its own
// source. The result lists node values in model order.
func (g *graphVal) upstreamWalk(nodeID string, key [5]string, blocked func(map[string]any) bool) []any {
	start, ok := g.nodeByID[nodeID]
	if !ok {
		return nil
	}
	if out, ok := g.upAvoid[key]; ok {
		return out
	}
	sources := map[string]bool{nodeID: true}
	if !blocked(start) {
		open := map[string]bool{nodeID: true}
		queue := []string{nodeID}
		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			for _, p := range g.inAdj[cur] {
				sources[p] = true
				if m, ok := g.nodeByID[p]; ok && !open[p] && !blocked(m) {
					open[p] = true
					queue = append(queue, p)
				}
			}
		}
	}
	out := []any{}
	for _, item := range g.nodes {
		m, _ := item.(map[string]any)
		if id, _ := m["id"].(string); sources[id] {
			out = append(out, m)
		}
	}
	g.upAvoid[key] = out
	return out
}

func (g *graphVal) addData(from, to string) {
	g.dataAdj[from] = append(g.dataAdj[from], to)
	g.dataRev[to] = append(g.dataRev[to], from)
}

// upstream returns the nodes whose data reaches id (including id), cached.
func (g *graphVal) upstream(id string) map[string]bool {
	if s, ok := g.dataBwd[id]; ok {
		return s
	}
	s := bfs(id, g.dataRev)
	g.dataBwd[id] = s
	return s
}

// dataSourcesVal lists, in model order, the ids of the nodes of a layer ("" = any) whose data reaches nodeID; the
// node itself is not its own source.
func (g *graphVal) dataSourcesVal(nodeID, layer string) ref.Val {
	if _, ok := g.nodeByID[nodeID]; !ok {
		return listVal(nil)
	}
	up := g.upstream(nodeID)
	var out []any
	for _, item := range g.nodes {
		m, _ := item.(map[string]any)
		id, _ := m["id"].(string)
		if id != nodeID && up[id] && (layer == "" || m["layer"] == layer) {
			out = append(out, id)
		}
	}
	return listVal(out)
}

// dataZonesVal lists the distinct non-empty zones of those sources, in model order: how many zones feed a store.
func (g *graphVal) dataZonesVal(nodeID, layer string) ref.Val {
	if _, ok := g.nodeByID[nodeID]; !ok {
		return listVal(nil)
	}
	up := g.upstream(nodeID)
	seen := map[string]bool{}
	var out []any
	for _, item := range g.nodes {
		m, _ := item.(map[string]any)
		id, _ := m["id"].(string)
		zone, _ := m["zone"].(string)
		if id == nodeID || !up[id] || zone == "" || seen[zone] || (layer != "" && m["layer"] != layer) {
			continue
		}
		seen[zone] = true
		out = append(out, zone)
	}
	return listVal(out)
}

func (g *graphVal) dataFlowsVal(from, to string) ref.Val {
	return types.Bool(g.dataFlows(from, to))
}

// dataFlows reports whether data can move from→to: along writes, publishes, flows, delegates and executes, against
// reads and subscribes (the reader pulls from the target), both ways along calls (request and response);
// authenticates carries no data. A node's data reaches itself.
func (g *graphVal) dataFlows(from, to string) bool {
	if _, ok := g.nodeByID[from]; !ok {
		return false
	}
	s, ok := g.dataFwd[from]
	if !ok {
		s = bfs(from, g.dataAdj)
		g.dataFwd[from] = s
	}
	return s[to]
}

// forward returns the set of nodes reachable from id (including id), cached.
func (g *graphVal) forward(id string) map[string]bool {
	if s, ok := g.fwd[id]; ok {
		return s
	}
	s := bfs(id, g.outAdj)
	g.fwd[id] = s
	return s
}

// backward returns the set of nodes that can reach id (including id), cached.
func (g *graphVal) backward(id string) map[string]bool {
	if s, ok := g.bwd[id]; ok {
		return s
	}
	s := bfs(id, g.inAdj)
	g.bwd[id] = s
	return s
}

func bfs(start string, adj map[string][]string) map[string]bool {
	seen := map[string]bool{start: true}
	queue := []string{start}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, next := range adj[cur] {
			if !seen[next] {
				seen[next] = true
				queue = append(queue, next)
			}
		}
	}
	return seen
}

func (g *graphVal) regimeVal(code string) ref.Val {
	return types.Bool(g.regimes[CanonRegime(code)])
}

func (g *graphVal) requiredVal(code string) ref.Val {
	return types.Int(g.table.Required(code, g.policy))
}

// cappedVal is capped(code): the ceiling PolicyTable.Cap returns, -1 when neither the table nor the
// tenant names the key (the rule supplies its own default).
func (g *graphVal) cappedVal(code string) ref.Val {
	limit, ok := g.table.Cap(code, g.policy)
	if !ok {
		return types.Int(-1)
	}
	return types.Int(limit)
}

// ---- value normalisation ------------------------------------------------------------------------

// normAttrs copies attrs with JSON/YAML numbers normalised: integral floats become int64 so that
// `attr(n,"retention_days",0) < required("retention_days")` compares int with int at runtime.
func normAttrs(in model.Attrs) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = normValue(v)
	}
	return out
}

func normValue(v any) any {
	switch x := v.(type) {
	case nil:
		return nil
	case float64:
		if x == math.Trunc(x) && math.Abs(x) < 1<<53 {
			return int64(x)
		}
		return x
	case float32:
		return normValue(float64(x))
	case int:
		return int64(x)
	case int32:
		return int64(x)
	case uint:
		return int64(x) // #nosec G115 -- attrs are small model numbers
	case uint32:
		return int64(x)
	case uint64:
		if x <= math.MaxInt64 {
			return int64(x)
		}
		return float64(x)
	case json.Number:
		if i, err := x.Int64(); err == nil {
			return i
		}
		if f, err := x.Float64(); err == nil {
			return normValue(f)
		}
		return x.String()
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			out[k] = normValue(val)
		}
		return out
	case model.Attrs:
		return normAttrs(x)
	case []any:
		out := make([]any, len(x))
		for i, val := range x {
			out[i] = normValue(val)
		}
		return out
	case []string:
		out := make([]any, len(x))
		for i, val := range x {
			out[i] = val
		}
		return out
	}
	return v
}

// nativeOf converts a CEL value back into a plain Go value (strings, int64, float64, bool, lists, maps).
func nativeOf(v ref.Val) any {
	switch x := v.(type) {
	case types.String:
		return string(x)
	case types.Bool:
		return bool(x)
	case types.Int:
		return int64(x)
	case types.Uint:
		return uint64(x)
	case types.Double:
		return float64(x)
	case types.Null:
		return nil
	case traits.Lister:
		it := x.Iterator()
		var out []any
		for it.HasNext() == types.True {
			out = append(out, nativeOf(it.Next()))
		}
		if out == nil {
			out = []any{}
		}
		return out
	case traits.Mapper:
		if m, ok := x.Value().(map[string]any); ok {
			return normValue(m)
		}
		out := map[string]any{}
		it := x.Iterator()
		for it.HasNext() == types.True {
			k := it.Next()
			out[fmt.Sprint(nativeOf(k))] = nativeOf(x.Get(k))
		}
		return out
	case *graphVal:
		return x.id
	}
	return v.Value()
}

// stringOf renders a CEL value for message templates.
func stringOf(v ref.Val) string {
	switch x := v.(type) {
	case types.String:
		return string(x)
	case types.Null:
		return ""
	case *graphVal:
		return x.id
	case traits.Lister, traits.Mapper:
		b, err := json.Marshal(nativeOf(v))
		if err != nil {
			return fmt.Sprint(v.Value())
		}
		return string(b)
	}
	return fmt.Sprint(nativeOf(v))
}

// regimeSet canonicalises the enabled regimes.
func regimeSet(codes []string) map[string]bool {
	out := make(map[string]bool, len(codes))
	for _, c := range codes {
		if cc := CanonRegime(c); cc != "" {
			out[cc] = true
		}
	}
	return out
}

var regimeAliases = map[string]string{
	"ISG": "CH-ISG", "CH_ISG": "CH-ISG", "ISO27001": "ISO", "ISO-27001": "ISO", "ISO42001": "ISO", "ISO-42001": "ISO",
	"CO": "CH-CO", "CH_CO": "CH-CO", "AI-ACT": "AIACT", "AI_ACT": "AIACT",
	"21CFR11": "FDA", "CFR11": "FDA", "PART11": "FDA", "EUGMP": "EU-GMP", "EU_GMP": "EU-GMP", "GMP": "EU-GMP",
	"MACHINERY": "MR", "MACHREG": "MR", "MVO": "MR", "GAMP5": "GAMP", "GAMP-5": "GAMP", "GAMP_5": "GAMP",
}

// CanonRegime normalises regime codes (upper-case, aliases ISG↔CH-ISG, ISO27001/ISO42001→ISO).
func CanonRegime(code string) string {
	c := strings.ToUpper(strings.TrimSpace(code))
	if alias, ok := regimeAliases[c]; ok {
		return alias
	}
	return c
}
