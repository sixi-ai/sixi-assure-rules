package rules

import (
	"slices"
	"sort"

	"github.com/sixi-ai/sixi-assure-rules/model"
)

// Framework-native remediation at render time (ADR-093 decision 9, docs/18 WS-M M4). A finding names elements; the
// framework whose sentence it shows is the `agent.framework` of the agent those elements belong to:
//
//   - an agent: its own framework;
//   - an edge: its agent ends read together (the one framework they declare; when both ends are agents that declare
//     different frameworks, none, since a rule may remediate either end), else the nearest agent of either end;
//   - any other node (a tool, an MCP server, an agent memory, the app or API an agent is hosted on): the agents hosted
//     on it, else the nearest agents over the drawn edges (one hop, then two), whichever direction they point;
//   - the architecture (a graph rule): every agent of the model.
//
// The ids are read in order and the first that settles one framework decides. When the agents found at the nearest
// distance declare different frameworks, or none, nothing is chosen and the generic remediation applies: a sentence
// for the wrong framework is worse than none.

// frameworkHops bounds the walk from a non-agent element to its nearest agent.
const frameworkHops = 2

// FrameworkLabels are the display names of the schema 1.2 frameworks, for reports and the web.
var FrameworkLabels = map[string]string{
	"langgraph":             "LangGraph",
	"ms_agent_framework":    "Microsoft Agent Framework",
	"foundry_agent_service": "Azure AI Foundry Agent Service",
	"google_adk":            "Google ADK",
	"openai_agents":         "OpenAI Agents SDK",
	"crewai":                "CrewAI",
	"other":                 "another framework",
}

// FrameworkLabel is the display name of a framework value (the value itself when it has none).
func FrameworkLabel(framework string) string {
	if l, ok := FrameworkLabels[framework]; ok {
		return l
	}
	return framework
}

// FrameworkOf returns the agent framework a finding on these element ids speaks to, "" when none is settled.
func FrameworkOf(a *model.Architecture, ids []string) string {
	if a == nil {
		return ""
	}
	nodes := make(map[string]*model.Node, len(a.Nodes))
	for i := range a.Nodes {
		nodes[a.Nodes[i].ID] = &a.Nodes[i]
	}
	edges := make(map[string]*model.Edge, len(a.Edges))
	adj := map[string][]string{}
	for i := range a.Edges {
		e := &a.Edges[i]
		edges[e.ID] = e
		adj[e.From] = append(adj[e.From], e.To)
		adj[e.To] = append(adj[e.To], e.From)
	}
	for _, id := range ids {
		if fw := frameworkOfElement(a, nodes, edges, adj, id); fw != "" {
			return fw
		}
	}
	return ""
}

func frameworkOfElement(a *model.Architecture, nodes map[string]*model.Node, edges map[string]*model.Edge,
	adj map[string][]string, id string) string {
	if id == a.ID {
		agents := []string{}
		for i := range a.Nodes {
			if a.Nodes[i].Type == "agent" {
				agents = append(agents, a.Nodes[i].ID)
			}
		}
		return oneFramework(nodes, agents)
	}
	if e, ok := edges[id]; ok {
		agents := []string{}
		for _, end := range []string{e.From, e.To} {
			if n := nodes[end]; n != nil && n.Type == "agent" {
				agents = append(agents, end)
			}
		}
		if len(agents) > 0 {
			// Both ends read together: a delegation between agents of two frameworks settles none, since the
			// rule may remediate either end (FW-006 patches the delegate, e.to).
			switch fws := declaredFrameworks(nodes, agents); len(fws) {
			case 1:
				return fws[0]
			case 2:
				return ""
			}
		}
		for _, end := range []string{e.From, e.To} {
			if fw := nearestFramework(nodes, adj, end); fw != "" {
				return fw
			}
		}
		return ""
	}
	n := nodes[id]
	if n == nil {
		return ""
	}
	if n.Type == "agent" {
		return n.Attrs.String("framework", "")
	}
	hosted := []string{}
	for i := range a.Nodes {
		if a.Nodes[i].Type == "agent" && a.Nodes[i].Attrs.String("hosted_on", "") == id {
			hosted = append(hosted, a.Nodes[i].ID)
		}
	}
	if len(hosted) > 0 {
		return oneFramework(nodes, hosted)
	}
	return nearestFramework(nodes, adj, id)
}

// nearestFramework walks the drawn edges (both directions) from a node and returns the one framework the agents at
// the nearest distance that has any declare, "" when they disagree or none is found within frameworkHops.
func nearestFramework(nodes map[string]*model.Node, adj map[string][]string, start string) string {
	if n := nodes[start]; n != nil && n.Type == "agent" {
		return n.Attrs.String("framework", "")
	}
	seen := map[string]bool{start: true}
	frontier := []string{start}
	for hop := 0; hop < frameworkHops && len(frontier) > 0; hop++ {
		next := []string{}
		agents := []string{}
		for _, id := range frontier {
			for _, to := range adj[id] {
				if seen[to] {
					continue
				}
				seen[to] = true
				next = append(next, to)
				if n := nodes[to]; n != nil && n.Type == "agent" {
					agents = append(agents, to)
				}
			}
		}
		if len(agents) > 0 {
			return oneFramework(nodes, agents)
		}
		sort.Strings(next)
		frontier = next
	}
	return ""
}

// declaredFrameworks returns the distinct frameworks the listed agents declare, in order.
func declaredFrameworks(nodes map[string]*model.Node, agentIDs []string) []string {
	found := []string{}
	for _, id := range agentIDs {
		if n := nodes[id]; n != nil {
			if fw := n.Attrs.String("framework", ""); fw != "" && !slices.Contains(found, fw) {
				found = append(found, fw)
			}
		}
	}
	return found
}

// oneFramework is the framework every listed agent that declares one shares, "" when they disagree or none declares.
func oneFramework(nodes map[string]*model.Node, agentIDs []string) string {
	found := declaredFrameworks(nodes, agentIDs)
	if len(found) != 1 {
		return ""
	}
	return found[0]
}

// FrameworkRemediationFor returns the framework-native remediation of a rule for a finding on these element ids of
// the architecture, false when the elements settle no framework or the rule has no sentence for it (the generic
// remediation then stands alone).
func (c *Catalog) FrameworkRemediationFor(ruleID string, a *model.Architecture, ids []string) (FrameworkRemediation, bool) {
	if c == nil {
		return FrameworkRemediation{}, false
	}
	r, ok := c.Rule(ruleID)
	if !ok || len(r.RemediationByFramework) == 0 {
		return FrameworkRemediation{}, false
	}
	return r.RemediationFor(FrameworkOf(a, ids))
}
