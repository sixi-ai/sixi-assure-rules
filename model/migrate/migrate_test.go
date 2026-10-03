package migrate

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStepsAreOrdered(t *testing.T) {
	t.Parallel()
	list := Steps()
	require.NotEmpty(t, list)
	assert.Equal(t, Unversioned, list[0].From, "the first step starts at the unversioned schema")
	assert.Equal(t, Current, list[len(list)-1].To, "the last step ends at the current schema")
	seen := map[string]bool{}
	for i, s := range list {
		assert.True(t, Valid(s.From) && Valid(s.To), "step %d versions are MAJOR.MINOR", i)
		assert.Equal(t, -1, compare(s.From, s.To), "step %d moves forward", i)
		assert.False(t, seen[s.From], "one step per from-version (%s)", s.From)
		seen[s.From] = true
		assert.NotEmpty(t, s.Note, "step %d has its docs/02 §Versions line", i)
		require.NotNil(t, s.Fn)
		if i > 0 {
			assert.Equal(t, list[i-1].To, s.From, "step %d continues where step %d ended", i, i-1)
		}
	}
}

func TestVersion(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		raw  string
		want string
		err  error
	}{
		{"absent means 0.9", `{"id":"a"}`, "0.9", nil},
		{"explicit 0.9", `{"schema_version":"0.9"}`, "0.9", nil},
		{"an older version", `{"schema_version":"1.0"}`, "1.0", nil},
		{"the previous minor", `{"schema_version":"1.1"}`, "1.1", nil},
		{"current", `{"schema_version":"1.2"}`, "1.2", nil},
		{"well-formed future", `{"schema_version":"12.3"}`, "12.3", nil},
		{"null", `{"schema_version":null}`, "", ErrInvalidVersion},
		{"number", `{"schema_version":1.0}`, "", ErrInvalidVersion},
		{"three parts", `{"schema_version":"1.0.0"}`, "", ErrInvalidVersion},
		{"leading zero", `{"schema_version":"01.0"}`, "", ErrInvalidVersion},
		{"free text", `{"schema_version":"latest"}`, "", ErrInvalidVersion},
		{"oversized part", `{"schema_version":"1.12345"}`, "", ErrInvalidVersion},
		{"array", `[]`, "", ErrNotObject},
		{"json null", `null`, "", ErrNotObject},
		{"malformed", `{"schema_version":`, "", ErrNotObject},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := Version([]byte(tc.raw))
			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestUpgrade(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		raw      string
		want     string
		from     string
		err      error
		contains string
	}{
		{name: "unversioned gains the field and nothing else", from: "0.9",
			raw:  `{"id":"a","nodes":[{"id":"n","attrs":{"x_html":"<b>&</b>","x_big":12345678901234567890,"x_exp":1.5e3}}]}`,
			want: `{"id":"a","schema_version":"1.2","nodes":[{"id":"n","attrs":{"x_html":"<b>&</b>","x_big":12345678901234567890,"x_exp":1.5e3}}]}`},
		{name: "explicit 0.9", from: "0.9", raw: `{"schema_version":"0.9","id":"a"}`, want: `{"schema_version":"1.2","id":"a"}`},
		{name: "1.0 without agents or edges changes only the version", from: "1.0", raw: `{"schema_version":"1.0","id":"a","nodes":[]}`,
			want: `{"schema_version":"1.2","id":"a","nodes":[]}`},
		// Schema 1.2 is additive (ADR-093 M1): a 1.1 model inside the 1.2 profiles changes only its version.
		{name: "1.1 changes only the version", from: "1.1",
			raw:  `{"schema_version":"1.1","id":"a","nodes":[{"id":"n","type":"agent","attrs":{"egress_policy":"default_allow","sandbox":"managed"}}],"edges":[{"id":"e","protocol":"https","attrs":{}}]}`,
			want: `{"schema_version":"1.2","id":"a","nodes":[{"id":"n","type":"agent","attrs":{"egress_policy":"default_allow","sandbox":"managed"}}],"edges":[{"id":"e","protocol":"https","attrs":{}}]}`},
		{name: "current is untouched", from: "1.2", raw: `{ "schema_version" : "1.2", "id":"a" }`, want: `{ "schema_version" : "1.2", "id":"a" }`},
		{name: "newer is refused", raw: `{"schema_version":"1.3"}`, err: ErrUnsupportedVersion, contains: "1.3 is newer than 1.2"},
		{name: "older without a step is refused", raw: `{"schema_version":"0.5"}`, err: ErrUnsupportedVersion, contains: "no migration from 0.5"},
		{name: "a malformed version is refused without echoing it", raw: `{"schema_version":"sk-live-secret"}`, err: ErrInvalidVersion},
		{name: "not an object", raw: `"text"`, err: ErrNotObject},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, from, to, err := Upgrade([]byte(tc.raw))
			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
				assert.NotContains(t, err.Error(), "sk-live", "a version that is not MAJOR.MINOR is never echoed")
				if tc.contains != "" {
					assert.Contains(t, err.Error(), tc.contains)
				}
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.from, from)
			assert.Equal(t, Current, to)
			assert.JSONEq(t, tc.want, string(got))
			if tc.from == Current {
				assert.Equal(t, tc.raw, string(got), "a current document is returned byte for byte")
			}
			if tc.name == "unversioned gains the field and nothing else" {
				assert.NotContains(t, string(got), "\\u003c", "upgraded JSON is not HTML-escaped")
				assert.Contains(t, string(got), "12345678901234567890", "numbers keep their exact text")
				assert.Contains(t, string(got), "1.5e3", "numbers keep their exact text")
			}
		})
	}
}

func TestUpgradeDocDoesNotModifyItsInput(t *testing.T) {
	t.Parallel()
	in := map[string]any{"id": "a", "nodes": []any{map[string]any{"id": "n", "attrs": map[string]any{}}}}
	out, from, to, err := UpgradeDoc(in)
	require.NoError(t, err)
	assert.Equal(t, "0.9", from)
	assert.Equal(t, Current, to)
	assert.Equal(t, Current, out[Field])
	_, has := in[Field]
	assert.False(t, has, "the caller's map is not modified")

	for _, tc := range []struct {
		name string
		doc  map[string]any
		err  error
	}{
		{"nil", nil, ErrNotObject},
		{"not a string", map[string]any{Field: json.Number("1.0")}, ErrInvalidVersion},
		{"newer", map[string]any{Field: "2.0"}, ErrUnsupportedVersion},
		{"next minor", map[string]any{Field: "1.3"}, ErrUnsupportedVersion},
	} {
		_, _, _, err := UpgradeDoc(tc.doc)
		require.ErrorIs(t, err, tc.err, tc.name)
	}
}

// TestUpgradeChainsSteps runs a synthetic list with a 1.2 → 1.3 step that removes an enum value
// (ADR-040 §4), so the step engine, the chaining and the deprecation helper are exercised beyond
// the real steps.
func TestUpgradeChainsSteps(t *testing.T) {
	t.Parallel()
	retire := Deprecation{Scope: ScopeEdges, Field: "auth", Removed: "legacy_token", Successor: "oauth_client", Since: "1.3"}
	list := append(Steps(), Step{From: "1.2", To: "1.3", Note: "synthetic", Fn: func(doc map[string]any) (map[string]any, error) {
		if _, err := Rewrite(doc, retire); err != nil {
			return nil, err
		}
		doc[Field] = "1.3"
		return doc, nil
	}})

	raw := `{"id":"a","edges":[{"id":"e1","auth":"legacy_token","attrs":{}},{"id":"e2","auth":"none","attrs":{}}]}`
	got, from, to, err := upgradeWith(list, "1.3", []byte(raw))
	require.NoError(t, err)
	assert.Equal(t, "0.9", from)
	assert.Equal(t, "1.3", to)
	assert.JSONEq(t, `{"id":"a","schema_version":"1.3","edges":[
		{"id":"e1","auth":"oauth_client","attrs":{"x_migrated_from":"auth=legacy_token"}},
		{"id":"e2","auth":"none","attrs":{}}]}`, string(got))

	// A document already at 1.2 runs the last step only.
	got, from, _, err = upgradeWith(list, "1.3", []byte(`{"schema_version":"1.2","edges":[]}`))
	require.NoError(t, err)
	assert.Equal(t, "1.2", from)
	assert.JSONEq(t, `{"schema_version":"1.3","edges":[]}`, string(got))

	// A step that forgets to set the version, or fails, stops the upgrade.
	for name, fn := range map[string]Func{
		"forgets the version": func(doc map[string]any) (map[string]any, error) { return doc, nil },
		"fails":               func(map[string]any) (map[string]any, error) { return nil, errors.New("boom") },
	} {
		broken := append(Steps(), Step{From: "1.2", To: "1.3", Note: name, Fn: fn})
		_, _, _, err := upgradeWith(broken, "1.3", []byte(`{"id":"a"}`))
		require.Error(t, err, name)
		assert.Contains(t, err.Error(), "1.2 → 1.3", name)
	}

	// A list that does not reach the current version is refused rather than half-applied.
	_, _, _, err = upgradeWith(Steps(), "1.3", []byte(`{"id":"a"}`))
	require.Error(t, err)
}

func TestRewriteDeprecations(t *testing.T) {
	t.Parallel()
	doc := func() map[string]any {
		return map[string]any{
			"attrs": map[string]any{"regimes": []any{"OLDREG", "FINMA", "NEWREG"}},
			"nodes": []any{
				map[string]any{"id": "n1", "type": "old_type", "attrs": map[string]any{"identity": "shared"}},
				map[string]any{"id": "n2", "type": "app", "attrs": map[string]any{"identity": "managed_identity"}},
			},
			"groups": []any{map[string]any{"id": "g1", "kind": "old_kind"}},
		}
	}
	for _, tc := range []struct {
		name  string
		dep   Deprecation
		count int
		check func(t *testing.T, d map[string]any)
	}{
		{"node member", Deprecation{Scope: ScopeNodes, Field: "type", Removed: "old_type", Successor: "app"}, 1,
			func(t *testing.T, d map[string]any) {
				n := d["nodes"].([]any)[0].(map[string]any)
				assert.Equal(t, "app", n["type"])
				assert.Equal(t, "type=old_type", n["attrs"].(map[string]any)[MigratedFrom])
				other := d["nodes"].([]any)[1].(map[string]any)
				assert.NotContains(t, other["attrs"], MigratedFrom, "an element without the value is untouched")
			}},
		{"node attribute", Deprecation{Scope: ScopeNodes, Field: "attrs.identity", Removed: "shared", Successor: "managed_identity"}, 1,
			func(t *testing.T, d map[string]any) {
				attrs := d["nodes"].([]any)[0].(map[string]any)["attrs"].(map[string]any)
				assert.Equal(t, "managed_identity", attrs["identity"])
				assert.Equal(t, "attrs.identity=shared", attrs[MigratedFrom])
			}},
		{"list attribute keeps items unique", Deprecation{Scope: ScopeArchitecture, Field: "attrs.regimes", Removed: "OLDREG", Successor: "NEWREG"}, 1,
			func(t *testing.T, d map[string]any) {
				attrs := d["attrs"].(map[string]any)
				assert.Equal(t, []any{"NEWREG", "FINMA"}, attrs["regimes"])
				assert.Equal(t, "attrs.regimes=OLDREG", attrs[MigratedFrom])
			}},
		{"group without attrs gains the note", Deprecation{Scope: ScopeGroups, Field: "kind", Removed: "old_kind", Successor: "zone"}, 1,
			func(t *testing.T, d map[string]any) {
				g := d["groups"].([]any)[0].(map[string]any)
				assert.Equal(t, "zone", g["kind"])
				assert.Equal(t, "kind=old_kind", g["attrs"].(map[string]any)[MigratedFrom])
			}},
		{"absent value changes nothing", Deprecation{Scope: ScopeEdges, Field: "auth", Removed: "x", Successor: "y"}, 0,
			func(t *testing.T, d map[string]any) { assert.Equal(t, doc(), d) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			d := doc()
			n, err := Rewrite(d, tc.dep)
			require.NoError(t, err)
			assert.Equal(t, tc.count, n)
			tc.check(t, d)
		})
	}

	t.Run("notes accumulate once per rewrite", func(t *testing.T) {
		t.Parallel()
		d := doc()
		deps := []Deprecation{
			{Scope: ScopeNodes, Field: "type", Removed: "old_type", Successor: "app"},
			{Scope: ScopeNodes, Field: "attrs.identity", Removed: "shared", Successor: "managed_identity"},
		}
		_, err := Rewrite(d, deps...)
		require.NoError(t, err)
		n, err := Rewrite(d, deps...)
		require.NoError(t, err)
		assert.Zero(t, n, "a rewrite is idempotent")
		attrs := d["nodes"].([]any)[0].(map[string]any)["attrs"].(map[string]any)
		assert.Equal(t, "type=old_type; attrs.identity=shared", attrs[MigratedFrom])
	})

	for name, bad := range map[string]Deprecation{
		"unknown scope":      {Scope: "findings", Field: "status", Removed: "a", Successor: "b"},
		"same successor":     {Scope: ScopeNodes, Field: "type", Removed: "a", Successor: "a"},
		"no field":           {Scope: ScopeNodes, Removed: "a", Successor: "b"},
		"no removed value":   {Scope: ScopeNodes, Field: "type", Successor: "b"},
		"no successor value": {Scope: ScopeNodes, Field: "type", Removed: "a"},
	} {
		_, err := Rewrite(doc(), bad)
		require.Error(t, err, name)
	}
}

func TestCompare(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		a, b string
		want int
	}{{"0.9", "1.0", -1}, {"1.0", "1.0", 0}, {"1.10", "1.9", 1}, {"2.0", "1.99", 1}} {
		assert.Equal(t, tc.want, compare(tc.a, tc.b), fmt.Sprintf("%s vs %s", tc.a, tc.b))
	}
}
