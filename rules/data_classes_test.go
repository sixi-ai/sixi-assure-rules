package rules

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDataClassesOnlyStoreIsDecided: DATA-003 and DATA-004 read data_classes[] with data_class (schema 1.1,
// self-assessment limitation 6) and still require data_class. A store that declares no data_class but lists a
// sensitive class in data_classes[] is a finding, decided by the declared list (the engine counts every element a
// rule fires on as decided). The same store listing only a non-sensitive class is not_checked: its single data_class,
// the required fact, could still be sensitive. With data_class declared it is decided either way.
func TestDataClassesOnlyStoreIsDecided(t *testing.T) {
	t.Parallel()
	c, err := LoadDirWith(repoPath("packs"), LoadOptions{})
	require.NoError(t, err)
	eng := New(c, nil)
	for _, rule := range []string{"DATA-003", "DATA-004"} {
		t.Run(rule, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(repoPath("packs"), "fixtures", rule+".classesonly.pos.json")
			a := loadModel(t, path)
			db := a.Node("n_db")
			require.NotNil(t, db)
			_, declared := db.Attrs["data_class"]
			require.False(t, declared, "the fixture declares no data_class")

			fs, cov, err := eng.EvaluateCoverage(context.Background(), a, policyFromAttrs(a))
			require.NoError(t, err)
			assert.Equal(t, []string{"n_db"}, findingsByRule(fs)[rule], "a sensitive data_classes[] entry fires")
			assert.NotContains(t, cov.NotChecked[rule], "n_db", "a store the rule fires on is decided")

			quiet := loadModel(t, path)
			quiet.Node("n_db").Attrs["data_classes"] = []any{"internal"}
			fs, cov, err = eng.EvaluateCoverage(context.Background(), quiet, policyFromAttrs(quiet))
			require.NoError(t, err)
			assert.Empty(t, findingsByRule(fs)[rule])
			assert.Contains(t, cov.NotChecked[rule], "n_db", "no data_class and no sensitive entry: not_checked")

			declaredQuiet := loadModel(t, path)
			declaredQuiet.Node("n_db").Attrs["data_classes"] = []any{"internal"}
			declaredQuiet.Node("n_db").Attrs["data_class"] = "internal"
			fs, cov, err = eng.EvaluateCoverage(context.Background(), declaredQuiet, policyFromAttrs(declaredQuiet))
			require.NoError(t, err)
			assert.Empty(t, findingsByRule(fs)[rule])
			assert.NotContains(t, cov.NotChecked[rule], "n_db", "data_class internal decides it")
		})
	}
}
