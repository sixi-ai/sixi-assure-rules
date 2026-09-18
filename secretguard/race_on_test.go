//go:build race

package secretguard

// raceEnabled loosens wall-clock budgets: the race detector slows allocation-heavy code 5–10× and
// make test runs every package in parallel (memory: "1 s of work reads as 8 s there").
const raceEnabled = true
