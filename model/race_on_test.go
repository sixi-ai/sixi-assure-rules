//go:build race

package model_test

// raceEnabled loosens wall-clock budgets: the race detector slows allocation-heavy code 5–10× and
// make test runs every package in parallel (memory: "1 s of work reads as 8 s there").
const raceEnabled = true
