//go:build !race

package gate_test

// raceDetector is false in an ordinary build, which is the build whose latency
// the budget is about.
const raceDetector = false
