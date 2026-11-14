//go:build race

package gate_test

// raceDetector reports that this binary was built with -race. The detector adds
// enough overhead that a wall-clock latency budget measured under it says
// nothing about the shipped binary, so the percentile test refuses to assert
// one here and says so.
const raceDetector = true
