//go:build race

package httpcatalog

// raceDetector slows the scale tests' timing checks out of meaning.
const raceDetector = true
