package main

import (
	"encoding/json"
	"net/http"
	"os"
	"time"
)

type demoRun struct {
	ID      string    `json:"id"`
	Started time.Time `json:"started"`
}

func currentRun() demoRun {
	var run demoRun
	b, err := os.ReadFile("/public/run.json")
	if err == nil {
		_ = json.Unmarshal(b, &run)
	}
	return run
}

type batchReport struct {
	Orders     int `json:"orders"`
	Refunds    int `json:"refunds"`
	Duplicates int `json:"duplicates"`
}
type schedulerState struct {
	Run       string       `json:"run"`
	Duplicate bool         `json:"duplicate"`
	LastBatch *batchReport `json:"last_batch,omitempty"`
}

func readScheduler(path, run string) schedulerState {
	var state schedulerState
	b, err := os.ReadFile(path)
	if err == nil && json.Unmarshal(b, &state) == nil && state.Run == run {
		return state
	}
	return schedulerState{Run: run, Duplicate: true}
}
func (s schedulerState) public() obj {
	return obj{"duplicate": s.Duplicate, "last_batch": s.LastBatch}
}

func simulateBatch(duplicate bool) batchReport {
	result := batchReport{Orders: 92}
	for order := 0; order < result.Orders; order++ {
		result.Refunds++
		if duplicate {
			result.Refunds++
			result.Duplicates++
		}
	}
	return result
}
func schedulerAction(w http.ResponseWriter, r *http.Request, path, run string) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "This action requires POST", http.StatusMethodNotAllowed)
		return
	}
	state := readScheduler(path, run)
	switch r.URL.Path {
	case "/scheduler/disable-duplicate":
		state.Duplicate = false
	case "/scheduler/test-run":
		report := simulateBatch(state.Duplicate)
		state.LastBatch = &report
	default:
		http.NotFound(w, r)
		return
	}
	saveJSON(path, state)
	_ = json.NewEncoder(w).Encode(obj{"scheduler": state.public(), "historical_refunds": 184, "message": "Only the next batch changes. Yesterday's refund history is preserved."})
}

const exampleClaim = "gatehouse-demo-claim-example"

func checkClaim(value string, target []targetHash) obj {
	if value == exampleClaim {
		return obj{"example": true, "matches": []string{}}
	}
	return obj{"example": false, "matches": matches(value, target)}
}
