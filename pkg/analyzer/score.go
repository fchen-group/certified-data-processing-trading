// Package analyzer is the replaceable, reviewed application module.
package analyzer

import (
	"encoding/json"
	"errors"
	"math"

	"certified-data-processing-trading/pkg/protocol"
)

type Parameters struct {
	Task      string    `json:"task,omitempty"`
	Weights   []float64 `json:"weights"`
	Bias      float64   `json:"bias"`
	Threshold float64   `json:"threshold"`
}
type Record struct {
	ID       string    `json:"id"`
	Features []float64 `json:"features"`
}
type Result struct {
	Count uint64 `json:"count"`
	Above uint64 `json:"above_threshold"`
}

func finite(f float64) bool { return !math.IsNaN(f) && !math.IsInf(f, 0) }
func Validate(p Parameters) error {
	if p.Task == AdultStatistics {
		if len(p.Weights) != 0 || p.Bias != 0 || p.Threshold != 0 {
			return errors.New("statistics task does not accept score parameters")
		}
		return nil
	}
	if p.Task != "" && p.Task != AdultIncome {
		return errors.New("unknown analysis task")
	}
	if p.Task == AdultIncome && len(p.Weights) != incomeTransform.Dimension {
		return errors.New("Adult model dimension mismatch")
	}
	if len(p.Weights) == 0 || len(p.Weights) > 4096 || !finite(p.Bias) || !finite(p.Threshold) {
		return errors.New("invalid score parameters")
	}
	for _, v := range p.Weights {
		if !finite(v) {
			return errors.New("nonfinite weight")
		}
	}
	return nil
}
func Analyze(records [][]byte, p Parameters) ([]byte, error) {
	if e := Validate(p); e != nil {
		return nil, e
	}
	if p.Task == AdultStatistics {
		return analyzeAdultStatistics(records)
	}
	if p.Task == AdultIncome {
		return analyzeAdultIncome(records, p)
	}
	r := Result{Count: uint64(len(records))}
	for _, raw := range records {
		var record Record
		if e := protocol.StrictJSON(raw, &record); e != nil {
			return nil, e
		}
		if record.ID == "" || len(record.Features) != len(p.Weights) {
			return nil, errors.New("record schema mismatch")
		}
		score := p.Bias
		for j, v := range record.Features {
			if !finite(v) {
				return nil, errors.New("nonfinite feature")
			}
			score += v * p.Weights[j]
		}
		if !finite(score) {
			return nil, errors.New("score overflow")
		}
		if score > p.Threshold {
			r.Above++
		}
	}
	return json.Marshal(r)
}
