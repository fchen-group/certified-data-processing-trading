package analyzer

import (
	_ "embed"
	"encoding/json"
	"errors"
	"strconv"
)

const AdultIncome = "adult-income-v1"

// Public preprocessing is part of the reviewed program. Only model weights,
// intercept and decision threshold are provided by DB at execution time.
//
//go:embed adult_transform.json
var adultTransformJSON []byte

type adultTransform struct {
	Format             string     `json:"format"`
	NumericColumns     []int      `json:"numeric_columns"`
	Medians            []float64  `json:"medians"`
	Means              []float64  `json:"means"`
	Scales             []float64  `json:"scales"`
	CategoricalColumns []int      `json:"categorical_columns"`
	Categories         [][]string `json:"categories"`
	Dimension          int        `json:"dimension"`
}

var incomeTransform = loadAdultTransform()

func loadAdultTransform() adultTransform {
	var t adultTransform
	if err := json.Unmarshal(adultTransformJSON, &t); err != nil {
		panic(err)
	}
	n := len(t.NumericColumns)
	if t.Format != AdultFormat || n != len(t.Medians) || n != len(t.Means) || n != len(t.Scales) || len(t.Categories) != len(t.CategoricalColumns) {
		panic("invalid reviewed Adult transform")
	}
	seen := map[int]bool{}
	for j, c := range t.NumericColumns {
		if c < 0 || c >= 14 || seen[c] || !finite(t.Medians[j]) || !finite(t.Means[j]) || !finite(t.Scales[j]) || t.Scales[j] <= 0 {
			panic("invalid reviewed numeric transform")
		}
		seen[c] = true
	}
	for j, c := range t.CategoricalColumns {
		if c < 0 || c >= 14 || seen[c] || len(t.Categories[j]) == 0 {
			panic("invalid reviewed categorical transform")
		}
		seen[c] = true
		for k, value := range t.Categories[j] {
			if value == "" || (k > 0 && value <= t.Categories[j][k-1]) {
				panic("invalid reviewed category order")
			}
		}
		n += len(t.Categories[j])
	}
	if len(seen) != 14 || n != t.Dimension {
		panic("invalid reviewed feature dimension")
	}
	return t
}

// AdultFeatures parses the full committed row and applies training-only
// preprocessing. The income label is never used as a prediction feature.
func AdultFeatures(raw []byte) ([]float64, error) {
	fields, err := ParseAdult(raw)
	if err != nil {
		return nil, err
	}
	t := &incomeTransform
	x := make([]float64, t.Dimension)
	for j, c := range t.NumericColumns {
		v := t.Medians[j]
		if fields[c] != "?" {
			v, err = strconv.ParseFloat(fields[c], 64)
			if err != nil || !finite(v) {
				return nil, errors.New("invalid numeric classification feature")
			}
		}
		x[j] = (v - t.Means[j]) / t.Scales[j]
	}
	offset := len(t.NumericColumns)
	for j, c := range t.CategoricalColumns {
		for k, value := range t.Categories[j] {
			if value == fields[c] {
				x[offset+k] = 1
				break
			}
		}
		offset += len(t.Categories[j])
	}
	return x, nil
}

func analyzeAdultIncome(records [][]byte, p Parameters) ([]byte, error) {
	if len(records) == 0 {
		return nil, errors.New("empty classification input")
	}
	r := Result{Count: uint64(len(records))}
	for _, raw := range records {
		x, err := AdultFeatures(raw)
		if err != nil {
			return nil, err
		}
		score := p.Bias
		for j, v := range x {
			score += v * p.Weights[j]
		}
		if !finite(score) {
			return nil, errors.New("classification score overflow")
		}
		if score > p.Threshold {
			r.Above++
		}
	}
	return json.Marshal(r)
}
