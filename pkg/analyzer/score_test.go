package analyzer

import (
	"math"
	"testing"
)

func TestScoreAndParameterValidation(t *testing.T) {
	records := [][]byte{[]byte(`{"id":"a","features":[2,3]}`), []byte(`{"id":"b","features":[1,0]}`)}
	p := Parameters{Weights: []float64{2, 1}, Threshold: 3}
	r, e := Analyze(records, p)
	if e != nil || string(r) != `{"count":2,"above_threshold":1}` {
		t.Fatalf("%s %v", r, e)
	}
	p.Weights = []float64{1}
	if _, e = Analyze(records, p); e == nil {
		t.Fatal("dimension mismatch")
	}
	p.Weights = []float64{math.Inf(1)}
	if e = Validate(p); e == nil {
		t.Fatal("invalid parameters")
	}
}
