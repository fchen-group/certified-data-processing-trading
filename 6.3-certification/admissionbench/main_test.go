package main

import (
	"encoding/json"
	"fmt"
	"testing"

	"certified-data-processing-trading/pkg/analyzer"
)

func TestRepeatedChallengeAndFullSampling(t *testing.T) {
	var rows [][]byte
	for i := 0; i < 23; i++ {
		b, _ := json.Marshal(analyzer.Record{ID: fmt.Sprint(i), Features: []float64{float64(i), 4}})
		rows = append(rows, b)
	}
	r, e := measure(rows, .05, .0001, 3, 3)
	if e != nil {
		t.Fatal(e)
	}
	if r.M != 23 || len(r.Audits) != 3 || r.CiphertextBytes != r.EncodedInputSize+28 {
		t.Fatal("incorrect count or AES-GCM wire size")
	}
	for _, a := range r.Audits {
		if a.CumulativeDistinct != 23 || a.SaltBytes != 23*32 || a.ResponseWireBytes <= a.SampleRecordBytes+a.SaltBytes+a.ProofHashBytes {
			t.Fatal("incorrect disclosure or encoded-byte accounting")
		}
	}
	if _, e := measure(rows, .05, .0001, 4, 3); e == nil {
		t.Fatal("budget bypassed")
	}
}

func TestRejectInvalidBenchmarkRecords(t *testing.T) {
	for _, rows := range [][][]byte{
		{[]byte(`{"id":"a","features":[]}`)},
		{[]byte(`{"id":"a","features":[1]}`), []byte(`{"id":"a","features":[2]}`)},
		{[]byte(`{"id":"a","features":[1]}`), []byte(`{"id":"b","features":[2,3]}`)},
		{[]byte(`{"id":"a","features":[1],"label":1}`)},
	} {
		if _, _, e := normalize(rows); e == nil {
			t.Fatal("invalid records accepted")
		}
	}
}

func TestPolicySweepSharesOneSaltedSnapshot(t *testing.T) {
	rows := make([][]byte, 1000)
	for i := range rows {
		rows[i] = []byte(fmt.Sprintf(`{"id":"%d","features":[1,2]}`, i))
	}
	policies := []samplingPolicy{{.05, .01}, {.05, .001}, {.05, .0001}}
	points, err := measureSweep(rows, policies, 1, 3)
	if err != nil {
		t.Fatal(err)
	}
	for i, p := range points {
		if p.Commitment != points[0].Commitment || p.Preparation != points[0].Preparation || p.M != []uint64{90, 135, 180}[i] {
			t.Fatal("policy sweep changed the salted snapshot or sample size")
		}
		if len(p.Audits) != 1 || !p.Checks["all_decoded_samples_verified"] {
			t.Fatal("missing independently verified policy response")
		}
	}
	other, err := measureSweep(rows, policies, 1, 3)
	if err != nil || other[0].Commitment == points[0].Commitment {
		t.Fatal("independent repetition reused protocol salts", err)
	}
	if _, err := measureSweep(rows, policies, 1, 2); err == nil {
		t.Fatal("sweep exceeded its shared challenge budget")
	}
}

func TestFullRecordsUseNewTimingScope(t *testing.T) {
	row := []byte("39, ?, 77516, Bachelors, 13, Never-married, Adm-clerical, Not-in-family, White, Male, 2174, 0, 40, United-States, <=50K. ")
	points, err := measureSweepFormat([][]byte{row, row}, []samplingPolicy{{.05, .0001}}, 10, 100, analyzer.AdultFormat)
	if err != nil {
		t.Fatal(err)
	}
	r := points[0]
	if r.RecordBytes != 2*len(row) || r.Dimensions != 14 || r.M != 2 || !r.Checks["dataset_roundtrip_verified"] {
		t.Fatal("inconsistent full-row measurement", r)
	}
	raw, _ := json.Marshal(r)
	var encoded map[string]json.RawMessage
	json.Unmarshal(raw, &encoded)
	var prep map[string]int64
	json.Unmarshal(encoded["preparation"], &prep)
	if len(prep) != 2 || prep["salt_prepare_ns"] <= 0 || prep["snapshot_ns"] <= 0 || r.MeasurementSchema != "commitment-v2" {
		t.Fatal("incorrect timing schema", prep)
	}
	for _, a := range r.Audits {
		if a.SampleRecordBytes != 2*len(row) {
			t.Fatal("projected or rewritten response")
		}
	}
}
