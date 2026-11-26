package analyzer

import (
	"bytes"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const adultRow = "39, ?, 77516, Bachelors, 13, Never-married, Adm-clerical, Not-in-family, White, Male, 2174, 0, 40, United-States, <=50K.  "

func TestAdultBoundariesPreserveFullBytes(t *testing.T) {
	rows, err := ReadAdultRows(strings.NewReader("|header\r\n\r\n"+adultRow+"\r\n"+adultRow+"\n"), 0)
	if err != nil || len(rows) != 2 || !bytes.Equal(rows[0], []byte(adultRow)) || !bytes.Equal(rows[1], rows[0]) {
		t.Fatal("record bytes or duplicates changed", err)
	}
	if _, err := ReadAdultRows(strings.NewReader(adultRow), 2); err == nil {
		t.Fatal("short input accepted")
	}
	for _, raw := range []string{"1,2", strings.Replace(adultRow, "77516", "bad", 1), adultRow + "\n"} {
		if _, err := ParseAdult([]byte(raw)); err == nil {
			t.Fatal("malformed row accepted")
		}
	}
}

func TestAdultStatisticsUseCommittedRows(t *testing.T) {
	second := strings.Replace(strings.Replace(adultRow, "39,", "41,", 1), ", 40,", ", 44,", 1)
	rows := [][]byte{[]byte(adultRow), []byte(second)}
	result, err := Analyze(rows, Parameters{Task: AdultStatistics})
	if err != nil {
		t.Fatal(err)
	}
	var got StatisticsResult
	if err := json.Unmarshal(result, &got); err != nil || got != (StatisticsResult{2, Statistic{40, 1}, Statistic{42, 4}}) {
		t.Fatal("wrong reference statistics", got, err)
	}
	rows[0] = []byte(strings.Replace(adultRow, "<=50K", ">50K", 1))
	changed, err := Analyze(rows, Parameters{Task: AdultStatistics})
	if err != nil || !bytes.Equal(result, changed) {
		t.Fatal("label used as statistics feature", err)
	}
	if _, err := Analyze(rows, Parameters{Task: AdultStatistics, Weights: []float64{1}}); err == nil {
		t.Fatal("inapplicable parameters accepted")
	}
	rows[0] = []byte(strings.Replace(adultRow, "39,", "?,", 1))
	if _, err := Analyze(rows, Parameters{Task: AdultStatistics}); err == nil {
		t.Fatal("missing task field silently dropped")
	}
}

// The Python preparation script supplies independent exact integer sums and
// sums of squares. This check runs when the local full dataset is available.
func TestPreparedAdultReferenceStatistics(t *testing.T) {
	dir := filepath.Join("..", "..", "data", "adult", "full-records")
	manifest, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if os.IsNotExist(err) {
		t.Skip("full-record dataset has not been prepared")
	}
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Outputs []struct {
			File       string      `json:"file"`
			Records    uint64      `json:"records"`
			Statistics []Statistic `json:"reference_statistics"`
		} `json:"outputs"`
	}
	if err := json.Unmarshal(manifest, &m); err != nil {
		t.Fatal(err)
	}
	if len(m.Outputs) != 2 {
		t.Fatal("missing prepared datasets")
	}
	for _, entry := range m.Outputs {
		f, err := os.Open(filepath.Join(dir, entry.File))
		if err != nil {
			t.Fatal(err)
		}
		rows, err := ReadAdultRows(f, 0)
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
		raw, err := Analyze(rows, Parameters{Task: AdultStatistics})
		if err != nil {
			t.Fatal(err)
		}
		var got StatisticsResult
		if err := json.Unmarshal(raw, &got); err != nil || got.Count != entry.Records || len(entry.Statistics) != 2 {
			t.Fatal("incorrect count or result", err)
		}
		for i, stat := range []Statistic{got.Age, got.HoursPerWeek} {
			ref := entry.Statistics[i]
			if math.Abs(stat.Mean-ref.Mean) > 1e-9 || math.Abs(stat.PopulationVariance-ref.PopulationVariance) > 1e-8 {
				t.Fatal("statistics differ from independent reference", entry.File, stat, ref)
			}
		}
	}
}
