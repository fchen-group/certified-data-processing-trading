package analyzer

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
)

const AdultFormat = "adult.raw.v1"
const AdultStatistics = "adult-statistics-v1"

// ReadAdultRows fixes record boundaries without changing record content.
// limit=0 reads all rows; a positive limit requires that many data rows.
func ReadAdultRows(r io.Reader, limit int) ([][]byte, error) {
	if limit < 0 {
		return nil, errors.New("negative record limit")
	}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	var rows [][]byte
	for (limit == 0 || len(rows) < limit) && scanner.Scan() {
		raw := scanner.Bytes() // ScanLines removes LF and an optional preceding CR.
		trimmed := bytes.TrimSpace(raw)
		if len(trimmed) == 0 || trimmed[0] == '|' {
			continue
		}
		rows = append(rows, bytes.Clone(raw))
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(rows) == 0 || (limit > 0 && len(rows) != limit) {
		return nil, errors.New("insufficient Adult records")
	}
	return rows, nil
}

// ParseAdult interprets a committed row. Trimming is only for computation;
// callers retain the original bytes for commitments and membership proofs.
func ParseAdult(raw []byte) ([15]string, error) {
	var fields [15]string
	for _, b := range raw {
		if b > 127 || b == '\n' || b == '\r' {
			return fields, errors.New("invalid Adult record encoding")
		}
	}
	parts := strings.Split(string(raw), ",")
	if len(parts) != len(fields) {
		return fields, errors.New("Adult requires 14 attributes and one label")
	}
	for i, p := range parts {
		fields[i] = strings.TrimSpace(p)
		if fields[i] == "" {
			return fields, errors.New("empty Adult field")
		}
	}
	label := strings.TrimSuffix(fields[14], ".")
	if label != "<=50K" && label != ">50K" {
		return fields, errors.New("invalid Adult label")
	}
	for _, i := range []int{0, 2, 4, 10, 11, 12} {
		if fields[i] == "?" {
			continue
		}
		for _, c := range fields[i] {
			if c < '0' || c > '9' {
				return fields, errors.New("invalid Adult numeric field")
			}
		}
		x, err := strconv.ParseUint(fields[i], 10, 53)
		if err != nil || (i == 0 && (x < 17 || x > 90)) || (i == 12 && (x < 1 || x > 99)) {
			return fields, errors.New("Adult numeric value out of range")
		}
	}
	return fields, nil
}

type Statistic struct {
	Mean               float64 `json:"mean"`
	PopulationVariance float64 `json:"population_variance"`
}

type StatisticsResult struct {
	Count        uint64    `json:"count"`
	Age          Statistic `json:"age"`
	HoursPerWeek Statistic `json:"hours_per_week"`
}

func analyzeAdultStatistics(records [][]byte) ([]byte, error) {
	if len(records) == 0 {
		return nil, errors.New("empty statistics input")
	}
	var means, m2 [2]float64
	for i, raw := range records {
		fields, err := ParseAdult(raw)
		if err != nil {
			return nil, err
		}
		for j, column := range []int{0, 12} {
			x, err := strconv.ParseFloat(fields[column], 64)
			if err != nil || !finite(x) {
				return nil, errors.New("statistics field missing or invalid")
			}
			delta := x - means[j]
			means[j] += delta / float64(i+1)
			m2[j] += delta * (x - means[j])
		}
	}
	n := float64(len(records))
	return json.Marshal(StatisticsResult{uint64(len(records)),
		Statistic{means[0], m2[0] / n}, Statistic{means[1], m2[1] / n}})
}
