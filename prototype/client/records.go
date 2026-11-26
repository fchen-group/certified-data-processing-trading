package main

import (
	"encoding/json"
	"errors"
	"os"

	"certified-data-processing-trading/pkg/analyzer"
	"certified-data-processing-trading/pkg/localio"
)

func loadInputRecords(path, format string) ([][]byte, error) {
	switch format {
	case analyzer.AdultFormat:
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		rows, err := analyzer.ReadAdultRows(f, 0)
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			if _, err := analyzer.ParseAdult(row); err != nil {
				return nil, err
			}
		}
		return rows, nil
	case "work2.score-record.v1":
		var records []analyzer.Record
		if err := localio.ReadJSON(path, &records); err != nil {
			return nil, err
		}
		raw := make([][]byte, len(records))
		for i, r := range records {
			b, err := json.Marshal(r)
			if err != nil {
				return nil, err
			}
			raw[i] = b
		}
		return raw, nil
	default:
		return nil, errors.New("unsupported description record format")
	}
}
