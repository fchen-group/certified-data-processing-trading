package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// DecodeDataset bounds array growth before allocating all records or salts.
// Byte limits must be enforced before this function is called.
func DecodeDataset(raw []byte, maxRecords, maxRecordBytes int) (Dataset, error) {
	var data Dataset
	if maxRecords <= 0 || maxRecordBytes <= 0 {
		return data, errors.New("invalid dataset limits")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	expect := func(want json.Delim) error {
		t, e := d.Token()
		if e != nil {
			return e
		}
		if t != want {
			return errors.New("invalid dataset container")
		}
		return nil
	}
	if e := expect('{'); e != nil {
		return data, e
	}
	seen := map[string]bool{}
	for d.More() {
		t, e := d.Token()
		if e != nil {
			return data, e
		}
		name, ok := t.(string)
		if !ok || seen[name] || (name != "records" && name != "salts") {
			return data, errors.New("unknown or repeated dataset field")
		}
		seen[name] = true
		if e = expect('['); e != nil {
			return data, e
		}
		for count := 0; d.More(); count++ {
			if count >= maxRecords {
				return data, errors.New("dataset record limit exceeded")
			}
			if name == "records" {
				var record []byte
				if e = d.Decode(&record); e != nil {
					return data, e
				}
				if len(record) > maxRecordBytes {
					return data, errors.New("individual record limit exceeded")
				}
				data.Records = append(data.Records, record)
			} else {
				var salt Hash
				if e = d.Decode(&salt); e != nil {
					return data, e
				}
				data.Salts = append(data.Salts, salt)
			}
		}
		if e = expect(']'); e != nil {
			return data, e
		}
	}
	if e := expect('}'); e != nil {
		return data, e
	}
	var extra any
	if e := d.Decode(&extra); e != io.EOF {
		return data, errors.New("trailing dataset data")
	}
	return data, data.Validate()
}
