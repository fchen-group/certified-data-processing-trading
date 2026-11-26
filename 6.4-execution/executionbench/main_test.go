package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFixtureRoundTripAndTampering(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "rows.csv")
	expected := filepath.Join(dir, "expected.json")
	row := "39, ?, 77516, Bachelors, 13, Never-married, Adm-clerical, Not-in-family, White, Male, 2174, 0, 40, United-States, <=50K\n"
	if err := os.WriteFile(input, []byte(row), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(expected, []byte(`{"count":1,"age":{"mean":39,"population_variance":0},"hours_per_week":{"mean":40,"population_variance":0}}`), 0600); err != nil {
		t.Fatal(err)
	}
	fixturePath := filepath.Join(dir, "fixture")
	if err := prepare(fixturePath, input, "", expected, 1); err != nil {
		t.Fatal(err)
	}
	if err := measure(fixturePath); err != nil {
		t.Fatal(err)
	}
	if err := prepare(fixturePath, input, "", expected, 1); err == nil {
		t.Fatal("overwrote fixture")
	}
	cipherPath := filepath.Join(fixturePath, "input.bin")
	cipher, err := os.ReadFile(cipherPath)
	if err != nil {
		t.Fatal(err)
	}
	cipher[len(cipher)-1] ^= 1
	if err := os.WriteFile(cipherPath, cipher, 0600); err != nil {
		t.Fatal(err)
	}
	if err := measure(fixturePath); err == nil {
		t.Fatal("accepted altered ciphertext")
	}
}
