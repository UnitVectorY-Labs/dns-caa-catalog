package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestJSONResultRoundTrip(t *testing.T) {
	dir := t.TempDir()
	want := DomainResult{Domain: "example.com", Issue: []string{"ca.example; account=<123>&x"}}
	if err := writeResult(dir, want); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "example.com.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{`"records": []`, `"issue": [`, `ca.example; account=<123>&x`} {
		if !strings.Contains(string(data), fragment) {
			t.Errorf("output missing %q: %s", fragment, data)
		}
	}
	if strings.Contains(string(data), `"error"`) {
		t.Errorf("empty error was not omitted: %s", data)
	}
	results, err := loadResults(dir)
	if err != nil || len(results) != 1 || results[0].Domain != want.Domain || len(results[0].Issue) != 1 || results[0].Issue[0] != want.Issue[0] {
		t.Fatalf("round trip: results=%+v, err=%v", results, err)
	}
}

func TestLoadResultsStrictJSON(t *testing.T) {
	dir := t.TempDir()
	files := map[string][]byte{
		"valid.json":        []byte(`{"domain":"valid.example","issue":["ca.example"]}`),
		"duplicate.json":    []byte(`{"domain":"first.example","domain":"second.example"}`),
		"invalid-utf8.json": append([]byte(`{"domain":"`), []byte{0xff, '"', '}'}...),
		"case.json":         []byte(`{"Domain":"wrong-case.example"}`),
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0644); err != nil {
			t.Fatal(err)
		}
	}
	results, err := loadResults(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 || results[0].Domain != "" || results[1].Domain != "valid.example" {
		t.Fatalf("unexpected results: %+v", results)
	}
}

func TestReadCrawlTimestamp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "timestamp.json")
	for _, tc := range []struct{ input, want string }{
		{`{"timestamp":"2025-07-10T23:16:42Z"}`, "2025-07-10T23:16:42Z"},
		{`{"Timestamp":"wrong-case"}`, ""},
		{`{"timestamp":"one","timestamp":"two"}`, ""},
	} {
		if err := os.WriteFile(path, []byte(tc.input), 0644); err != nil {
			t.Fatal(err)
		}
		if got := readCrawlTimestamp(dir); got != tc.want {
			t.Errorf("readCrawlTimestamp(%s) = %q, want %q", tc.input, got, tc.want)
		}
	}
}
