package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateSelfContainedDesignPages(t *testing.T) {
	root := t.TempDir()
	input := filepath.Join(root, "caa")
	output := filepath.Join(root, "output")
	if err := os.MkdirAll(input, 0755); err != nil {
		t.Fatal(err)
	}
	for _, record := range []DomainResult{
		{Domain: "example.com", Issue: []string{"letsencrypt.org"}, Records: []string{`0 issue "letsencrypt.org"`}},
		{Domain: "empty.example"},
		{Domain: "error.example", Error: "fixture timeout"},
	} {
		data, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(input, record.Domain+".json"), data, 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := generate(GenerateConfig{InputDir: input, OutputDir: output}); err != nil {
		t.Fatal(err)
	}
	for _, route := range []string{"index.html", "example.com.html", "empty.example.html", "error.example.html", "providers/letsencrypt.org.html"} {
		data, err := os.ReadFile(filepath.Join(output, route))
		if err != nil {
			t.Fatal(err)
		}
		page := string(data)
		for _, required := range []string{`src="/uvy-theme.js"`, `href="/uvy-tokens.css"`, `src="/vendor/htmx-4.0.0.min.js"`, `id="theme-toggle"`, `aria-controls="leftPanel"`, `Open source on GitHub`, `MIT License`, `Browse all domains`} {
			if !strings.Contains(page, required) {
				t.Errorf("%s missing %s", route, required)
			}
		}
		if strings.Contains(page, `src="https://`) {
			t.Errorf("%s has a remote runtime dependency", route)
		}
	}
	for _, asset := range []string{"uvy-theme.js", "uvy-tokens.css", "uvy-elements.css", "vendor/htmx-4.0.0.min.js"} {
		want, err := os.ReadFile(filepath.Join("assets", asset))
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join(output, asset))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("generated asset %s differs from vendored source", asset)
		}
	}
	raw, err := os.ReadFile(filepath.Join(output, "snippets/example.com.html"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `/providers/letsencrypt.org.html`) || !strings.Contains(string(raw), `0 issue &#34;letsencrypt.org&#34;`) {
		t.Error("domain fragment lost provider link or escaped raw response")
	}
}
