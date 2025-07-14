package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// CAARecord represents a parsed CAA DNS record
type CAARecord struct {
	Flag  uint8  `json:"flag"`
	Tag   string `json:"tag"`
	Value string `json:"value"`
}

// DomainResult represents the CAA lookup result for a domain
type DomainResult struct {
	Domain    string   `json:"domain"`
	Records   []string `json:"records"`
	Issue     []string `json:"issue"`
	IssueWild []string `json:"issuewild"`
	Iodef     []string `json:"iodef"`
	Error     string   `json:"error,omitempty"`
}

// CrawlConfig holds configuration for the crawl command
type CrawlConfig struct {
	Input       string
	Output      string
	Concurrency int
	Timeout     time.Duration
	Retries     int
}

// GenerateConfig holds configuration for the generate command
type GenerateConfig struct {
	InputDir  string
	OutputDir string
}

// CAASummary holds statistics about CAA records across all domains
type CAASummary struct {
	TotalDomains         int
	DomainsWithCAA       int
	DomainsWithIssue     int
	DomainsWithIssueWild int
	IssueStats           map[string]int
	IssueWildStats       map[string]int
	SortedIssueStats     []StatEntry
	SortedIssueWildStats []StatEntry
}

// CAProviderData holds information about a certificate authority and domains using it
type CAProviderData struct {
	CA           string         `json:"ca"`
	NormalizedCA string         `json:"normalized_ca"`
	IssueDomains []DomainResult `json:"issue_domains"`
	WildDomains  []DomainResult `json:"wild_domains"`
	TotalDomains int            `json:"total_domains"`
}

// StatEntry represents a CA and its count for sorted display
type StatEntry struct {
	CA    string
	Count int
}

// PageData holds the data for rendering the main page template
type PageData struct {
	Results []DomainResult
	Content template.HTML
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]
	switch command {
	case "-crawl":
		crawlCommand()
	case "-generate":
		generateCommand()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("DNS CAA Catalog - Track and publish CAA DNS records")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  main.go -crawl [flags]     Crawl domains and perform CAA DNS lookups")
	fmt.Println("  main.go -generate [flags]  Generate static HTML pages from crawl data")
	fmt.Println()
	fmt.Println("Crawl flags:")
	fmt.Println("  -input, -i <path>         Input domains file (default: data/domains)")
	fmt.Println("  -output, -o <path>        Output directory (default: caa)")
	fmt.Println("  -concurrency, -c <int>    Concurrent workers (default: 100)")
	fmt.Println("  -timeout, -t <duration>   DNS timeout (default: 5s)")
	fmt.Println("  -retries, -r <int>        Retry attempts (default: 3)")
	fmt.Println()
	fmt.Println("Generate flags:")
	fmt.Println("  -input-dir, -i <path>     Input directory with JSON files (default: caa)")
	fmt.Println("  -output-dir, -o <path>    Output directory for HTML (default: output)")
}

func crawlCommand() {
	// Parse flags for crawl command
	fs := flag.NewFlagSet("crawl", flag.ExitOnError)
	config := CrawlConfig{}

	fs.StringVar(&config.Input, "input", "data/domains", "Input domains file")
	fs.StringVar(&config.Input, "i", "data/domains", "Input domains file")
	fs.StringVar(&config.Output, "output", "caa", "Output directory")
	fs.StringVar(&config.Output, "o", "caa", "Output directory")
	fs.IntVar(&config.Concurrency, "concurrency", 100, "Concurrent workers")
	fs.IntVar(&config.Concurrency, "c", 10, "Concurrent workers")
	fs.DurationVar(&config.Timeout, "timeout", 5*time.Second, "DNS timeout")
	fs.DurationVar(&config.Timeout, "t", 5*time.Second, "DNS timeout")
	fs.IntVar(&config.Retries, "retries", 3, "Retry attempts")
	fs.IntVar(&config.Retries, "r", 3, "Retry attempts")

	if err := fs.Parse(os.Args[2:]); err != nil {
		log.Fatalf("Failed to parse flags: %v", err)
	}

	if err := crawl(config); err != nil {
		log.Fatalf("Crawl failed: %v", err)
	}
}

func generateCommand() {
	// Parse flags for generate command
	fs := flag.NewFlagSet("generate", flag.ExitOnError)
	config := GenerateConfig{}

	fs.StringVar(&config.InputDir, "input-dir", "caa", "Input directory with JSON files")
	fs.StringVar(&config.InputDir, "i", "caa", "Input directory with JSON files")
	fs.StringVar(&config.OutputDir, "output-dir", "output", "Output directory for HTML")
	fs.StringVar(&config.OutputDir, "o", "output", "Output directory for HTML")

	if err := fs.Parse(os.Args[2:]); err != nil {
		log.Fatalf("Failed to parse flags: %v", err)
	}

	if err := generate(config); err != nil {
		log.Fatalf("Generate failed: %v", err)
	}
}

func crawl(config CrawlConfig) error {
	log.Printf("Starting crawl with config: %+v", config)

	// Validate input file exists
	if _, err := os.Stat(config.Input); os.IsNotExist(err) {
		return fmt.Errorf("input file does not exist: %s", config.Input)
	}

	// Load and dedupe domains
	domains, err := loadDomains(config.Input)
	if err != nil {
		return fmt.Errorf("failed to load domains: %v", err)
	}

	log.Printf("Loaded %d unique domains", len(domains))

	// Create output directory
	if err := os.MkdirAll(config.Output, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	// Write crawl timestamp
	crawlTimestamp := time.Now().UTC().Format(time.RFC3339)
	tsPath := filepath.Join(config.Output, "timestamp.json")
	tsData, _ := json.MarshalIndent(map[string]string{"timestamp": crawlTimestamp}, "", "  ")
	_ = os.WriteFile(tsPath, tsData, 0644)

	// Process domains concurrently
	results := processDomainsConcurrently(domains, config)

	// Write results
	for _, result := range results {
		if err := writeResult(config.Output, result); err != nil {
			log.Printf("Failed to write result for %s: %v", result.Domain, err)
		}
	}

	log.Printf("Crawl completed. Processed %d domains", len(results))
	return nil
}

func loadDomains(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	domainSet := make(map[string]bool)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		if domain != "" && !strings.HasPrefix(domain, "#") {
			// Sanitize domain (remove protocol, paths, etc.)
			domain = sanitizeDomain(domain)
			if domain != "" {
				domainSet[domain] = true
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// Convert to sorted slice for deterministic output
	domains := make([]string, 0, len(domainSet))
	for domain := range domainSet {
		domains = append(domains, domain)
	}
	sort.Strings(domains)

	return domains, nil
}

func sanitizeDomain(domain string) string {
	// Remove protocol prefixes
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "//")

	// Remove path components
	if idx := strings.Index(domain, "/"); idx != -1 {
		domain = domain[:idx]
	}

	// Remove port numbers
	if idx := strings.LastIndex(domain, ":"); idx != -1 {
		if net.ParseIP(domain) == nil { // Not an IPv6 address
			domain = domain[:idx]
		}
	}

	// Convert to lowercase
	domain = strings.ToLower(domain)

	return domain
}

func processDomainsConcurrently(domains []string, config CrawlConfig) []DomainResult {
	semaphore := make(chan struct{}, config.Concurrency)
	results := make([]DomainResult, len(domains))
	var wg sync.WaitGroup

	for i, domain := range domains {
		wg.Add(1)
		go func(index int, d string) {
			defer wg.Done()
			semaphore <- struct{}{}        // Acquire semaphore
			defer func() { <-semaphore }() // Release semaphore

			result := lookupCAA(d, config.Timeout, config.Retries)
			results[index] = result
		}(i, domain)
	}

	wg.Wait()
	return results
}

func lookupCAA(domain string, timeout time.Duration, retries int) DomainResult {
	result := DomainResult{
		Domain:    domain,
		Records:   []string{},
		Issue:     []string{},
		IssueWild: []string{},
		Iodef:     []string{},
	}

	var lastErr error
	for attempt := 0; attempt <= retries; attempt++ {
		if attempt > 0 {
			log.Printf("Retrying CAA lookup for %s (attempt %d/%d)", domain, attempt+1, retries+1)
			time.Sleep(time.Duration(attempt) * time.Second) // Exponential backoff
		}

		records, err := lookupCAARecords(domain, timeout)
		if err != nil {
			lastErr = err
			continue
		}

		// Parse and categorize records
		for _, record := range records {
			result.Records = append(result.Records, record)
			parsed := parseCAA(record)
			if parsed != nil {
				switch parsed.Tag {
				case "issue":
					result.Issue = append(result.Issue, parsed.Value)
				case "issuewild":
					result.IssueWild = append(result.IssueWild, parsed.Value)
				case "iodef":
					result.Iodef = append(result.Iodef, parsed.Value)
				}
			}
		}

		// Sort arrays for deterministic output
		sort.Strings(result.Records)
		sort.Strings(result.Issue)
		sort.Strings(result.IssueWild)
		sort.Strings(result.Iodef)

		return result
	}

	// All retries failed
	result.Error = lastErr.Error()
	log.Printf("Failed to lookup CAA for %s after %d retries: %v", domain, retries+1, lastErr)
	return result
}

func lookupCAARecords(domain string, timeout time.Duration) ([]string, error) {
	caaRecords := []string{}

	c := new(dns.Client)
	c.Timeout = timeout
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeCAA)

	// Use system resolver
	server := "8.8.8.8:53" // Use Google DNS for reliability

	r, _, err := c.Exchange(m, server)
	if err != nil {
		return nil, err
	}

	for _, ans := range r.Answer {
		if caa, ok := ans.(*dns.CAA); ok {
			// Format: flag tag value
			record := fmt.Sprintf("%d %s \"%s\"", caa.Flag, caa.Tag, caa.Value)
			caaRecords = append(caaRecords, record)
		}
	}

	return caaRecords, nil
}

func parseCAA(record string) *CAARecord {
	// Simple CAA parsing - this is a basic implementation
	// Real CAA records have a specific format: flag tag value
	parts := strings.SplitN(record, " ", 3)
	if len(parts) < 3 {
		return nil
	}

	var flag uint8
	if parts[0] == "0" {
		flag = 0
	} else {
		flag = 1
	}

	return &CAARecord{
		Flag:  flag,
		Tag:   parts[1],
		Value: strings.Trim(parts[2], `"`),
	}
}

func writeResult(outputDir string, result DomainResult) error {
	filename := filepath.Join(outputDir, result.Domain+".json")

	// Marshal with sorted keys
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}

func cleanCAValue(caValue string) string {
	// Remove everything after the first semicolon
	if idx := strings.Index(caValue, ";"); idx != -1 {
		result := caValue[:idx]
		// Return empty string if the result is empty or just whitespace
		return strings.TrimSpace(result)
	}
	return strings.TrimSpace(caValue)
}

func normalizeCAName(caValue string) string {
	// Clean the CA value and normalize it for file naming and grouping
	cleaned := cleanCAValue(caValue)
	// Convert to lowercase for consistency
	normalized := strings.ToLower(cleaned)
	// Replace characters that aren't filesystem-friendly
	normalized = strings.ReplaceAll(normalized, "/", "_")
	normalized = strings.ReplaceAll(normalized, "\\", "_")
	normalized = strings.ReplaceAll(normalized, ":", "_")
	normalized = strings.ReplaceAll(normalized, "*", "_")
	normalized = strings.ReplaceAll(normalized, "?", "_")
	normalized = strings.ReplaceAll(normalized, "\"", "_")
	normalized = strings.ReplaceAll(normalized, "<", "_")
	normalized = strings.ReplaceAll(normalized, ">", "_")
	normalized = strings.ReplaceAll(normalized, "|", "_")
	normalized = strings.ReplaceAll(normalized, " ", "_")
	return normalized
}

func collectCAProviders(results []DomainResult) map[string]*CAProviderData {
	providers := make(map[string]*CAProviderData)

	for _, result := range results {
		// Process 'issue' records
		for _, issueValue := range result.Issue {
			cleanCA := cleanCAValue(issueValue)
			if cleanCA == "" {
				continue
			}

			normalizedCA := normalizeCAName(issueValue)

			if providers[normalizedCA] == nil {
				providers[normalizedCA] = &CAProviderData{
					CA:           cleanCA,
					NormalizedCA: normalizedCA,
					IssueDomains: []DomainResult{},
					WildDomains:  []DomainResult{},
				}
			}

			// Add domain to issue domains if not already present
			found := false
			for _, existingDomain := range providers[normalizedCA].IssueDomains {
				if existingDomain.Domain == result.Domain {
					found = true
					break
				}
			}
			if !found {
				providers[normalizedCA].IssueDomains = append(providers[normalizedCA].IssueDomains, result)
			}
		}

		// Process 'issuewild' records
		for _, issueWildValue := range result.IssueWild {
			cleanCA := cleanCAValue(issueWildValue)
			if cleanCA == "" {
				continue
			}

			normalizedCA := normalizeCAName(issueWildValue)

			if providers[normalizedCA] == nil {
				providers[normalizedCA] = &CAProviderData{
					CA:           cleanCA,
					NormalizedCA: normalizedCA,
					IssueDomains: []DomainResult{},
					WildDomains:  []DomainResult{},
				}
			}

			// Add domain to wild domains if not already present
			found := false
			for _, existingDomain := range providers[normalizedCA].WildDomains {
				if existingDomain.Domain == result.Domain {
					found = true
					break
				}
			}
			if !found {
				providers[normalizedCA].WildDomains = append(providers[normalizedCA].WildDomains, result)
			}
		}
	}

	// Calculate total domains and sort
	for _, provider := range providers {
		// Create a map to deduplicate domains that appear in both issue and issuewild
		uniqueDomains := make(map[string]bool)
		for _, domain := range provider.IssueDomains {
			uniqueDomains[domain.Domain] = true
		}
		for _, domain := range provider.WildDomains {
			uniqueDomains[domain.Domain] = true
		}
		provider.TotalDomains = len(uniqueDomains)

		// Sort domain lists
		sort.Slice(provider.IssueDomains, func(i, j int) bool {
			return provider.IssueDomains[i].Domain < provider.IssueDomains[j].Domain
		})
		sort.Slice(provider.WildDomains, func(i, j int) bool {
			return provider.WildDomains[i].Domain < provider.WildDomains[j].Domain
		})
	}

	return providers
}

func toFloat64(v interface{}) float64 {
	switch val := v.(type) {
	case int:
		return float64(val)
	case int32:
		return float64(val)
	case int64:
		return float64(val)
	case float32:
		return float64(val)
	case float64:
		return val
	default:
		return 0
	}
}

func calculateCAASummary(results []DomainResult) CAASummary {
	// Use a map to track unique lowercase domains for accurate counting
	uniqueDomains := make(map[string]bool)
	domainStats := make(map[string]struct {
		hasCAA       bool
		hasIssue     bool
		hasIssueWild bool
		uniqueCAs    map[string]bool
	})

	summary := CAASummary{
		IssueStats:     make(map[string]int),
		IssueWildStats: make(map[string]int),
	}

	// First pass: collect data by lowercase domain
	for _, result := range results {
		lowerDomain := strings.ToLower(result.Domain)
		uniqueDomains[lowerDomain] = true

		// Get or create domain stats
		stats, exists := domainStats[lowerDomain]
		if !exists {
			stats.uniqueCAs = make(map[string]bool)
		}

		hasCAA := len(result.Records) > 0
		hasIssue := len(result.Issue) > 0
		hasIssueWild := len(result.IssueWild) > 0

		// Update domain-level flags (use OR logic for multiple variants)
		stats.hasCAA = stats.hasCAA || hasCAA
		stats.hasIssue = stats.hasIssue || hasIssue
		stats.hasIssueWild = stats.hasIssueWild || hasIssueWild

		// Collect CA stats
		if hasIssue {
			for _, issueValue := range result.Issue {
				cleanCA := strings.ToLower(cleanCAValue(issueValue))
				if cleanCA != "" { // Filter out empty values
					summary.IssueStats[cleanCA]++
					stats.uniqueCAs[cleanCA] = true
				}
			}
		}

		if hasIssueWild {
			for _, issueWildValue := range result.IssueWild {
				cleanCA := strings.ToLower(cleanCAValue(issueWildValue))
				if cleanCA != "" { // Filter out empty values
					summary.IssueWildStats[cleanCA]++
					stats.uniqueCAs[cleanCA] = true
				}
			}
		}

		domainStats[lowerDomain] = stats
	}

	// Second pass: calculate final counts based on unique lowercase domains
	summary.TotalDomains = len(uniqueDomains)
	for _, stats := range domainStats {
		if stats.hasCAA {
			summary.DomainsWithCAA++
		}
		if stats.hasIssue {
			summary.DomainsWithIssue++
		}
		if stats.hasIssueWild {
			summary.DomainsWithIssueWild++
		}
	}

	// Create sorted slices for template display (filter out empty strings)
	for ca, count := range summary.IssueStats {
		if ca != "" {
			summary.SortedIssueStats = append(summary.SortedIssueStats, StatEntry{CA: ca, Count: count})
		}
	}
	sort.Slice(summary.SortedIssueStats, func(i, j int) bool {
		return summary.SortedIssueStats[i].Count > summary.SortedIssueStats[j].Count
	})

	for ca, count := range summary.IssueWildStats {
		if ca != "" {
			summary.SortedIssueWildStats = append(summary.SortedIssueWildStats, StatEntry{CA: ca, Count: count})
		}
	}
	sort.Slice(summary.SortedIssueWildStats, func(i, j int) bool {
		return summary.SortedIssueWildStats[i].Count > summary.SortedIssueWildStats[j].Count
	})

	return summary
}

func generate(config GenerateConfig) error {
	log.Printf("Starting generate with config: %+v", config)

	// Validate required directories exist
	if _, err := os.Stat("templates"); os.IsNotExist(err) {
		return fmt.Errorf("templates directory does not exist")
	}
	if _, err := os.Stat("assets"); os.IsNotExist(err) {
		return fmt.Errorf("assets directory does not exist")
	}

	// Create output directory and subdirectories
	snippetsDir := filepath.Join(config.OutputDir, "snippets")
	providersDir := filepath.Join(config.OutputDir, "providers")
	providerSnippetsDir := filepath.Join(config.OutputDir, "snippets", "providers")
	if err := os.MkdirAll(snippetsDir, 0755); err != nil {
		return fmt.Errorf("failed to create snippets directory: %v", err)
	}
	if err := os.MkdirAll(providersDir, 0755); err != nil {
		return fmt.Errorf("failed to create providers directory: %v", err)
	}
	if err := os.MkdirAll(providerSnippetsDir, 0755); err != nil {
		return fmt.Errorf("failed to create provider snippets directory: %v", err)
	}

	// Load domain results
	results, err := loadResults(config.InputDir)
	if err != nil {
		return fmt.Errorf("failed to load results: %v", err)
	}

	log.Printf("Loaded %d domain results", len(results))

	// Parse templates with custom functions
	funcMap := template.FuncMap{
		"mul": func(a, b interface{}) float64 {
			return toFloat64(a) * toFloat64(b)
		},
		"div": func(a, b interface{}) float64 {
			va, vb := toFloat64(a), toFloat64(b)
			if vb == 0 {
				return 0
			}
			return va / vb
		},
		"normalizeCA": normalizeCAName,
	}

	mainTmpl, err := template.New("index.html").Funcs(funcMap).ParseFiles("templates/index.html")
	if err != nil {
		return fmt.Errorf("failed to parse main template: %v", err)
	}
	domainTmpl, err := template.New("domain.html").Funcs(funcMap).ParseFiles("templates/domain.html")
	if err != nil {
		return fmt.Errorf("failed to parse domain template: %v", err)
	}
	homeTmpl, err := template.New("home.html").Funcs(funcMap).ParseFiles("templates/home.html")
	if err != nil {
		return fmt.Errorf("failed to parse home template: %v", err)
	}
	snippetTmpl, err := template.New("snippet.html").Funcs(funcMap).ParseFiles("templates/snippet.html")
	if err != nil {
		return fmt.Errorf("failed to parse snippet template: %v", err)
	}
	navTmpl, err := template.New("nav.html").Funcs(funcMap).ParseFiles("templates/nav.html")
	if err != nil {
		return fmt.Errorf("failed to parse nav template: %v", err)
	}
	providerTmpl, err := template.New("provider.html").Funcs(funcMap).ParseFiles("templates/provider.html")
	if err != nil {
		return fmt.Errorf("failed to parse provider template: %v", err)
	}
	providerSnippetTmpl, err := template.New("provider-snippet.html").Funcs(funcMap).ParseFiles("templates/provider-snippet.html")
	if err != nil {
		return fmt.Errorf("failed to parse provider snippet template: %v", err)
	}

	// Generate index page with home content
	summary := calculateCAASummary(results)
	if err := generateIndex(config.OutputDir, results, summary, mainTmpl, homeTmpl); err != nil {
		return fmt.Errorf("failed to generate index: %v", err)
	}

	// Generate navigation snippet
	if err := generateNavSnippet(config.OutputDir, results, navTmpl); err != nil {
		return fmt.Errorf("failed to generate nav snippet: %v", err)
	}

	// Generate domain pages and snippets
	for _, result := range results {
		if err := generateDomainPageAndSnippet(config.OutputDir, result, results, domainTmpl, snippetTmpl); err != nil {
			log.Printf("Failed to generate page for %s: %v", result.Domain, err)
		}
	}

	// Generate provider pages and snippets
	providers := collectCAProviders(results)
	if err := generateProviderPagesAndSnippets(config.OutputDir, providers, providerTmpl, providerSnippetTmpl); err != nil {
		return fmt.Errorf("failed to generate provider pages: %v", err)
	}

	// Copy assets
	if err := copyAssets(config.OutputDir); err != nil {
		return fmt.Errorf("failed to copy assets: %v", err)
	}

	log.Printf("Generate completed. Created pages for %d domains", len(results))
	return nil
}

func loadResults(inputDir string) ([]DomainResult, error) {
	var results []DomainResult

	err := filepath.WalkDir(inputDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if !d.IsDir() && strings.HasSuffix(path, ".json") && filepath.Base(path) != "timestamp.json" {
			data, err := os.ReadFile(path)
			if err != nil {
				log.Printf("Failed to read %s: %v", path, err)
				return nil
			}

			var result DomainResult
			if err := json.Unmarshal(data, &result); err != nil {
				log.Printf("Failed to parse %s: %v", path, err)
				return nil
			}

			results = append(results, result)
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	// Sort results by domain for deterministic output
	sort.Slice(results, func(i, j int) bool {
		return results[i].Domain < results[j].Domain
	})

	return results, nil
}

func readCrawlTimestamp(inputDir string) string {
	tsPath := filepath.Join(inputDir, "timestamp.json")
	data, err := os.ReadFile(tsPath)
	if err != nil {
		return ""
	}
	var ts struct{ Timestamp string }
	if err := json.Unmarshal(data, &ts); err != nil {
		return ""
	}
	return ts.Timestamp
}

func generateIndex(outputDir string, results []DomainResult, summary CAASummary, mainTmpl, homeTmpl *template.Template) error {
	// Read crawl timestamp from the input directory (not output)
	timestamp := readCrawlTimestamp(filepath.Dir(outputDir)) // Assumes input is parent of output
	pageGen := time.Now().UTC().Format(time.RFC3339)

	// Render home content into a buffer
	contentBuffer := new(bytes.Buffer)
	homeData := struct {
		Summary CAASummary
	}{
		Summary: summary,
	}
	if err := homeTmpl.Execute(contentBuffer, homeData); err != nil {
		return fmt.Errorf("error executing home template: %w", err)
	}

	data := struct {
		Timestamp     string
		PageGenerated string
		Results       []DomainResult
		Content       template.HTML
	}{
		Timestamp:     timestamp,
		PageGenerated: pageGen,
		Results:       results,
		Content:       template.HTML(contentBuffer.String()),
	}

	file, err := os.Create(filepath.Join(outputDir, "index.html"))
	if err != nil {
		return err
	}
	defer file.Close()

	if err := mainTmpl.Execute(file, data); err != nil {
		return err
	}

	// --- Write home.html snippet to snippets directory ---
	homeSnippetPath := filepath.Join(outputDir, "snippets", "home.html")
	if err := os.WriteFile(homeSnippetPath, contentBuffer.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write home snippet: %w", err)
	}

	return nil
}

func generateDomainPageAndSnippet(outputDir string, result DomainResult, allResults []DomainResult, domainTmpl, snippetTmpl *template.Template) error {
	timestamp := readCrawlTimestamp(filepath.Dir(outputDir))
	pageGen := time.Now().UTC().Format(time.RFC3339)

	templateData := struct {
		Timestamp     string
		PageGenerated string
		DomainResult  DomainResult
		Results       []DomainResult
		Content       template.HTML
	}{
		Timestamp:     timestamp,
		PageGenerated: pageGen,
		DomainResult:  result,
		Results:       allResults,
	}

	// Generate the snippet first
	snippetBuffer := new(bytes.Buffer)
	if err := snippetTmpl.Execute(snippetBuffer, templateData); err != nil {
		return fmt.Errorf("failed to execute snippet template for %s: %w", result.Domain, err)
	}

	// Write snippet to file
	snippetPath := filepath.Join(outputDir, "snippets", result.Domain+".html")
	if err := os.WriteFile(snippetPath, snippetBuffer.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write snippet for %s: %w", result.Domain, err)
	}

	// Now generate the full page
	templateData.Content = template.HTML(snippetBuffer.String())

	filename := filepath.Join(outputDir, result.Domain+".html")
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	return domainTmpl.Execute(file, templateData)
}

func generateProviderPagesAndSnippets(outputDir string, providers map[string]*CAProviderData, providerTmpl, providerSnippetTmpl *template.Template) error {
	timestamp := readCrawlTimestamp(filepath.Dir(outputDir))
	pageGen := time.Now().UTC().Format(time.RFC3339)

	for normalizedCA, provider := range providers {
		templateData := struct {
			Timestamp     string
			PageGenerated string
			Provider      *CAProviderData
			Content       template.HTML
		}{
			Timestamp:     timestamp,
			PageGenerated: pageGen,
			Provider:      provider,
		}

		// Generate the snippet first
		snippetBuffer := new(bytes.Buffer)
		if err := providerSnippetTmpl.Execute(snippetBuffer, templateData); err != nil {
			return fmt.Errorf("failed to execute provider snippet template for %s: %w", provider.CA, err)
		}

		// Write snippet to file
		snippetPath := filepath.Join(outputDir, "snippets", "providers", normalizedCA+".html")
		if err := os.WriteFile(snippetPath, snippetBuffer.Bytes(), 0644); err != nil {
			return fmt.Errorf("failed to write provider snippet for %s: %w", provider.CA, err)
		}

		// Now generate the full page
		templateData.Content = template.HTML(snippetBuffer.String())

		filename := filepath.Join(outputDir, "providers", normalizedCA+".html")
		file, err := os.Create(filename)
		if err != nil {
			return err
		}
		defer file.Close()

		if err := providerTmpl.Execute(file, templateData); err != nil {
			return fmt.Errorf("failed to execute provider template for %s: %w", provider.CA, err)
		}
	}

	log.Printf("Generated pages for %d certificate authorities", len(providers))
	return nil
}

func generateNavSnippet(outputDir string, results []DomainResult, navTmpl *template.Template) error {
	navData := struct {
		Results []DomainResult
	}{
		Results: results,
	}

	navBuffer := new(bytes.Buffer)
	if err := navTmpl.Execute(navBuffer, navData); err != nil {
		return fmt.Errorf("failed to execute nav template: %w", err)
	}

	navPath := filepath.Join(outputDir, "snippets", "nav.html")
	if err := os.WriteFile(navPath, navBuffer.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write nav snippet: %w", err)
	}

	return nil
}

func copyAssets(outputDir string) error {
	// Copy style.css to the output directory
	src := "assets/style.css"
	dst := filepath.Join(outputDir, "style.css")
	if err := copyFile(src, dst); err != nil {
		return fmt.Errorf("error copying style.css: %v", err)
	}
	return nil
}

// copyFile copies a file from source to destination.
func copyFile(source, destination string) error {
	srcFile, err := os.Open(source)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	destFile, err := os.Create(destination)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, srcFile)
	return err
}
