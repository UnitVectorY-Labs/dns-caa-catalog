[![License](https://img.shields.io/badge/license-MIT-blue)](https://opensource.org/licenses/MIT) [![Active](https://img.shields.io/badge/Status-Active-green)](https://guide.unitvectorylabs.com/bestpractices/status/#active) [![Go Report Card](https://goreportcard.com/badge/github.com/UnitVectorY-Labs/dns-caa-catalog)](https://goreportcard.com/report/github.com/UnitVectorY-Labs/dns-caa-catalog)

# dns-caa-catalog

A Go CLI tool for tracking and publishing CAA (Certificate Authority Authorization) DNS records.

## Features

- **Crawl Command**: Performs DNS CAA lookups for domains and saves results as JSON
- **Generate Command**: Creates static HTML pages from crawl data
- **Concurrent Processing**: Configurable concurrency with rate limiting
- **Error Handling**: Retry mechanisms and comprehensive error reporting
- **Deterministic Output**: Sorted JSON keys and arrays for consistent results

## Automation

This repository is set to automatically udpate the CAA records for the top 10k sites once a day by retreiving them them and commiting the results as JSON to this repository.  The list of top 10k domains is also updated once a week.

## Building

```bash
go build -o dns-caa-catalog main.go
```

## Usage

### Crawl Command

Reads domains from a file and performs CAA DNS lookups:

```bash
./dns-caa-catalog -crawl [flags]
```

**Flags:**
- `-input, -i <path>`: Input domains file (default: `data/domains`)
- `-output, -o <path>`: Output directory (default: `caa`)
- `-concurrency, -c <int>`: Concurrent workers (default: 100)
- `-timeout, -t <duration>`: DNS timeout (default: 5s)
- `-retries, -r <int>`: Retry attempts (default: 3)

**Example:**
```bash
./dns-caa-catalog -crawl -i domains.txt -o results -c 5 -t 3s -r 2
```

### Generate Command

Creates static HTML pages from crawl JSON data:

```bash
./dns-caa-catalog -generate [flags]
```

**Flags:**
- `-input-dir, -i <path>`: Input directory with JSON files (default: `caa`)
- `-output-dir, -o <path>`: Output directory for HTML (default: `output`)

**Example:**
```bash
./dns-caa-catalog -generate -i results -o website
```

### Update Command

Fetches the latest top 10,000 domains from Cloudflare Radar and updates the input domains list:

```bash
./dns-caa-catalog -update
```

**Requirements:**
- Requires the `CLOUDFLARE_API_KEY` environment variable to be set with a valid Cloudflare API key.
- Overwrites the file at `data/domains` with the new list.

**Example:**
```bash
export CLOUDFLARE_API_KEY=your_api_key_here
./dns-caa-catalog -update
```

## Output Format

### JSON Output (from crawl)

Each domain gets a JSON file with the following structure:

```json
{
  "domain": "example.com",
  "records": ["0 issue \"letsencrypt.org\""],
  "issue": ["letsencrypt.org"],
  "issuewild": [],
  "iodef": [],
  "error": "optional error message"
}
```

Additionally, a `timestamp.json` file is created in the output directory:

```json
{
  "timestamp": "2025-07-10T23:16:42Z"
}
```
This represents when the crawl was started and is used for display in the generated HTML.

### HTML Output (from generate)

- `index.html`: Summary table of all domains with CAA status
- `<domain>.html`: Detailed page for each domain showing parsed CAA records
- `style.css`: Responsive stylesheet copied from `assets/`

## Requirements

- Latest version of Go
- `templates/` and `assets/` directories (for generate command)
- Standard library only (no external dependencies)

## Domain File Format

The input domains file should contain one domain per line:

```
google.com
example.org
test.example
```

Comments (lines starting with `#`) and empty lines are ignored.

## CAA Record Types

The tool categorizes CAA records into three types:

- **issue**: Authorize certificate issuance for the domain
- **issuewild**: Authorize wildcard certificate issuance  
- **iodef**: Specify incident reporting contact

## Error Handling

- DNS timeouts and failures are retried with exponential backoff
- Failed lookups are logged and saved with error details
- Invalid domains are processed but may result in DNS errors
- Missing input files cause immediate failure with non-zero exit code
Tracks CAA DNS configurations across top websites to surface insights on certificate issuance policies.
