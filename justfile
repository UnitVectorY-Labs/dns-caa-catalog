
# Commands for dns-caa-catalog
default:
  @just --list
# Build dns-caa-catalog with Go
build:
  go build ./...

# Run tests for dns-caa-catalog with Go
test:
  go clean -testcache
  go test ./...

# Check maintained templates for HTMX 2.x patterns removed or changed in HTMX 4
htmx-check:
  npx --yes htmx.org@4.0.0 upgrade-check -- ./templates
