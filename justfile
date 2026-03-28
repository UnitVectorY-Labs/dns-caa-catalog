
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