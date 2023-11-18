lint: 
	golangci-lint run --fix

test:
	go clean -testcache && go test -race -cover ./...

test-v:
	go clean -testcache && go test ./... -v

golangci-lint-install:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.55.0

coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	rm coverage.out
	google-chrome-stable coverage.html