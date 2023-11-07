lint: 
	golangci-lint run

test:
	go test -cover ./...

test-v:
	go test ./... -v

golangci-lint-install:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.55.0

coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	rm coverage.out
	google-chrome-stable coverage.html