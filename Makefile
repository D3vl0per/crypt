lint: 
	golangci-lint run --fix

test:
	go test -race -covermode=atomic -cover ./...

fast-test:
	go test ./...

test-v:
	go clean -testcache && go test ./... -v

golangci-lint-install:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.55.0

benchmark-compression:
	go test -benchmem -bench BenchmarkRoundTrip github.com/D3vl0per/crypt/compression -timeout 30m -benchtime=1s -count=6 | tee "compression-$(shell date --iso-8601=seconds).out"

coverage:
	go test -covermode=atomic -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	rm coverage.out
	google-chrome-stable coverage.html