lint: go-sec go-lint
	
go-lint:
	golangci-lint run

go-sec:
	gosec -no-fail ./...

go-test:
	go test ./...

go-test-v:
	go test ./... -v

lint-install: golangci-lint-install gosec-install

golangci-lint-install:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.55.0

gosec-install:
	go install github.com/securego/gosec/v2/cmd/gosec@latest
