test:
	go test ./... -race -count=2 -cover

check:
	test -z "$$(gofmt -l .)"
	go vet ./...
	go test ./... -race -count=2 -cover
	go build ./...
