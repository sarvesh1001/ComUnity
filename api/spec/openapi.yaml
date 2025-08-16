.PHONY: build run tidy swagger

build:
	go build -o bin/auth-service ./cmd/server

run:
	go run ./cmd/server

tidy:
	go mod tidy

swagger:
	swag init -g cmd/server/main.go -o api/swagger