.PHONY: tidy all
all: main
main: go.sum main.go
	go build

go.sum: go.mod
	go mod tidy
