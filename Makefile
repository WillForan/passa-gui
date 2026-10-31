.PHONY: tidy all
all: passa-gui
passa-gui: go.sum main.go
	go build

go.sum: go.mod
	go mod tidy
