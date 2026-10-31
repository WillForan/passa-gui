.PHONY: tidy all
all:
	go build
tidy:
	go mod tidy
