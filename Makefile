.PHONY: tidy all
all: passa-gui .make/test.log
passa-gui: go.sum main.go
	go build

go.sum: go.mod
	go mod tidy

.make/test.log: passa-gui | .make/
	go test | tee $@

%/:
	mkdir -p $@
