.PHONY: all test
all: passa-gui .make/test.log
test: .make/test.log
SRC := main.go backend.go
passa-gui: go.sum $(SRC)
	go build

go.sum: go.mod $(SRC)
	go mod tidy

.make/test.log: passa-gui | .make/
	go test | tee $@

%/:
	mkdir -p $@
