.PHONY: all test
all: passa-gui .make/test.log
test: .make/test.log
SRC := main.go backend.go
passa-gui: go.sum $(SRC)
	go build

passa-gui.exe: go.sum $(SRC)
	GOOS=windows GOARCH=amd64 CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc go build -o $@

go.sum: go.mod $(SRC)
	go mod tidy

.make/test.log: passa-gui | .make/
	go test | tee $@

%/:
	mkdir -p $@
