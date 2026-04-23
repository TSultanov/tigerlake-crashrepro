.PHONY: all clean run smoke

all: crashrepro

crashrepro: $(wildcard src/*.c) $(wildcard src/*.h) build.sh
	./build.sh

clean:
	rm -f crashrepro
	rm -rf .zig-cache zig-cache zig-out build

run: crashrepro
	./crashrepro

smoke: crashrepro
	./tests/smoke/run.sh
