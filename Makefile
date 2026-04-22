.PHONY: all clean run

all: crashrepro

crashrepro: $(wildcard src/*.c) $(wildcard src/*.h) build.sh
	./build.sh

clean:
	rm -f crashrepro
	rm -rf .zig-cache zig-cache zig-out

run: crashrepro
	./crashrepro
