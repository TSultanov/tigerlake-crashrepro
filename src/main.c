#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(const char *prog) {
	fprintf(stderr,
		"usage: %s [--help]\n"
		"  AVX-512 crash-reproduction fuzzer for Intel i5-1135G7 (Tiger Lake).\n"
		"  See README.md for flags; this skeleton does nothing yet.\n",
		prog);
}

int main(int argc, char **argv) {
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
			usage(argv[0]);
			return 0;
		}
	}
	printf("crashrepro skeleton — build OK\n");
	return 0;
}
