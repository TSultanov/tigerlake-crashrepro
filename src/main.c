#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cpuid.h"
#include "prng.h"

static void usage(const char *prog) {
	fprintf(stderr,
		"usage: %s [--help] [--seed=<u64>]\n"
		"  AVX-512 crash-reproduction fuzzer for Intel i5-1135G7 (Tiger Lake).\n",
		prog);
}

static uint64_t random_seed(void) {
	uint64_t s = 0;
	int fd = open("/dev/urandom", O_RDONLY);
	if (fd >= 0) {
		if (read(fd, &s, sizeof s) != (ssize_t)sizeof s) s = 0;
		close(fd);
	}
	if (s == 0) s = (uint64_t)getpid() * 2654435761ull;
	return s;
}

int main(int argc, char **argv) {
	uint64_t seed = 0;
	int have_seed = 0;

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
			usage(argv[0]);
			return 0;
		}
		if (strncmp(argv[i], "--seed=", 7) == 0) {
			seed = strtoull(argv[i] + 7, NULL, 0);
			have_seed = 1;
		}
	}
	if (!have_seed) seed = random_seed();

	cpuinfo_t ci;
	cpuinfo_detect(&ci);
	cpuinfo_print(&ci);

	if (!ci.avx512f) {
		fprintf(stderr, "error: host CPU lacks AVX-512F; fuzzer cannot run.\n");
		return 2;
	}
	if (!ci.is_tigerlake) {
		fprintf(stderr,
			"warning: not running on Tiger Lake — results may not repro "
			"the target crash, but the fuzzer will run.\n");
	}

	printf("seed=0x%016llx\n", (unsigned long long)seed);

	/* Smoke-test the PRNG is deterministic from the seed. */
	prng_t p;
	prng_seed(&p, seed);
	printf("prng sample: %016llx %016llx %016llx\n",
	       (unsigned long long)prng_u64(&p),
	       (unsigned long long)prng_u64(&p),
	       (unsigned long long)prng_u64(&p));
	return 0;
}
