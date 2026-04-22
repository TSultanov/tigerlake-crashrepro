#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cpuid.h"
#include "logger.h"
#include "prng.h"

static void usage(const char *prog) {
	fprintf(stderr,
		"usage: %s [flags]\n"
		"  --help                this message\n"
		"  --seed=<u64>          RNG seed (default: /dev/urandom)\n"
		"  --logdir=<path>       durable log dir (default: /var/tmp/crashrepro)\n"
		"  --replay=<path>       dump last state from a log dir and exit\n",
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
	const char *logdir = "/var/tmp/crashrepro";
	const char *replay = NULL;

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
			usage(argv[0]);
			return 0;
		} else if (strncmp(argv[i], "--seed=", 7) == 0) {
			seed = strtoull(argv[i] + 7, NULL, 0);
			have_seed = 1;
		} else if (strncmp(argv[i], "--logdir=", 9) == 0) {
			logdir = argv[i] + 9;
		} else if (strncmp(argv[i], "--replay=", 9) == 0) {
			replay = argv[i] + 9;
		} else {
			fprintf(stderr, "unknown flag: %s\n", argv[i]);
			usage(argv[0]);
			return 2;
		}
	}

	if (replay) {
		return logger_replay_dir(replay) == 0 ? 0 : 1;
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

	printf("seed=0x%016llx logdir=%s\n",
	       (unsigned long long)seed, logdir);

	/* Smoke test: open a logger, write a few dummy entries, close, replay. */
	logger_t lg;
	if (logger_open(&lg, logdir, 0, seed) < 0) return 1;

	prng_t p;
	prng_seed(&p, seed);
	for (uint64_t i = 0; i < 4; i++) {
		uint64_t inhash = prng_u64(&p);
		log_entry_t *e = logger_begin(&lg, i,
		                              /*insn_class*/0, /*shape*/0,
		                              /*mask*/0xffff, /*align*/0,
		                              /*zmm_dst*/0, /*flags*/0, inhash);
		logger_end(&lg, e, /*out*/inhash ^ 0xdeadbeef, /*status*/1);
	}
	logger_close(&lg);

	printf("logger smoke test OK; replay with: %s --replay=%s\n",
	       argv[0], logdir);
	return 0;
}
