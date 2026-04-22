#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cpuid.h"
#include "fuzz.h"
#include "insns.h"
#include "logger.h"
#include "sighandler.h"

static void usage(const char *prog) {
	fprintf(stderr,
		"usage: %s [flags]\n"
		"  --help                show this message\n"
		"  --seed=<u64>          base RNG seed (default: /dev/urandom)\n"
		"  --threads=<N>         worker threads (default: nproc)\n"
		"  --iters=<N>           iterations per thread, 0=infinite (default: 0)\n"
		"  --classes=<csv>       restrict to these insn names; default: all\n"
		"  --verify=<on|off>     scalar oracle compare (default: on)\n"
		"  --pin                 pin thread i to core i (default: off)\n"
		"  --quiet               suppress periodic progress output\n"
		"  --logdir=<path>       durable log dir (default: /var/tmp/crashrepro)\n"
		"  --replay=<path>       dump last state from a log dir and exit\n"
		"  --list-classes        print instruction classes and exit\n",
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

static int parse_on_off(const char *v, int dflt) {
	if (!v || !*v) return dflt;
	if (!strcmp(v, "on") || !strcmp(v, "1") || !strcmp(v, "yes")) return 1;
	if (!strcmp(v, "off") || !strcmp(v, "0") || !strcmp(v, "no")) return 0;
	fprintf(stderr, "bad on/off value: %s\n", v);
	exit(2);
}

static uint64_t parse_classes(const char *csv) {
	uint64_t mask = 0;
	const char *p = csv;
	while (*p) {
		const char *q = p;
		while (*q && *q != ',') q++;
		size_t n = (size_t)(q - p);
		int matched = 0;
		for (uint32_t i = 0; i < INSN_CLASS_COUNT; i++) {
			const char *name = insn_specs[i].name;
			if (strlen(name) == n && strncmp(name, p, n) == 0) {
				mask |= 1ull << i;
				matched = 1;
				break;
			}
		}
		if (!matched) {
			fprintf(stderr, "unknown insn class: %.*s\n", (int)n, p);
			exit(2);
		}
		p = q + (*q ? 1 : 0);
	}
	return mask;
}

static void list_classes(void) {
	for (uint32_t i = 0; i < INSN_CLASS_COUNT; i++) {
		printf("  %s\n", insn_specs[i].name);
	}
}

typedef struct {
	fuzz_cfg_t cfg;
	pthread_t  th;
	int        rc;
} worker_t;

static void *worker_entry(void *arg) {
	worker_t *w = arg;
	w->rc = fuzz_run(&w->cfg);
	return NULL;
}

static void on_shutdown(int sig) {
	(void)sig;
	fuzz_request_stop();
}

int main(int argc, char **argv) {
	uint64_t seed = 0;
	int have_seed = 0;
	const char *logdir = "/var/tmp/crashrepro";
	const char *replay = NULL;
	int threads = 0;
	uint64_t iters = 0;
	uint64_t class_mask = 0;
	int verify = 1;
	int pin = 0;
	int quiet = 0;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
			usage(argv[0]); return 0;
		} else if (!strcmp(argv[i], "--list-classes")) {
			list_classes(); return 0;
		} else if (!strncmp(argv[i], "--seed=", 7)) {
			seed = strtoull(argv[i] + 7, NULL, 0); have_seed = 1;
		} else if (!strncmp(argv[i], "--threads=", 10)) {
			threads = atoi(argv[i] + 10);
		} else if (!strncmp(argv[i], "--iters=", 8)) {
			iters = strtoull(argv[i] + 8, NULL, 0);
		} else if (!strncmp(argv[i], "--classes=", 10)) {
			class_mask = parse_classes(argv[i] + 10);
		} else if (!strncmp(argv[i], "--verify=", 9)) {
			verify = parse_on_off(argv[i] + 9, 1);
		} else if (!strcmp(argv[i], "--pin")) {
			pin = 1;
		} else if (!strcmp(argv[i], "--quiet")) {
			quiet = 1;
		} else if (!strncmp(argv[i], "--logdir=", 9)) {
			logdir = argv[i] + 9;
		} else if (!strncmp(argv[i], "--replay=", 9)) {
			replay = argv[i] + 9;
		} else {
			fprintf(stderr, "unknown flag: %s\n", argv[i]);
			usage(argv[0]); return 2;
		}
	}

	if (replay) return logger_replay_dir(replay) == 0 ? 0 : 1;

	if (!have_seed) seed = random_seed();
	if (threads <= 0) {
		long n = sysconf(_SC_NPROCESSORS_ONLN);
		threads = (n > 0) ? (int)n : 1;
	}

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
			"the target crash.\n");
	}

	printf("seed=0x%016llx threads=%d iters=%llu verify=%s pin=%d logdir=%s\n",
	       (unsigned long long)seed, threads, (unsigned long long)iters,
	       verify ? "on" : "off", pin, logdir);

	if (sighandler_install_global(logdir) < 0) {
		fprintf(stderr, "error: cannot install crash handlers: %s\n",
		        strerror(errno));
		return 1;
	}

	/* Convert SIGINT / SIGTERM into graceful shutdown. These must be
	 * installed after sighandler_install_global so we override its default
	 * sigaction for these signals specifically. */
	struct sigaction sa;
	memset(&sa, 0, sizeof sa);
	sa.sa_handler = on_shutdown;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGINT,  &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	worker_t *ws = calloc((size_t)threads, sizeof *ws);
	if (!ws) { fprintf(stderr, "oom\n"); return 1; }

	for (int i = 0; i < threads; i++) {
		ws[i].cfg.thread_id  = (uint32_t)i;
		ws[i].cfg.seed       = seed ^ ((uint64_t)i * 0x9E3779B97F4A7C15ull);
		ws[i].cfg.iters      = iters;
		ws[i].cfg.logdir     = logdir;
		ws[i].cfg.class_mask = class_mask;
		ws[i].cfg.verify     = verify;
		ws[i].cfg.pin_core   = pin ? i : -1;
		ws[i].cfg.quiet      = quiet;
		if (pthread_create(&ws[i].th, NULL, worker_entry, &ws[i]) != 0) {
			fprintf(stderr, "pthread_create thread %d failed\n", i);
			fuzz_request_stop();
		}
	}

	int any_mismatch = 0;
	for (int i = 0; i < threads; i++) {
		pthread_join(ws[i].th, NULL);
		if (ws[i].rc) any_mismatch = 1;
	}

	printf("all threads joined; mismatch=%d\n", any_mismatch);
	free(ws);
	return any_mismatch;
}
