#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "cpuid.h"
#include "fuzz.h"
#include "insns.h"
#include "logger.h"
#include "power.h"
#include "sighandler.h"

#define INTERRUPT_SIGNAL SIGUSR1
#define INTERRUPT_MIN_US 50u
#define INTERRUPT_MAX_US 250u

static int g_interrupt_rt_signal = 0;
static volatile sig_atomic_t g_interrupt_variant = INTERRUPT_VARIANT_NESTED;

static void usage(const char *prog) {
	fprintf(stderr,
		"usage: %s [flags]\n"
		"  --help                show this message\n"
		"  --seed=<u64>          base RNG seed (default: /dev/urandom)\n"
		"  --threads=<N>         worker threads (default: one per physical core\n"
		"                        when SMT antagonists are on, else nproc)\n"
		"  --iters=<N>           iterations per thread, 0=infinite (default: 0)\n"
		"  --classes=<csv>       restrict to these insn names; default: all\n"
		"  --shapes=<csv>        restrict to these operand shapes; default: all\n"
		"  --share-dst=<mode>    dst ownership mode: off|on|alternate (default: alternate)\n"
		"  --interrupts=<on|off> inject asynchronous signal pressure into workers (default: on)\n"
		"  --interrupt-variant=<basic|rt|nested> interrupt save/restore path\n"
		"                        to exercise when interrupts are on (default: nested)\n"
		"  --dirty-upper=<on|off> run an AVX2 warmup before each AVX-512 dispatch\n"
		"                        to enter with live upper YMM state (default: on)\n"
		"  --gather-scatter-partial-fault=<on|off> provoke mixed valid/faulting\n"
		"                        gather/scatter lanes and recover the fault (default: on)\n"
		"  --tlb-noise=<on|off>  run a helper thread that churns page protections\n"
		"                        to force TLB shootdowns during bursts (default: on)\n"
		"  --smt-antagonist=<on|off> reserve SMT siblings for AVX2-only antagonist\n"
		"                        threads; default worker count becomes one per core (default: on)\n"
		"  --fork-churn=<on|off> occasionally fork after a hot AVX-512 iteration\n"
		"                        and probe one child-side vmovdqu64 (default: on)\n"
		"  --churn-profile=<p>   power transition profile: random|passive|scalar|avx2|train\n"
		"  --churn-burst-us=<r>  AVX-512 burst range in microseconds: min:max or fixed\n"
		"  --churn-gap-us=<r>    gap range in microseconds: min:max or fixed\n"
		"  --churn-reentry-us=<r> re-entry burst range in microseconds: min:max or fixed\n"
		"  --list-churn-profiles print available churn profiles and exit\n"
		"  --verify=<on|off>     scalar oracle compare (default: on)\n"
		"  --churn=<on|off>      AVX-512 frequency/power churn (default: on)\n"
		"  --faults=<on|off>     AVX-512 loads/stores at intentionally bad\n"
		"                        addresses (SIGSEGV recovered and logged);\n"
		"                        default: on\n"
		"  --pin                 pin thread i to core i (default: off)\n"
		"  --quiet               suppress periodic progress output\n"
		"  --verbose             echo every iteration to the console\n"
		"  --logdir=<path>       durable log dir (default: /var/tmp/crashrepro)\n"
		"  --replay=<path>       dump last state from a log dir and exit\n"
		"  --list-classes        print instruction classes and exit\n"
		"  --list-shapes         print operand shapes and exit\n",
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

static share_dst_mode_t parse_share_dst_mode(const char *v) {
	if (!v || !*v) return SHARE_DST_ALTERNATE;
	if (!strcmp(v, "off") || !strcmp(v, "0") || !strcmp(v, "no")) {
		return SHARE_DST_OFF;
	}
	if (!strcmp(v, "on") || !strcmp(v, "1") || !strcmp(v, "yes")) {
		return SHARE_DST_ON;
	}
	if (!strcmp(v, "alternate") || !strcmp(v, "alt") || !strcmp(v, "mixed")) {
		return SHARE_DST_ALTERNATE;
	}
	fprintf(stderr, "bad share-dst mode: %s\n", v);
	exit(2);
}

static power_profile_t parse_power_profile(const char *v) {
	if (!v || !*v || !strcmp(v, "random")) return POWER_PROFILE_RANDOM;
	if (!strcmp(v, "passive") || !strcmp(v, "sleep")) return POWER_PROFILE_PASSIVE;
	if (!strcmp(v, "scalar")) return POWER_PROFILE_SCALAR;
	if (!strcmp(v, "avx2")) return POWER_PROFILE_AVX2;
	if (!strcmp(v, "train") || !strcmp(v, "reentry")) return POWER_PROFILE_TRAIN;
	fprintf(stderr, "bad churn profile: %s\n", v);
	exit(2);
}

static interrupt_variant_t parse_interrupt_variant(const char *v) {
	if (!v || !*v || !strcmp(v, "nested")) return INTERRUPT_VARIANT_NESTED;
	if (!strcmp(v, "basic") || !strcmp(v, "plain")) return INTERRUPT_VARIANT_BASIC;
	if (!strcmp(v, "rt") || !strcmp(v, "realtime")) return INTERRUPT_VARIANT_RT;
	fprintf(stderr, "bad interrupt variant: %s\n", v);
	exit(2);
}

static void parse_u32_range(const char *v, uint32_t *min_out, uint32_t *max_out) {
	char *end = NULL;
	unsigned long lo;
	unsigned long hi;
	if (!v || !*v) {
		fprintf(stderr, "empty numeric range\n");
		exit(2);
	}
	lo = strtoul(v, &end, 0);
	if (end == v || lo > 0xfffffffful) {
		fprintf(stderr, "bad numeric range: %s\n", v);
		exit(2);
	}
	if (*end == '\0') {
		*min_out = (uint32_t)lo;
		*max_out = (uint32_t)lo;
		return;
	}
	if (*end != ':') {
		fprintf(stderr, "bad numeric range: %s\n", v);
		exit(2);
	}
	hi = strtoul(end + 1, &end, 0);
	if (*end != '\0' || hi > 0xfffffffful || hi < lo) {
		fprintf(stderr, "bad numeric range: %s\n", v);
		exit(2);
	}
	*min_out = (uint32_t)lo;
	*max_out = (uint32_t)hi;
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

static uint32_t parse_shapes(const char *csv) {
	uint32_t mask = 0;
	const char *p = csv;
	if (!p || !*p) {
		fprintf(stderr, "empty shape list\n");
		exit(2);
	}
	while (*p) {
		const char *q = p;
		while (*q && *q != ',') q++;
		size_t n = (size_t)(q - p);
		int matched = 0;
		for (uint32_t i = 0; i < OPERAND_SHAPE_COUNT; i++) {
			const char *name = operand_shape_name(i);
			if (strlen(name) == n && strncmp(name, p, n) == 0) {
				mask |= 1u << i;
				matched = 1;
				break;
			}
		}
		if (!matched) {
			fprintf(stderr, "unknown operand shape: %.*s\n", (int)n, p);
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

static void list_shapes(void) {
	for (uint32_t i = 0; i < OPERAND_SHAPE_COUNT; i++) {
		printf("  %s\n", operand_shape_name(i));
	}
}

static void list_churn_profiles(void) {
	for (uint32_t i = 0; i < POWER_PROFILE_COUNT; i++) {
		printf("  %s\n", power_profile_name((power_profile_t)i));
	}
}

typedef struct {
	int worker_cpu;
	int antagonist_cpu;
} cpu_pair_t;

static int compare_ints(const void *lhs, const void *rhs) {
	int a = *(const int *)lhs;
	int b = *(const int *)rhs;
	return (a > b) - (a < b);
}

static int parse_cpu_list(const char *text, int *cpus, int max_cpus) {
	const char *p = text;
	int count = 0;

	while (*p) {
		char *end = NULL;
		long first;
		long last;

		while (*p == ' ' || *p == '\t' || *p == '\n') p++;
		if (*p == '\0') break;
		first = strtol(p, &end, 10);
		if (end == p || first < 0) return -1;
		last = first;
		p = end;
		if (*p == '-') {
			last = strtol(p + 1, &end, 10);
			if (end == p + 1 || last < first) return -1;
			p = end;
		}
		for (long cpu = first; cpu <= last; cpu++) {
			if (count >= max_cpus) return -1;
			cpus[count++] = (int)cpu;
		}
		while (*p == ' ' || *p == '\t') p++;
		if (*p == ',') p++;
	}
	if (count > 1) {
		qsort(cpus, (size_t)count, sizeof *cpus, compare_ints);
	}
	return count;
}

static int read_thread_siblings(int cpu, int *cpus, int max_cpus) {
	char path[256];
	char buf[256];
	FILE *fp;

	snprintf(path, sizeof path,
	         "/sys/devices/system/cpu/cpu%d/topology/thread_siblings_list",
	         cpu);
	fp = fopen(path, "r");
	if (!fp) return -1;
	if (!fgets(buf, sizeof buf, fp)) {
		fclose(fp);
		return -1;
	}
	fclose(fp);
	return parse_cpu_list(buf, cpus, max_cpus);
}

static int discover_cpu_pairs(cpu_pair_t **pairs_out, uint32_t *pair_count_out) {
	long n = sysconf(_SC_NPROCESSORS_ONLN);
	int max_cpus = (n > 0) ? (int)n : 1;
	cpu_pair_t *pairs = calloc((size_t)max_cpus, sizeof *pairs);
	uint32_t pair_count = 0;

	if (!pairs) return -1;
	for (int cpu = 0; cpu < max_cpus; cpu++) {
		int siblings[32];
		int sibling_count = read_thread_siblings(cpu, siblings, 32);
		if (sibling_count < 2) continue;
		if (siblings[0] != cpu) continue;
		pairs[pair_count].worker_cpu = siblings[0];
		pairs[pair_count].antagonist_cpu = siblings[1];
		pair_count++;
	}
	if (pair_count == 0) {
		free(pairs);
		errno = ENODEV;
		return -1;
	}
	*pairs_out = pairs;
	*pair_count_out = pair_count;
	return 0;
}

static int pin_current_thread_to_cpu(int cpu) {
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	return sched_setaffinity(0, sizeof set, &set);
}

typedef struct {
	fuzz_cfg_t cfg;
	pthread_t  th;
	int        started;
	int        rc;
} worker_t;

typedef struct {
	worker_t   *workers;
	uint32_t    worker_count;
	int         signal_no;
	uint64_t    seed;
	_Atomic int stop;
	pthread_t   th;
} interrupt_pressure_t;

typedef struct {
	void      *mapping;
	size_t     page_size;
	uint8_t   *page;
	_Atomic int stop;
	pthread_t  th;
} tlb_noise_t;

typedef struct {
	int        cpu;
	uint32_t   worker_id;
	int        started;
	_Atomic int stop;
	pthread_t  th;
} antagonist_t;

static void interrupt_send_self_signal(int sig) {
	long tid;
	if (sig <= 0) return;
	tid = syscall(SYS_gettid);
	if (tid <= 0) return;
	(void)syscall(SYS_tgkill, getpid(), tid, sig);
}

static void interrupt_pressure_handler(int sig) {
	(void)sig;
	if (g_interrupt_variant == INTERRUPT_VARIANT_NESTED && g_interrupt_rt_signal > 0) {
		interrupt_send_self_signal(g_interrupt_rt_signal);
	}
}

static void interrupt_rt_handler(int sig) {
	(void)sig;
	power_interrupt_signal_probe();
}

static int choose_interrupt_rt_signal(void) {
	int rtmax = SIGRTMAX;
	int rtmin = SIGRTMIN;
	if (rtmax < rtmin) return -1;
	return rtmax;
}

static int install_interrupt_pressure_handlers(interrupt_variant_t variant) {
	struct sigaction sa;

	g_interrupt_variant = variant;
	g_interrupt_rt_signal = choose_interrupt_rt_signal();
	if (g_interrupt_rt_signal < 0) {
		errno = EINVAL;
		return -1;
	}

	memset(&sa, 0, sizeof sa);
	sa.sa_handler = interrupt_pressure_handler;
	sa.sa_flags = SA_RESTART | SA_ONSTACK;
	sigemptyset(&sa.sa_mask);
	if (sigaction(INTERRUPT_SIGNAL, &sa, NULL) < 0) {
		return -1;
	}

	memset(&sa, 0, sizeof sa);
	sa.sa_handler = interrupt_rt_handler;
	sa.sa_flags = SA_RESTART | SA_ONSTACK;
	sigemptyset(&sa.sa_mask);
	return sigaction(g_interrupt_rt_signal, &sa, NULL);
}

static uint64_t interrupt_rng_next(uint64_t *state) {
	uint64_t x = *state ? *state : 0x9E3779B97F4A7C15ull;
	x ^= x >> 12;
	x ^= x << 25;
	x ^= x >> 27;
	*state = x;
	return x * 2685821657736338717ull;
}

static void *interrupt_pressure_entry(void *arg) {
	interrupt_pressure_t *pressure = arg;
	uint64_t state = pressure->seed ? pressure->seed : 1u;

	while (!atomic_load_explicit(&pressure->stop, memory_order_relaxed) &&
	       !fuzz_should_stop()) {
		int sent = 0;
		uint32_t start = (uint32_t)(interrupt_rng_next(&state) % pressure->worker_count);
		for (uint32_t offset = 0; offset < pressure->worker_count; offset++) {
			worker_t *worker = &pressure->workers[(start + offset) % pressure->worker_count];
			if (!worker->started) continue;
			(void)pthread_kill(worker->th, pressure->signal_no);
			sent = 1;
			break;
		}
		if (!sent) break;
		if ((interrupt_rng_next(&state) & 3u) == 0) {
			for (uint32_t i = 0; i < pressure->worker_count; i++) {
				if (!pressure->workers[i].started) continue;
				(void)pthread_kill(pressure->workers[i].th, pressure->signal_no);
			}
		}
		usleep((useconds_t)(INTERRUPT_MIN_US +
		       (interrupt_rng_next(&state) % (INTERRUPT_MAX_US - INTERRUPT_MIN_US + 1u))));
	}
	return NULL;
}

static void *tlb_noise_entry(void *arg) {
	tlb_noise_t *noise = arg;
	volatile uint8_t *page = (volatile uint8_t *)noise->page;

	while (!atomic_load_explicit(&noise->stop, memory_order_relaxed) &&
	       !fuzz_should_stop()) {
		(void)mprotect(noise->page, noise->page_size, PROT_NONE);
		(void)mprotect(noise->page, noise->page_size, PROT_READ | PROT_WRITE);
		page[0] ^= 1u;
		(void)madvise(noise->page, noise->page_size, MADV_DONTNEED);
	}
	return NULL;
}

static void *antagonist_entry(void *arg) {
	antagonist_t *antagonist = arg;
	if (pin_current_thread_to_cpu(antagonist->cpu) < 0) {
		fprintf(stderr, "warning: antagonist for worker %u pin(cpu=%d) failed: %s\n",
		        antagonist->worker_id, antagonist->cpu, strerror(errno));
	}
	while (!atomic_load_explicit(&antagonist->stop, memory_order_relaxed) &&
	       !fuzz_should_stop()) {
		power_avx2_antagonist_step();
		power_avx2_antagonist_step();
		power_avx2_antagonist_step();
		power_avx2_antagonist_step();
	}
	return NULL;
}

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
	int smt_antagonist_explicit = 0;
	uint64_t iters = 0;
	uint64_t class_mask = 0;
	uint32_t shape_mask = 0;
	share_dst_mode_t share_dst_mode = SHARE_DST_ALTERNATE;
	int interrupt_pressure = 1;
	interrupt_variant_t interrupt_variant = INTERRUPT_VARIANT_NESTED;
	int dirty_upper = 1;
	int gather_scatter_partial_fault = 1;
	int tlb_noise = 1;
	int smt_antagonist = 1;
	int fork_churn = 1;
	power_cfg_t power = power_cfg_default();
	int verify = 1;
	int churn = 1;
	int faults = 1;
	int pin = 0;
	int quiet = 0;
	int verbose = 0;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
			usage(argv[0]); return 0;
		} else if (!strcmp(argv[i], "--list-classes")) {
			list_classes(); return 0;
		} else if (!strcmp(argv[i], "--list-shapes")) {
			list_shapes(); return 0;
		} else if (!strcmp(argv[i], "--list-churn-profiles")) {
			list_churn_profiles(); return 0;
		} else if (!strncmp(argv[i], "--seed=", 7)) {
			seed = strtoull(argv[i] + 7, NULL, 0); have_seed = 1;
		} else if (!strncmp(argv[i], "--threads=", 10)) {
			threads = atoi(argv[i] + 10);
		} else if (!strncmp(argv[i], "--iters=", 8)) {
			iters = strtoull(argv[i] + 8, NULL, 0);
		} else if (!strncmp(argv[i], "--classes=", 10)) {
			class_mask = parse_classes(argv[i] + 10);
		} else if (!strncmp(argv[i], "--shapes=", 9)) {
			shape_mask = parse_shapes(argv[i] + 9);
		} else if (!strncmp(argv[i], "--share-dst=", 12)) {
			share_dst_mode = parse_share_dst_mode(argv[i] + 12);
		} else if (!strncmp(argv[i], "--interrupts=", 13)) {
			interrupt_pressure = parse_on_off(argv[i] + 13, 0);
		} else if (!strncmp(argv[i], "--interrupt-variant=", 20)) {
			interrupt_variant = parse_interrupt_variant(argv[i] + 20);
		} else if (!strncmp(argv[i], "--dirty-upper=", 14)) {
			dirty_upper = parse_on_off(argv[i] + 14, 1);
		} else if (!strncmp(argv[i], "--gather-scatter-partial-fault=", 31)) {
			gather_scatter_partial_fault = parse_on_off(argv[i] + 31, 1);
		} else if (!strncmp(argv[i], "--tlb-noise=", 12)) {
			tlb_noise = parse_on_off(argv[i] + 12, 1);
		} else if (!strncmp(argv[i], "--smt-antagonist=", 17)) {
			smt_antagonist_explicit = 1;
			smt_antagonist = parse_on_off(argv[i] + 17, 1);
		} else if (!strncmp(argv[i], "--fork-churn=", 13)) {
			fork_churn = parse_on_off(argv[i] + 13, 1);
		} else if (!strncmp(argv[i], "--churn-profile=", 16)) {
			power.profile = parse_power_profile(argv[i] + 16);
		} else if (!strncmp(argv[i], "--churn-burst-us=", 17)) {
			parse_u32_range(argv[i] + 17, &power.burst_min_us, &power.burst_max_us);
		} else if (!strncmp(argv[i], "--churn-gap-us=", 15)) {
			parse_u32_range(argv[i] + 15, &power.gap_min_us, &power.gap_max_us);
		} else if (!strncmp(argv[i], "--churn-reentry-us=", 19)) {
			parse_u32_range(argv[i] + 19, &power.reentry_min_us, &power.reentry_max_us);
		} else if (!strncmp(argv[i], "--verify=", 9)) {
			verify = parse_on_off(argv[i] + 9, 1);
		} else if (!strncmp(argv[i], "--churn=", 8)) {
			churn = parse_on_off(argv[i] + 8, 1);
		} else if (!strncmp(argv[i], "--faults=", 9)) {
			faults = parse_on_off(argv[i] + 9, 1);
		} else if (!strcmp(argv[i], "--pin")) {
			pin = 1;
		} else if (!strcmp(argv[i], "--quiet")) {
			quiet = 1;
		} else if (!strcmp(argv[i], "--verbose")) {
			verbose = 1;
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
	cpu_pair_t *cpu_pairs = NULL;
	uint32_t cpu_pair_count = 0;
	if (smt_antagonist && discover_cpu_pairs(&cpu_pairs, &cpu_pair_count) < 0) {
		if (smt_antagonist_explicit) {
			fprintf(stderr, "error: SMT antagonist requested but sibling topology is unavailable\n");
			return 2;
		}
		fprintf(stderr, "warning: disabling SMT antagonist: sibling topology is unavailable\n");
		smt_antagonist = 0;
	}
	if (threads <= 0) {
		long n = sysconf(_SC_NPROCESSORS_ONLN);
		if (smt_antagonist && cpu_pair_count > 0) {
			threads = (int)cpu_pair_count;
		} else {
			threads = (n > 0) ? (int)n : 1;
		}
	}
	if (smt_antagonist && (threads <= 0 || (uint32_t)threads > cpu_pair_count)) {
		fprintf(stderr,
		        "error: --threads=%d requires %d worker/sibling pairs but only %u were discovered; use --smt-antagonist=off or lower --threads\n",
		        threads, threads, cpu_pair_count);
		free(cpu_pairs);
		return 2;
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

	printf("seed=0x%016llx threads=%d iters=%llu verify=%s churn=%s churn_profile=%s burst_us=%u:%u gap_us=%u:%u reentry_us=%u:%u faults=%s share_dst=%s interrupts=%s interrupt_variant=%s dirty_upper=%s partial_fault=%s tlb_noise=%s smt_antagonist=%s fork_churn=%s pin=%s logdir=%s\n",
	       (unsigned long long)seed, threads, (unsigned long long)iters,
	       verify ? "on" : "off", churn ? "on" : "off",
	       power_profile_name(power.profile),
	       power.burst_min_us, power.burst_max_us,
	       power.gap_min_us, power.gap_max_us,
	       power.reentry_min_us, power.reentry_max_us,
	       faults ? "on" : "off", share_dst_mode_name(share_dst_mode),
	       interrupt_pressure ? "on" : "off",
	       interrupt_variant_name(interrupt_variant),
	       dirty_upper ? "on" : "off",
	       gather_scatter_partial_fault ? "on" : "off",
	       tlb_noise ? "on" : "off",
	       smt_antagonist ? "on" : "off",
	       fork_churn ? "on" : "off",
	       smt_antagonist ? "auto" : (pin ? "on" : "off"), logdir);
	if (smt_antagonist) {
		printf("cpu-pairs:");
		for (int i = 0; i < threads; i++) {
			printf(" t%d=%d/%d", i, cpu_pairs[i].worker_cpu,
			       cpu_pairs[i].antagonist_cpu);
		}
		printf("\n");
	}

	if (sighandler_install_global(logdir) < 0) {
		fprintf(stderr, "error: cannot install crash handlers: %s\n",
		        strerror(errno));
		return 1;
	}
	if (interrupt_pressure && install_interrupt_pressure_handlers(interrupt_variant) < 0) {
		fprintf(stderr, "error: cannot install interrupt-pressure handler: %s\n",
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
	antagonist_t *antagonists = NULL;
	if (smt_antagonist) {
		antagonists = calloc((size_t)threads, sizeof *antagonists);
		if (!antagonists) {
			fprintf(stderr, "oom\n");
			free(cpu_pairs);
			free(ws);
			return 1;
		}
	}
	interrupt_pressure_t pressure;
	int pressure_started = 0;
	tlb_noise_t noise;
	int noise_started = 0;
	memset(&pressure, 0, sizeof pressure);
	memset(&noise, 0, sizeof noise);
	pressure.workers = ws;
	pressure.worker_count = (uint32_t)threads;
	pressure.signal_no = (interrupt_variant == INTERRUPT_VARIANT_RT) ? g_interrupt_rt_signal : INTERRUPT_SIGNAL;
	pressure.seed = seed ^ 0xA0761D6478BD642Full;
	if (tlb_noise) {
		long page_size = sysconf(_SC_PAGESIZE);
		noise.page_size = (size_t)((page_size > 0) ? page_size : 4096);
		noise.mapping = mmap(NULL, noise.page_size, PROT_READ | PROT_WRITE,
		                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (noise.mapping == MAP_FAILED) {
			noise.mapping = NULL;
			tlb_noise = 0;
			fprintf(stderr, "warning: tlb noise disabled: mmap failed\n");
		} else {
			noise.page = (uint8_t *)noise.mapping;
			if (pthread_create(&noise.th, NULL, tlb_noise_entry, &noise) != 0) {
				fprintf(stderr, "warning: tlb noise disabled: pthread_create failed\n");
				munmap(noise.mapping, noise.page_size);
				noise.mapping = NULL;
				tlb_noise = 0;
			} else {
				noise_started = 1;
			}
		}
	}

	for (int i = 0; i < threads; i++) {
		ws[i].cfg.thread_id  = (uint32_t)i;
		ws[i].cfg.thread_count = (uint32_t)threads;
		ws[i].cfg.seed       = seed ^ ((uint64_t)i * 0x9E3779B97F4A7C15ull);
		ws[i].cfg.iters      = iters;
		ws[i].cfg.logdir     = logdir;
		ws[i].cfg.class_mask = class_mask;
		ws[i].cfg.shape_mask = shape_mask;
		ws[i].cfg.share_dst_mode = share_dst_mode;
		ws[i].cfg.interrupt_pressure = interrupt_pressure;
		ws[i].cfg.interrupt_variant = interrupt_variant;
		ws[i].cfg.dirty_upper = dirty_upper;
		ws[i].cfg.gather_scatter_partial_fault = gather_scatter_partial_fault;
		ws[i].cfg.tlb_noise = tlb_noise;
		ws[i].cfg.smt_antagonist = smt_antagonist;
		ws[i].cfg.fork_churn = fork_churn;
		ws[i].cfg.power      = power;
		ws[i].cfg.verify     = verify;
		ws[i].cfg.churn      = churn;
		ws[i].cfg.faults     = faults;
		ws[i].cfg.pin_core   = smt_antagonist ? cpu_pairs[i].worker_cpu : (pin ? i : -1);
		ws[i].cfg.quiet      = quiet;
		ws[i].cfg.verbose    = verbose;
		if (smt_antagonist) {
			antagonists[i].cpu = cpu_pairs[i].antagonist_cpu;
			antagonists[i].worker_id = (uint32_t)i;
			if (pthread_create(&antagonists[i].th, NULL, antagonist_entry,
			                   &antagonists[i]) != 0) {
				fprintf(stderr,
				        "warning: antagonist for worker %d disabled: pthread_create failed\n",
				        i);
				ws[i].cfg.smt_antagonist = 0;
			} else {
				antagonists[i].started = 1;
			}
		}
		if (pthread_create(&ws[i].th, NULL, worker_entry, &ws[i]) != 0) {
			fprintf(stderr, "pthread_create thread %d failed\n", i);
			fuzz_request_stop();
		} else {
			ws[i].started = 1;
		}
	}
	if (interrupt_pressure) {
		if (pthread_create(&pressure.th, NULL, interrupt_pressure_entry, &pressure) != 0) {
			fprintf(stderr, "warning: interrupt pressure disabled: pthread_create failed\n");
		} else {
			pressure_started = 1;
		}
	}

	int any_mismatch = 0;
	for (int i = 0; i < threads; i++) {
		if (!ws[i].started) continue;
		pthread_join(ws[i].th, NULL);
		if (ws[i].rc) any_mismatch = 1;
	}
	if (pressure_started) {
		atomic_store_explicit(&pressure.stop, 1, memory_order_relaxed);
		pthread_join(pressure.th, NULL);
	}
	if (noise_started) {
		atomic_store_explicit(&noise.stop, 1, memory_order_relaxed);
		pthread_join(noise.th, NULL);
	}
	for (int i = 0; i < threads; i++) {
		if (!antagonists || !antagonists[i].started) continue;
		atomic_store_explicit(&antagonists[i].stop, 1, memory_order_relaxed);
		pthread_join(antagonists[i].th, NULL);
	}
	if (noise.mapping) {
		munmap(noise.mapping, noise.page_size);
	}

	printf("all threads joined; mismatch=%d\n", any_mismatch);
	free(antagonists);
	free(cpu_pairs);
	free(ws);
	return any_mismatch;
}
