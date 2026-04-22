#include "sighandler.h"
#include "fuzz.h"
#include "logger.h"

#include <errno.h>
#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ucontext.h>
#include <ucontext.h>
#include <unistd.h>

/* Per-thread state used from inside the signal handler. Must only be
 * accessed from the owning thread or via async-signal-safe loads/stores. */
static __thread logger_t *tls_logger = NULL;
static __thread int       tls_crash_fd = -1;
static __thread volatile sig_atomic_t tls_in_handler = 0;

/* Process-wide handler config. Written once before worker threads start,
 * then read by each thread during sighandler_thread_init(). */
static char g_logdir[512];

/* Expected-fault recovery state. See sighandler.h for the contract. */
__thread sigjmp_buf          sighandler_recovery_buf;
static __thread volatile int tls_expecting_fault = 0;
static __thread uint64_t     tls_expected_addr   = 0;
static __thread log_entry_t *tls_expected_entry  = NULL;

void sighandler_arm_expected_fault(uint64_t expected_addr, log_entry_t *e) {
	tls_expected_addr  = expected_addr;
	tls_expected_entry = e;
	/* Publish last so the handler never sees a stale entry pointer. */
	tls_expecting_fault = 1;
}

void sighandler_disarm_expected_fault(void) {
	tls_expecting_fault = 0;
	tls_expected_entry  = NULL;
	tls_expected_addr   = 0;
}

/* ---------- async-signal-safe writers ---------- */

static void safe_write(int fd, const char *s, size_t n) {
	while (n > 0) {
		ssize_t w = write(fd, s, n);
		if (w <= 0) return;
		s += w;
		n -= (size_t)w;
	}
}

static void safe_str(int fd, const char *s) {
	size_t n = 0;
	while (s[n]) n++;
	safe_write(fd, s, n);
}

static void safe_hex64(int fd, uint64_t v) {
	char buf[18];
	buf[0] = '0'; buf[1] = 'x';
	for (int i = 0; i < 16; i++) {
		int d = (int)((v >> (60 - 4 * i)) & 0xf);
		buf[2 + i] = (char)(d < 10 ? '0' + d : 'a' + d - 10);
	}
	safe_write(fd, buf, sizeof buf);
}

static void safe_u64(int fd, uint64_t v) {
	char tmp[24];
	int n = 0;
	if (v == 0) { safe_write(fd, "0", 1); return; }
	while (v && n < (int)sizeof tmp) { tmp[n++] = (char)('0' + (v % 10)); v /= 10; }
	char out[24];
	for (int i = 0; i < n; i++) out[i] = tmp[n - 1 - i];
	safe_write(fd, out, (size_t)n);
}

static void safe_reg(int fd, const char *name, uint64_t v) {
	safe_str(fd, "  "); safe_str(fd, name); safe_str(fd, "=");
	safe_hex64(fd, v);
	safe_str(fd, "\n");
}

/* ---------- handler install state (accessible from inside the handler) ---------- */

static struct sigaction g_sa;  /* template used to reinstall after recovery */

/* ---------- the handler ---------- */

static const char *sig_name(int s) {
	switch (s) {
	case SIGSEGV: return "SIGSEGV";
	case SIGILL:  return "SIGILL";
	case SIGBUS:  return "SIGBUS";
	case SIGFPE:  return "SIGFPE";
	case SIGTRAP: return "SIGTRAP";
	default:      return "SIG?";
	}
}

static void dump_mcontext(int fd, const mcontext_t *mc) {
#if defined(__x86_64__)
	const greg_t *g = mc->gregs;
	safe_reg(fd, "RIP", (uint64_t)g[REG_RIP]);
	safe_reg(fd, "RSP", (uint64_t)g[REG_RSP]);
	safe_reg(fd, "RBP", (uint64_t)g[REG_RBP]);
	safe_reg(fd, "RAX", (uint64_t)g[REG_RAX]);
	safe_reg(fd, "RBX", (uint64_t)g[REG_RBX]);
	safe_reg(fd, "RCX", (uint64_t)g[REG_RCX]);
	safe_reg(fd, "RDX", (uint64_t)g[REG_RDX]);
	safe_reg(fd, "RSI", (uint64_t)g[REG_RSI]);
	safe_reg(fd, "RDI", (uint64_t)g[REG_RDI]);
	safe_reg(fd, "R8",  (uint64_t)g[REG_R8]);
	safe_reg(fd, "R9",  (uint64_t)g[REG_R9]);
	safe_reg(fd, "R10", (uint64_t)g[REG_R10]);
	safe_reg(fd, "R11", (uint64_t)g[REG_R11]);
	safe_reg(fd, "R12", (uint64_t)g[REG_R12]);
	safe_reg(fd, "R13", (uint64_t)g[REG_R13]);
	safe_reg(fd, "R14", (uint64_t)g[REG_R14]);
	safe_reg(fd, "R15", (uint64_t)g[REG_R15]);
	safe_reg(fd, "EFLAGS", (uint64_t)g[REG_EFL]);
	safe_reg(fd, "ERR",    (uint64_t)g[REG_ERR]);
	safe_reg(fd, "TRAPNO", (uint64_t)g[REG_TRAPNO]);
	safe_reg(fd, "CR2",    (uint64_t)g[REG_CR2]);
#else
	(void)mc;
	safe_str(fd, "  (mcontext dump unavailable on this arch)\n");
#endif
}

static void dump_ring(int fd, const logger_t *lg) {
	if (!lg || !lg->map) return;
	const log_file_t *lf = lg->map;
	safe_str(fd, "thread="); safe_u64(fd, lf->thread_id);
	safe_str(fd, " seed=");  safe_hex64(fd, lf->seed);
	safe_str(fd, " iter=");  safe_u64(fd, lf->iter);
	safe_str(fd, "\n");

	/* Walk ring newest-first: the entry just before ring_pos is the most
	 * recently dispatched one. */
	uint32_t len = lf->ring_len;
	for (uint32_t i = 0; i < len; i++) {
		uint32_t idx = (lf->ring_pos + len - 1 - i) % len;
		const log_entry_t *e = &lf->entries[idx];
		if (e->timestamp_ns == 0) continue;
		safe_str(fd, "  [-"); safe_u64(fd, i); safe_str(fd, "] iter=");
		safe_u64(fd, e->iter);
		safe_str(fd, " insn="); safe_u64(fd, e->insn_class);
		safe_str(fd, " shape="); safe_u64(fd, e->operand_shape);
		safe_str(fd, "("); safe_str(fd, operand_shape_name(e->operand_shape)); safe_str(fd, ")");
		safe_str(fd, " dst="); safe_str(fd, (e->flags & LOG_FLAG_SHARED_DST) ? "shared" : "private");
		safe_str(fd, " irq="); safe_str(fd, (e->flags & LOG_FLAG_INTERRUPT_PRESSURE) ? "on" : "off");
		safe_str(fd, " churn=");
		if (e->flags & LOG_FLAG_CHURN_ACTIVE) {
			safe_str(fd, power_profile_name((power_profile_t)LOG_DECODE_CHURN_PROFILE(e->flags)));
		} else {
			safe_str(fd, "none");
		}
		safe_str(fd, " kreg="); safe_u64(fd, LOG_DECODE_KREG(e->flags));
		safe_str(fd, " mask="); safe_hex64(fd, e->mask_pattern);
		safe_str(fd, " off="); safe_u64(fd, e->alignment_offset);
		safe_str(fd, " zmm="); safe_u64(fd, e->zmm_dst);
		safe_str(fd, " flags="); safe_hex64(fd, e->flags);
		safe_str(fd, " status="); safe_u64(fd, e->status);
		safe_str(fd, " in="); safe_hex64(fd, e->input_hash);
		safe_str(fd, " out="); safe_hex64(fd, e->output_hash);
		safe_str(fd, "\n");
	}
}

/* Dumping bytes at RIP can re-fault (the crash may be jumping through a
 * bad pointer). SA_NODEFER lets that nested synchronous signal re-enter
 * the handler on the same thread, where tls_in_handler makes us fail
 * closed with an immediate _exit. This routine is therefore best-effort. */
static void dump_rip_bytes(int fd, uint64_t rip) {
	if (!rip) return;
	const uint8_t *base = (const uint8_t *)(rip - 32);
	safe_str(fd, "bytes @ RIP-32:\n  ");
	for (int i = 0; i < 64; i++) {
		uint8_t b = base[i];
		char hex[3];
		int hi = (b >> 4) & 0xf, lo = b & 0xf;
		hex[0] = (char)(hi < 10 ? '0' + hi : 'a' + hi - 10);
		hex[1] = (char)(lo < 10 ? '0' + lo : 'a' + lo - 10);
		hex[2] = ' ';
		safe_write(fd, hex, 3);
		if (i == 31) { safe_str(fd, "| "); }
		if (i % 16 == 15) { safe_str(fd, "\n  "); }
	}
	safe_str(fd, "\n");
}

static void handler(int sig, siginfo_t *info, void *ucontext_v) {
	if (tls_in_handler) {
		_exit(128 + sig);
	}
	tls_in_handler = 1;

	int fd = tls_crash_fd >= 0 ? tls_crash_fd : STDERR_FILENO;

	/* Expected-fault recovery fast-path. If the fuzz loop armed us, any
	 * SIGSEGV/SIGBUS on this thread is treated as expected: we're
	 * deliberately inside code that pokes invalid addresses with AVX-512,
	 * and the kernel-synthesized faults don't always carry a usable
	 * fault address (e.g. #GP from vmovdqa64 misalignment yields
	 * si_code=SI_KERNEL with si_addr=0 and CR2=0). The actual fault
	 * address, whatever we can recover, is still logged for triage.
	 *
	 * A fault outside an armed section still goes to the full dump. */
	if (tls_expecting_fault && (sig == SIGSEGV || sig == SIGBUS)) {
		uint64_t actual = (uint64_t)info->si_addr;
#if defined(__x86_64__)
		if (ucontext_v) {
			const ucontext_t *uc = (const ucontext_t *)ucontext_v;
			uint64_t cr2 = (uint64_t)uc->uc_mcontext.gregs[REG_CR2];
			if (cr2) actual = cr2;
		}
#endif
		log_entry_t *e = tls_expected_entry;
		tls_expecting_fault = 0;
		if (e) {
			e->actual_fault_addr = actual;
			e->status = LOG_STATUS_EXPECTED_FAULT;
			msync(e, sizeof *e, MS_SYNC);
		}
		safe_str(fd, "expected fault: sig=");
		safe_str(fd, sig_name(sig));
		safe_str(fd, " si_code=");
		safe_u64(fd, (uint64_t)info->si_code);
		safe_str(fd, " addr=");
		safe_hex64(fd, actual);
		safe_str(fd, " expected=");
		safe_hex64(fd, tls_expected_addr);
		safe_str(fd, "\n");
		tls_in_handler = 0;
		siglongjmp(sighandler_recovery_buf, 1);
	}

	safe_str(fd, "\n*** crashrepro: ");
	safe_str(fd, sig_name(sig));
	safe_str(fd, " si_code=");
	safe_u64(fd, (uint64_t)info->si_code);
	safe_str(fd, " si_addr=");
	safe_hex64(fd, (uint64_t)info->si_addr);
	safe_str(fd, "\n");

	if (ucontext_v) {
		const ucontext_t *uc = (const ucontext_t *)ucontext_v;
		dump_mcontext(fd, &uc->uc_mcontext);
	}
	dump_ring(fd, tls_logger);
	if (ucontext_v) {
		const ucontext_t *uc = (const ucontext_t *)ucontext_v;
#if defined(__x86_64__)
		dump_rip_bytes(fd, (uint64_t)uc->uc_mcontext.gregs[REG_RIP]);
#endif
	}

	/* fsync the crash fd so it survives a follow-on kernel panic. */
	if (tls_crash_fd >= 0) fsync(tls_crash_fd);

	/* Also flush the state ring file. */
	if (tls_logger && tls_logger->map) {
		msync(tls_logger->map, LOG_FILE_SIZE, MS_SYNC);
	}

	_exit(128 + sig);
}

/* ---------- install ---------- */

int sighandler_install_global(const char *logdir) {
	if (logdir) {
		size_t n = strlen(logdir);
		if (n >= sizeof g_logdir) n = sizeof g_logdir - 1;
		memcpy(g_logdir, logdir, n);
		g_logdir[n] = '\0';
	} else {
		g_logdir[0] = '\0';
	}

	memset(&g_sa, 0, sizeof g_sa);
	g_sa.sa_sigaction = handler;
	/* Keep synchronous faults re-entrant on the same thread so the handler
	 * can fail closed via tls_in_handler without dropping process-wide
	 * SIGSEGV/SIGBUS handlers for other threads. */
	g_sa.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_NODEFER;
	sigemptyset(&g_sa.sa_mask);

	const int sigs[] = { SIGSEGV, SIGILL, SIGBUS, SIGFPE, SIGTRAP };
	for (size_t i = 0; i < sizeof sigs / sizeof sigs[0]; i++) {
		if (sigaction(sigs[i], &g_sa, NULL) < 0) {
			return -1;
		}
	}
	return 0;
}

/* Per-thread state: alt stack and logger pointer. We allocate the alt
 * stack with mmap + guard pages so stack overflow in the handler is
 * itself caught. */
int sighandler_thread_init(logger_t *lg) {
	tls_logger = lg;

	const size_t stack_sz = 64 * 1024;
	void *stk = mmap(NULL, stack_sz, PROT_READ | PROT_WRITE,
	                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (stk == MAP_FAILED) return -1;

	stack_t ss;
	ss.ss_sp = stk;
	ss.ss_size = stack_sz;
	ss.ss_flags = 0;
	if (sigaltstack(&ss, NULL) < 0) return -1;

	if (lg && g_logdir[0]) {
		char path[1024];
		int pos = 0;
		for (const char *p = g_logdir; *p && pos < (int)sizeof(path) - 40; p++)
			path[pos++] = *p;
		const char suffix_fmt[] = "/crash.t";
		for (size_t i = 0; i < sizeof suffix_fmt - 1; i++) path[pos++] = suffix_fmt[i];
		uint32_t tid = lg->thread_id;
		if (tid == 0) {
			path[pos++] = '0';
		} else {
			char digits[12]; int n = 0;
			while (tid) { digits[n++] = (char)('0' + tid % 10); tid /= 10; }
			while (n--) path[pos++] = digits[n];
		}
		const char ext[] = ".log";
		for (size_t i = 0; i < sizeof ext - 1; i++) path[pos++] = ext[i];
		path[pos] = '\0';
		tls_crash_fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	}
	return 0;
}
