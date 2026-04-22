#include "fuzz.h"
#include "insns.h"
#include "logger.h"
#include "prng.h"
#include "sighandler.h"
#include "util.h"

#include <errno.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define PAGE_SIZE  4096u
#define PLAY_SIZE  (128u * 1024u)   /* per-region play area */

/* Layout for each worker's scratch: three regions (A, B, dst) each sandwiched
 * between PROT_NONE guard pages so walking off the end is a clean SIGSEGV
 * instead of silent memory corruption. */
typedef struct {
	uint8_t *a;
	uint8_t *b;
	uint8_t *dst;
	size_t   region_size;
	void    *mmap_base;
	size_t   mmap_size;
} scratch_t;

static _Atomic int g_stop = 0;

void fuzz_request_stop(void) { atomic_store_explicit(&g_stop, 1, memory_order_relaxed); }
int  fuzz_should_stop(void)  { return atomic_load_explicit(&g_stop, memory_order_relaxed); }

static int scratch_alloc(scratch_t *s) {
	/* [guard][A][guard][B][guard][DST][guard] */
	size_t total = PAGE_SIZE * 4 + PLAY_SIZE * 3;
	void *base = mmap(NULL, total, PROT_READ | PROT_WRITE,
	                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (base == MAP_FAILED) return -1;

	uint8_t *p = (uint8_t *)base;
	if (mprotect(p, PAGE_SIZE, PROT_NONE) < 0) goto fail;
	p += PAGE_SIZE;
	s->a = p; p += PLAY_SIZE;
	if (mprotect(p, PAGE_SIZE, PROT_NONE) < 0) goto fail;
	p += PAGE_SIZE;
	s->b = p; p += PLAY_SIZE;
	if (mprotect(p, PAGE_SIZE, PROT_NONE) < 0) goto fail;
	p += PAGE_SIZE;
	s->dst = p; p += PLAY_SIZE;
	if (mprotect(p, PAGE_SIZE, PROT_NONE) < 0) goto fail;

	s->region_size = PLAY_SIZE;
	s->mmap_base = base;
	s->mmap_size = total;
	return 0;
fail:
	munmap(base, total);
	return -1;
}

static void scratch_free(scratch_t *s) {
	if (s->mmap_base) munmap(s->mmap_base, s->mmap_size);
	memset(s, 0, sizeof *s);
}

/* Fill n bytes pseudo-randomly from p's state. */
static void fill_rand(prng_t *p, void *dst, size_t n) {
	uint8_t *d = dst;
	while (n >= 8) {
		uint64_t v = prng_u64(p);
		memcpy(d, &v, 8);
		d += 8; n -= 8;
	}
	if (n) {
		uint64_t v = prng_u64(p);
		memcpy(d, &v, n);
	}
}

/* Pick a 64-aligned offset within a region, optionally biased toward the
 * end so the 64-byte operand straddles a page boundary. */
static size_t pick_offset(prng_t *p, const insn_spec_t *spec, size_t region_size) {
	uint32_t r = prng_u32(p);
	size_t base_off;

	if ((r & 0x7) == 0) {
		/* 1/8 of the time: land the base 0..63 bytes before a page boundary
		 * to exercise page-straddling loads/stores. */
		uint32_t mod = r % (PAGE_SIZE - 64);
		base_off = (size_t)mod;
		/* round down to 64 so we can add a sub-cacheline offset below if
		 * alignment is flexible */
		base_off &= ~(size_t)63;
		/* position just below a page boundary */
		base_off = (base_off + PAGE_SIZE) - 64 * (1 + (r & 1));
	} else {
		base_off = ((size_t)r % (region_size - 128)) & ~(size_t)63;
	}

	if (spec->needs_align64) {
		return base_off;
	}
	/* Add 0..63 bytes of misalignment half the time. */
	if (prng_bool(p)) {
		base_off += (prng_u32(p) & 63);
		if (base_off > region_size - 64) base_off = region_size - 64;
	}
	return base_off;
}

/* Pick an interesting mask pattern. Mix of random and edge-case values
 * (all-ones, all-zeros, alternating, single-bit). */
static uint64_t pick_mask(prng_t *p) {
	switch (prng_u32(p) % 8) {
	case 0: return 0;                       /* all masked off */
	case 1: return ~(uint64_t)0;            /* no masking */
	case 2: return 0xAAAAAAAAAAAAAAAAull;   /* alternating */
	case 3: return 0x5555555555555555ull;   /* alternating */
	case 4: return 1ull << (prng_u32(p) & 63);      /* single bit */
	case 5: return ~(1ull << (prng_u32(p) & 63));   /* all but one */
	default: return prng_u64(p);
	}
}

int fuzz_run(const fuzz_cfg_t *cfg) {
	logger_t lg;
	if (logger_open(&lg, cfg->logdir, cfg->thread_id, cfg->seed) < 0) return -1;
	sighandler_thread_init(&lg);

	if (cfg->pin_core >= 0) {
		cpu_set_t set;
		CPU_ZERO(&set);
		CPU_SET(cfg->pin_core, &set);
		if (sched_setaffinity(0, sizeof set, &set) < 0) {
			fprintf(stderr, "t%u: sched_setaffinity(core=%d): %s\n",
			        cfg->thread_id, cfg->pin_core, strerror(errno));
		}
	}

	scratch_t s;
	if (scratch_alloc(&s) < 0) {
		fprintf(stderr, "t%u: scratch_alloc failed\n", cfg->thread_id);
		logger_close(&lg);
		return -1;
	}

	prng_t p;
	prng_seed(&p, cfg->seed);

	uint64_t mismatches = 0;
	uint64_t iter = 0;
	uint64_t report_every = 1ull << 16;   /* ~65k iters */
	uint64_t next_report = report_every;
	uint64_t last_ns = now_ns();

	/* Verification scratch (stack, 64 bytes each). */
	uint8_t v_a[64] __attribute__((aligned(64)));
	uint8_t v_b[64] __attribute__((aligned(64)));
	uint8_t v_dst_pre[64]  __attribute__((aligned(64)));
	uint8_t v_dst_post[64] __attribute__((aligned(64)));
	uint8_t v_dst_oracle[64] __attribute__((aligned(64)));

	while (!fuzz_should_stop() && (cfg->iters == 0 || iter < cfg->iters)) {
		/* Choose class, honouring optional bitmask filter. */
		uint32_t cls;
		if (cfg->class_mask) {
			do { cls = prng_u32(&p) % INSN_CLASS_COUNT; }
			while ((cfg->class_mask & (1ull << cls)) == 0);
		} else {
			cls = prng_u32(&p) % INSN_CLASS_COUNT;
		}
		const insn_spec_t *spec = &insn_specs[cls];

		size_t off_a   = pick_offset(&p, spec, s.region_size);
		size_t off_b   = pick_offset(&p, spec, s.region_size);
		size_t off_dst = pick_offset(&p, spec, s.region_size);
		uint64_t mask  = pick_mask(&p);
		int zeromask   = prng_bool(&p);

		uint8_t *a_ptr   = s.a   + off_a;
		uint8_t *b_ptr   = s.b   + off_b;
		uint8_t *dst_ptr = s.dst + off_dst;

		fill_rand(&p, v_a, 64);
		fill_rand(&p, v_b, 64);
		fill_rand(&p, v_dst_pre, 64);
		memcpy(a_ptr,   v_a,       64);
		memcpy(b_ptr,   v_b,       64);
		memcpy(dst_ptr, v_dst_pre, 64);

		uint64_t in_hash = fnv1a64(v_a, 64) ^
		                   fnv1a64(v_b, 64) ^
		                   fnv1a64(v_dst_pre, 64);
		uint32_t flags = (uint32_t)(zeromask ? 1u : 0u);
		log_entry_t *e = logger_begin(&lg, iter, cls, /*shape*/0,
		                              (uint32_t)(mask & 0xffffffffu),
		                              (uint32_t)(off_dst & 0xffffu),
		                              /*zmm_dst*/2, flags, in_hash);

		spec->exec(a_ptr, b_ptr, dst_ptr, mask, zeromask);
		memcpy(v_dst_post, dst_ptr, 64);
		uint64_t out_hash = fnv1a64(v_dst_post, 64);

		uint64_t status = 1;
		if (cfg->verify) {
			memcpy(v_dst_oracle, v_dst_pre, 64);
			spec->oracle(v_a, v_b, v_dst_oracle, mask, zeromask);
			if (memcmp(v_dst_oracle, v_dst_post, 64) != 0) {
				mismatches++;
				status = 2;
				if (!cfg->quiet) {
					fprintf(stderr,
						"t%u iter=%llu class=%s MISMATCH (mask=0x%016llx z=%d)\n",
						cfg->thread_id, (unsigned long long)iter,
						spec->name, (unsigned long long)mask, zeromask);
				}
			}
		}
		logger_end(&lg, e, out_hash, status);

		iter++;
		if (!cfg->quiet && iter == next_report) {
			uint64_t now = now_ns();
			double elapsed = (double)(now - last_ns) / 1e9;
			double rate = (double)report_every / elapsed;
			fprintf(stderr, "t%u iter=%llu rate=%.0f/s mismatches=%llu\n",
			        cfg->thread_id, (unsigned long long)iter,
			        rate, (unsigned long long)mismatches);
			last_ns = now;
			next_report += report_every;
		}
	}

	scratch_free(&s);
	logger_close(&lg);
	return mismatches ? 1 : 0;
}
