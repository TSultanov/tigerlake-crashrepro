#include "fuzz.h"
#include "insns.h"
#include "logger.h"
#include "power.h"
#include "prng.h"
#include "sighandler.h"
#include "util.h"

#include <errno.h>
#include <sched.h>
#include <setjmp.h>
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

typedef struct {
	uint8_t        *a_ptr;
	uint8_t        *b_ptr;
	uint8_t        *dst_ptr;
	operand_shape_t shape;
	size_t          off_dst;
} operand_layout_t;

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


#define SHAPE_BIT(shape) (1u << (shape))

static uint32_t shape_mask_for_spec(const insn_spec_t *spec) {
	uint32_t mask = SHAPE_BIT(OPERAND_SHAPE_DISTINCT) |
	                SHAPE_BIT(OPERAND_SHAPE_DST_EQ_A);

	if (spec->binary) {
		mask |= SHAPE_BIT(OPERAND_SHAPE_DST_EQ_B) |
		        SHAPE_BIT(OPERAND_SHAPE_A_EQ_B);
	}
	if (!spec->needs_align64) {
		mask |= SHAPE_BIT(OPERAND_SHAPE_DST_OVERLAPS_A) |
		        SHAPE_BIT(OPERAND_SHAPE_A_OVERLAPS_DST);
		if (spec->binary) {
			mask |= SHAPE_BIT(OPERAND_SHAPE_DST_OVERLAPS_B) |
			        SHAPE_BIT(OPERAND_SHAPE_B_OVERLAPS_DST);
		}
	}
	return mask;
}

static operand_shape_t pick_operand_shape(prng_t *p, const insn_spec_t *spec,
	                                      uint32_t requested_mask) {
	uint32_t mask = shape_mask_for_spec(spec);
	uint32_t allowed = requested_mask ? (requested_mask & mask) : mask;
	uint32_t picks[OPERAND_SHAPE_COUNT];
	uint32_t count = 0;

	for (uint32_t shape = 0; shape < OPERAND_SHAPE_COUNT; shape++) {
		if (allowed & SHAPE_BIT(shape)) {
			picks[count++] = shape;
		}
	}

	if (count == 0) {
		return OPERAND_SHAPE_DISTINCT;
	}
	return (operand_shape_t)picks[prng_u32(p) % count];
}

static size_t pick_overlap_delta(prng_t *p) {
	return 1u + (size_t)(prng_u32(p) & 63u);
}

static uint32_t pick_kreg(prng_t *p) {
	return INSN_KREG_MIN + (prng_u32(p) % (INSN_KREG_MAX - INSN_KREG_MIN + 1u));
}

static void choose_operand_layout(prng_t *p, const insn_spec_t *spec,
	                              const scratch_t *s, uint32_t shape_mask,
	                              operand_layout_t *layout) {
	operand_shape_t shape = pick_operand_shape(p, spec, shape_mask);
	size_t off_a = pick_offset(p, spec, s->region_size);
	size_t off_b = pick_offset(p, spec, s->region_size);
	size_t off_dst = pick_offset(p, spec, s->region_size);
	size_t delta;

	layout->shape = shape;
	layout->a_ptr = s->a + off_a;
	layout->b_ptr = s->b + off_b;
	layout->dst_ptr = s->dst + off_dst;
	layout->off_dst = off_dst;

	switch (shape) {
	case OPERAND_SHAPE_DST_EQ_A:
		off_dst = pick_offset(p, spec, s->region_size);
		layout->a_ptr = s->dst + off_dst;
		layout->dst_ptr = layout->a_ptr;
		layout->off_dst = off_dst;
		break;
	case OPERAND_SHAPE_DST_EQ_B:
		off_dst = pick_offset(p, spec, s->region_size);
		layout->b_ptr = s->dst + off_dst;
		layout->dst_ptr = layout->b_ptr;
		layout->off_dst = off_dst;
		break;
	case OPERAND_SHAPE_A_EQ_B:
		off_a = pick_offset(p, spec, s->region_size);
		layout->a_ptr = s->a + off_a;
		layout->b_ptr = layout->a_ptr;
		break;
	case OPERAND_SHAPE_DST_OVERLAPS_A:
		delta = pick_overlap_delta(p);
		off_a = pick_offset(p, spec, s->region_size - delta);
		layout->a_ptr = s->dst + off_a;
		layout->dst_ptr = layout->a_ptr + delta;
		layout->off_dst = off_a + delta;
		break;
	case OPERAND_SHAPE_A_OVERLAPS_DST:
		delta = pick_overlap_delta(p);
		off_dst = pick_offset(p, spec, s->region_size - delta);
		layout->dst_ptr = s->dst + off_dst;
		layout->a_ptr = layout->dst_ptr + delta;
		layout->off_dst = off_dst;
		break;
	case OPERAND_SHAPE_DST_OVERLAPS_B:
		delta = pick_overlap_delta(p);
		off_b = pick_offset(p, spec, s->region_size - delta);
		layout->b_ptr = s->dst + off_b;
		layout->dst_ptr = layout->b_ptr + delta;
		layout->off_dst = off_b + delta;
		break;
	case OPERAND_SHAPE_B_OVERLAPS_DST:
		delta = pick_overlap_delta(p);
		off_dst = pick_offset(p, spec, s->region_size - delta);
		layout->dst_ptr = s->dst + off_dst;
		layout->b_ptr = layout->dst_ptr + delta;
		layout->off_dst = off_dst;
		break;
	case OPERAND_SHAPE_DISTINCT:
	default:
		break;
	}
}

/* Pick a bad address for the intentional-fault class. Mixes fixed small
 * addresses that match real crash triage (0x14c, 0x1500), canonical-hole
 * and kernel-space addresses that trigger #GP, random small values, random
 * high-canonical values, and the PROT_NONE guard pages around the scratch
 * regions. */
static uint64_t pick_bad_addr(prng_t *p, const scratch_t *s) {
	static const uint64_t fixed_small[] = {
		0x0ull, 0x8ull, 0x14ull, 0x14cull, 0x1500ull, 0x10000ull,
	};
	static const uint64_t canonical_hole[] = {
		0xffffffffffffffc0ull,
		0xffff800000000000ull,
		0x0000800000000000ull,
	};

	uint32_t bucket = prng_u32(p) % 5;
	switch (bucket) {
	case 0:
		return fixed_small[prng_u32(p) % (sizeof fixed_small / sizeof fixed_small[0])];
	case 1:
		return canonical_hole[prng_u32(p) % (sizeof canonical_hole / sizeof canonical_hole[0])];
	case 2:
		return (uint64_t)(prng_u32(p) & 0xffffu);
	case 3:
		return 0xffff000000000000ull | (prng_u64(p) & 0x0000ffffffffffc0ull);
	default: {
		/* Target one of the three PROT_NONE guard pages. Guards sit at
		 * s->a - PAGE_SIZE, s->b - PAGE_SIZE, s->dst - PAGE_SIZE, and
		 * the trailing one at s->dst + region_size. */
		static const int which_max = 4;
		int which = (int)(prng_u32(p) % (uint32_t)which_max);
		uintptr_t base;
		switch (which) {
		case 0:  base = (uintptr_t)s->a - PAGE_SIZE; break;
		case 1:  base = (uintptr_t)s->b - PAGE_SIZE; break;
		case 2:  base = (uintptr_t)s->dst - PAGE_SIZE; break;
		default: base = (uintptr_t)s->dst + s->region_size; break;
		}
		return (uint64_t)(base + (prng_u32(p) % (PAGE_SIZE - 64)));
	}
	}
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
	lg.verbose = cfg->verbose;
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
	uint64_t expected_faults = 0;
	uint64_t missed_faults = 0;
	uint64_t iter = 0;
	uint64_t report_every = 1ull << 16;   /* ~65k iters */
	uint64_t next_report = report_every;
	uint64_t last_ns = now_ns();
	power_stats_t pwr = {0};

	/* Build the effective class mask. If the user gave one explicitly we
	 * use it verbatim; otherwise all classes are eligible but the
	 * intentional-fault class is opt-in via cfg->faults. */
	uint64_t effective_mask = cfg->class_mask;
	if (effective_mask == 0) {
		effective_mask = (1ull << INSN_CLASS_COUNT) - 1ull;
		if (!cfg->faults) {
			effective_mask &= ~(1ull << INSN_INTENTIONAL_FAULT);
		}
	}
	for (uint32_t cls = 0; cls < INSN_CLASS_COUNT; cls++) {
		if ((effective_mask & (1ull << cls)) == 0) continue;
		if (cls == INSN_INTENTIONAL_FAULT) continue;
		if (cfg->shape_mask != 0 &&
		    (shape_mask_for_spec(&insn_specs[cls]) & cfg->shape_mask) == 0) {
			effective_mask &= ~(1ull << cls);
		}
	}
	if (effective_mask == 0) {
		fprintf(stderr,
		        "t%u: no enabled instruction classes are compatible with the selected operand shapes\n",
		        cfg->thread_id);
		scratch_free(&s);
		logger_close(&lg);
		return -1;
	}

	/* Verification scratch (stack, 64 bytes each). */
	uint8_t seed_a[64] __attribute__((aligned(64)));
	uint8_t seed_b[64] __attribute__((aligned(64)));
	uint8_t seed_dst[64] __attribute__((aligned(64)));
	uint8_t v_a[64] __attribute__((aligned(64)));
	uint8_t v_b[64] __attribute__((aligned(64)));
	uint8_t v_dst_pre[64]  __attribute__((aligned(64)));
	uint8_t v_dst_post[64] __attribute__((aligned(64)));
	uint8_t v_dst_oracle[64] __attribute__((aligned(64)));

	while (!fuzz_should_stop() && (cfg->iters == 0 || iter < cfg->iters)) {
		/* Choose class, honouring the effective mask computed above. */
		uint32_t cls;
		do { cls = prng_u32(&p) % INSN_CLASS_COUNT; }
		while ((effective_mask & (1ull << cls)) == 0);
		const insn_spec_t *spec = &insn_specs[cls];

		if (cls == INSN_INTENTIONAL_FAULT) {
			uint64_t bad = pick_bad_addr(&p, &s);
			uint32_t variant = prng_u32(&p) % INSN_FAULT_VAR_COUNT;
			log_entry_t *e = logger_begin_fault(&lg, iter, cls, /*flags*/0,
			                                    bad, variant);
			if (sigsetjmp(sighandler_recovery_buf, 1) == 0) {
				sighandler_arm_expected_fault(bad, e);
				/* Dispatch; handler should longjmp back before this
				 * returns. If the address happens to be mapped (unlikely
				 * — guards are PROT_NONE, canonical-hole values #GP), we
				 * reach the line below. */
				spec->exec((const void *)(uintptr_t)bad, NULL, NULL,
				           (uint64_t)variant, 0);
				sighandler_disarm_expected_fault();
				missed_faults++;
				logger_end(&lg, e, 0, LOG_STATUS_FAULT_MISSED);
				if (!cfg->quiet) {
					fprintf(stderr,
						"t%u iter=%llu class=%s FAULT_MISSED target=0x%016llx variant=%u\n",
						cfg->thread_id, (unsigned long long)iter,
						spec->name, (unsigned long long)bad, variant);
				}
			} else {
				/* Recovered via siglongjmp. The handler already set
				 * status=EXPECTED_FAULT and msync'd the entry. */
				expected_faults++;
			}
			iter++;
			goto end_of_iter;
		}

		operand_layout_t layout;
		uint32_t kreg;
		uint64_t mask  = pick_mask(&p);
		int zeromask   = prng_bool(&p);

		choose_operand_layout(&p, spec, &s, cfg->shape_mask, &layout);
		kreg = pick_kreg(&p);

		fill_rand(&p, seed_a, 64);
		fill_rand(&p, seed_b, 64);
		fill_rand(&p, seed_dst, 64);
		memcpy(layout.a_ptr,   seed_a,   64);
		memcpy(layout.b_ptr,   seed_b,   64);
		memcpy(layout.dst_ptr, seed_dst, 64);
		memcpy(v_a,       layout.a_ptr,   64);
		memcpy(v_b,       layout.b_ptr,   64);
		memcpy(v_dst_pre, layout.dst_ptr, 64);

		uint64_t in_hash = fnv1a64(v_a, 64) ^
		                   fnv1a64(v_b, 64) ^
		                   fnv1a64(v_dst_pre, 64);
		uint32_t flags = (uint32_t)(zeromask ? LOG_FLAG_ZEROMASK : 0u) |
		                 LOG_ENCODE_KREG(kreg);
		log_entry_t *e = logger_begin(&lg, iter, cls, (uint32_t)layout.shape,
		                              (uint32_t)(mask & 0xffffffffu),
		                              (uint32_t)(layout.off_dst & 0xffffu),
		                              /*zmm_dst*/2, flags, in_hash);

		insn_set_kreg(kreg);
		spec->exec(layout.a_ptr, layout.b_ptr, layout.dst_ptr, mask, zeromask);
		memcpy(v_dst_post, layout.dst_ptr, 64);
		uint64_t out_hash = fnv1a64(v_dst_post, 64);

		uint64_t status = LOG_STATUS_OK;
		if (cfg->verify) {
			memcpy(v_dst_oracle, v_dst_pre, 64);
			spec->oracle(v_a, v_b, v_dst_oracle, mask, zeromask);
			if (memcmp(v_dst_oracle, v_dst_post, 64) != 0) {
				mismatches++;
				status = LOG_STATUS_MISMATCH;
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
	end_of_iter: ;

		/* Frequency/voltage churn: ~1 in 256 iterations, do a burst+gap.
		 * The burst drives the AVX-512 license and VR transient; the gap
		 * lets the core clock back up. Tiger Lake's suspected crash sits
		 * right on this transition, so this is a primary provocation. */
		if (cfg->churn && (prng_u32(&p) & 0xFFu) == 0) {
			power_churn_cycle(&p, &pwr);
		}

		if (!cfg->quiet && iter == next_report) {
			uint64_t now = now_ns();
			double elapsed = (double)(now - last_ns) / 1e9;
			double rate = (double)report_every / elapsed;
			fprintf(stderr,
				"t%u iter=%llu rate=%.0f/s mismatches=%llu churn_bursts=%llu expected_faults=%llu missed_faults=%llu\n",
				cfg->thread_id, (unsigned long long)iter,
				rate,
				(unsigned long long)mismatches,
				(unsigned long long)pwr.bursts,
				(unsigned long long)expected_faults,
				(unsigned long long)missed_faults);
			last_ns = now;
			next_report += report_every;
		}
	}

	scratch_free(&s);
	logger_close(&lg);
	return mismatches ? 1 : 0;
}
