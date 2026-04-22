#include "power.h"
#include "util.h"

#include <stdint.h>
#include <unistd.h>

/* One unit of burst work with no cross-register dependencies, designed to
 * keep both vector pipes busy. Operates on zmm16..zmm27 (EVEX-only
 * encoding) to also exercise the encoder path those registers go through. */
static inline void burst_kernel_independent(void) {
	__asm__ volatile(
		"vpxorq  %%zmm16, %%zmm16, %%zmm16\n\t"
		"vpxorq  %%zmm17, %%zmm17, %%zmm17\n\t"
		"vpxorq  %%zmm18, %%zmm18, %%zmm18\n\t"
		"vpxorq  %%zmm19, %%zmm19, %%zmm19\n\t"
		"vpaddq  %%zmm16, %%zmm17, %%zmm20\n\t"
		"vpaddq  %%zmm18, %%zmm19, %%zmm21\n\t"
		"vpmullq %%zmm20, %%zmm21, %%zmm22\n\t"
		"vpmullq %%zmm21, %%zmm20, %%zmm23\n\t"
		"vpxorq  %%zmm22, %%zmm23, %%zmm24\n\t"
		"vpxorq  %%zmm23, %%zmm22, %%zmm25\n\t"
		"vpaddq  %%zmm24, %%zmm25, %%zmm26\n\t"
		"vpaddq  %%zmm25, %%zmm24, %%zmm27\n\t"
		"vpmullq %%zmm26, %%zmm27, %%zmm16\n\t"
		"vpmullq %%zmm27, %%zmm26, %%zmm17\n\t"
		"vpxorq  %%zmm16, %%zmm17, %%zmm18\n\t"
		"vpxorq  %%zmm17, %%zmm16, %%zmm19\n\t"
		::: "zmm16","zmm17","zmm18","zmm19","zmm20","zmm21","zmm22","zmm23",
		    "zmm24","zmm25","zmm26","zmm27", "memory"
	);
}

/* A more serial burst shape that creates a long dependency chain instead of
 * pure throughput pressure. This stresses rename/forwarding and retirement
 * around the AVX-512 license transition rather than only raw execution rate. */
static inline void burst_kernel_dependent(void) {
	__asm__ volatile(
		"vpxorq  %%zmm16, %%zmm16, %%zmm16\n\t"
		"vpxorq  %%zmm17, %%zmm17, %%zmm17\n\t"
		"vpaddq  %%zmm17, %%zmm16, %%zmm16\n\t"
		"vpmullq %%zmm16, %%zmm16, %%zmm16\n\t"
		"vpxorq  %%zmm16, %%zmm17, %%zmm16\n\t"
		"vpaddq  %%zmm16, %%zmm17, %%zmm16\n\t"
		"vpmullq %%zmm16, %%zmm16, %%zmm16\n\t"
		"vpxorq  %%zmm16, %%zmm17, %%zmm16\n\t"
		"vpaddq  %%zmm16, %%zmm17, %%zmm16\n\t"
		"vpmullq %%zmm16, %%zmm16, %%zmm16\n\t"
		"vpxorq  %%zmm16, %%zmm17, %%zmm16\n\t"
		"vpaddq  %%zmm16, %%zmm17, %%zmm16\n\t"
		::: "zmm16", "zmm17", "memory"
	);
}

/* A memory-heavy burst that keeps issuing unaligned vmovdqu64 loads/stores
 * around integer AVX-512 ALU ops. The random 0..63-byte base skew ensures
 * cache-line and occasional page-subrange variation across churn cycles. */
static inline void burst_kernel_memory(uint8_t *base) {
	__asm__ volatile(
		"vmovdqu64   0(%0), %%zmm16\n\t"
		"vmovdqu64  64(%0), %%zmm17\n\t"
		"vmovdqu64 128(%0), %%zmm18\n\t"
		"vmovdqu64 192(%0), %%zmm19\n\t"
		"vpaddq   %%zmm17, %%zmm16, %%zmm20\n\t"
		"vpxorq   %%zmm19, %%zmm18, %%zmm21\n\t"
		"vpmullq  %%zmm21, %%zmm20, %%zmm22\n\t"
		"vpaddq   %%zmm22, %%zmm16, %%zmm23\n\t"
		"vmovdqu64 %%zmm20,   0(%0)\n\t"
		"vmovdqu64 %%zmm21,  64(%0)\n\t"
		"vmovdqu64 %%zmm22, 128(%0)\n\t"
		"vmovdqu64 %%zmm23, 192(%0)\n\t"
		:
		: "r"(base)
		: "zmm16", "zmm17", "zmm18", "zmm19", "zmm20", "zmm21", "zmm22", "zmm23", "memory"
	);
}

static inline void burst_kernel(prng_t *p, uint8_t *mem) {
	switch (prng_u32(p) % 3u) {
	case 0:
		burst_kernel_independent();
		break;
	case 1:
		burst_kernel_dependent();
		break;
	default:
		burst_kernel_memory(mem + (prng_u32(p) & 63u));
		break;
	}
}

/* Keep the core busy without issuing vector instructions so the AVX-512
 * license can decay while the thread remains hot and runnable. */
static inline void scalar_gap_kernel(uint64_t *state) {
	*state = (*state * 6364136223846793005ull) + 1442695040888963407ull;
	*state ^= *state >> 29;
	__asm__ volatile("" : "+r"(*state) :: "memory");
}

/* Bridge from AVX-512 into a lighter vector phase before re-entering AVX-512. */
static inline void avx2_gap_kernel(void) {
	__asm__ volatile(
		"vpxor %%ymm8, %%ymm8, %%ymm8\n\t"
		"vpxor %%ymm9, %%ymm9, %%ymm9\n\t"
		"vpaddq %%ymm8, %%ymm9, %%ymm10\n\t"
		"vpxor %%ymm10, %%ymm8, %%ymm11\n\t"
		"vpaddq %%ymm11, %%ymm10, %%ymm8\n\t"
		::: "ymm8", "ymm9", "ymm10", "ymm11", "memory"
	);
}

static void run_burst_window(prng_t *p, uint8_t *mem, uint64_t burst_us,
	                         uint64_t *iters_out) {
	uint64_t end = now_ns() + burst_us * 1000ull;
	do {
		burst_kernel(p, mem); burst_kernel(p, mem); burst_kernel(p, mem); burst_kernel(p, mem);
		burst_kernel(p, mem); burst_kernel(p, mem); burst_kernel(p, mem); burst_kernel(p, mem);
		if (iters_out) *iters_out += 8;
	} while (now_ns() < end);
}

static void run_scalar_gap_window(uint64_t gap_us) {
	uint64_t state = 0x2545F4914F6CDD1Dull;
	uint64_t end = now_ns() + gap_us * 1000ull;
	do {
		scalar_gap_kernel(&state);
		scalar_gap_kernel(&state);
		scalar_gap_kernel(&state);
		scalar_gap_kernel(&state);
		scalar_gap_kernel(&state);
		scalar_gap_kernel(&state);
		scalar_gap_kernel(&state);
		scalar_gap_kernel(&state);
	} while (now_ns() < end);
	(void)state;
}

static void run_avx2_gap_window(uint64_t gap_us) {
	uint64_t end = now_ns() + gap_us * 1000ull;
	do {
		avx2_gap_kernel(); avx2_gap_kernel(); avx2_gap_kernel(); avx2_gap_kernel();
		avx2_gap_kernel(); avx2_gap_kernel(); avx2_gap_kernel(); avx2_gap_kernel();
	} while (now_ns() < end);
}

static uint64_t pick_us(prng_t *p, uint32_t min_us, uint32_t max_us) {
	if (max_us <= min_us) return min_us;
	return min_us + (prng_u32(p) % (max_us - min_us + 1u));
}

void power_churn_plan(prng_t *p, const power_cfg_t *cfg, power_plan_t *plan) {
	power_cfg_t defaults;
	const power_cfg_t *use_cfg;

	defaults = power_cfg_default();
	use_cfg = cfg ? cfg : &defaults;
	plan->profile = use_cfg->profile;
	if (plan->profile == POWER_PROFILE_RANDOM) {
		plan->profile = (power_profile_t)(POWER_PROFILE_PASSIVE + (prng_u32(p) % 4u));
	}
	plan->burst_us = (uint32_t)pick_us(p, use_cfg->burst_min_us, use_cfg->burst_max_us);
	plan->gap_us = (uint32_t)pick_us(p, use_cfg->gap_min_us, use_cfg->gap_max_us);
	plan->reentry_us = (uint32_t)pick_us(p, use_cfg->reentry_min_us, use_cfg->reentry_max_us);
}

void power_churn_cycle(prng_t *p, const power_plan_t *plan, power_stats_t *st) {
	power_plan_t fallback;
	const power_plan_t *use_plan;
	uint8_t mem[320] __attribute__((aligned(64)));

	if (plan) {
		use_plan = plan;
	} else {
		power_churn_plan(p, NULL, &fallback);
		use_plan = &fallback;
	}

	for (size_t i = 0; i < sizeof mem; i += 8) {
		uint64_t v = prng_u64(p);
		*(uint64_t *)(void *)(mem + i) = v;
	}

	uint64_t start = now_ns();
	uint64_t iters = 0;
	switch (use_plan->profile) {
	case POWER_PROFILE_PASSIVE:
		/* Baseline: long AVX-512 burst followed by a passive cool-off. */
		run_burst_window(p, mem, use_plan->burst_us, &iters);
		usleep((useconds_t)use_plan->gap_us);
		break;
	case POWER_PROFILE_SCALAR:
		/* Decay the license while keeping the thread active in scalar code,
		 * then quickly re-enter AVX-512. */
		run_burst_window(p, mem, use_plan->burst_us, &iters);
		run_scalar_gap_window(use_plan->gap_us);
		run_burst_window(p, mem, use_plan->reentry_us, &iters);
		break;
	case POWER_PROFILE_AVX2:
		/* Bridge through an AVX2 phase before re-entering AVX-512. */
		run_burst_window(p, mem, use_plan->burst_us, &iters);
		run_avx2_gap_window(use_plan->gap_us);
		run_burst_window(p, mem, use_plan->reentry_us, &iters);
		break;
	case POWER_PROFILE_TRAIN:
	default:
		/* A train of shorter bursts separated by mixed tiny gaps to hit
		 * rapid downclock/ramp-up edges repeatedly in one cycle. */
		run_burst_window(p, mem, use_plan->burst_us / 2u + 1u, &iters);
		usleep((useconds_t)(use_plan->gap_us / 3u + 1u));
		run_burst_window(p, mem, use_plan->reentry_us, &iters);
		run_scalar_gap_window(use_plan->gap_us / 2u + 1u);
		run_burst_window(p, mem, use_plan->reentry_us, &iters);
		break;
	}

	if (st) {
		st->bursts++;
		st->total_burst_ns += (now_ns() - start);
	}
	(void)iters;
}
