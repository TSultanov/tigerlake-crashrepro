#include "power.h"
#include "util.h"

#include <stdint.h>
#include <unistd.h>

/* One unit of "burst work": 16 independent AVX-512 integer ops with no
 * cross-register dependencies, designed to keep both vector pipes busy.
 * Operates on zmm16..zmm27 (EVEX-only encoding) to also exercise the
 * encoder path those registers go through. Uses vpxorq to pre-zero so
 * subsequent ops have defined inputs and we avoid slow-path denormals
 * that FMA on undefined data can trigger. */
static inline void burst_kernel(void) {
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

void power_churn_cycle(prng_t *p, power_stats_t *st) {
	/* Burst between 50 µs and 2 ms; gap between 10 µs and 200 µs.
	 * 50 µs is enough to demote the core to the AVX-512 license on Tiger
	 * Lake; 2 ms exceeds the license-hold window so the core is forced to
	 * downclock. The gap lets it ramp back up. */
	uint32_t r1 = prng_u32(p);
	uint32_t r2 = prng_u32(p);
	uint64_t burst_us = 50u + (r1 % 1950u);
	uint64_t gap_us   = 10u + (r2 % 190u);

	uint64_t start = now_ns();
	uint64_t end   = start + burst_us * 1000ull;
	uint64_t iters = 0;
	do {
		/* Unroll the kernel a few times so the now_ns() poll is amortised. */
		burst_kernel(); burst_kernel(); burst_kernel(); burst_kernel();
		burst_kernel(); burst_kernel(); burst_kernel(); burst_kernel();
		iters += 8;
	} while (now_ns() < end);

	usleep((useconds_t)gap_us);

	if (st) {
		st->bursts++;
		st->total_burst_ns += (now_ns() - start);
	}
	(void)iters;
}
