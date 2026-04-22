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

void power_churn_cycle(prng_t *p, power_stats_t *st) {
	/* Burst between 50 µs and 2 ms; gap between 10 µs and 200 µs.
	 * 50 µs is enough to demote the core to the AVX-512 license on Tiger
	 * Lake; 2 ms exceeds the license-hold window so the core is forced to
	 * downclock. The gap lets it ramp back up. */
	uint32_t r1 = prng_u32(p);
	uint32_t r2 = prng_u32(p);
	uint64_t burst_us = 50u + (r1 % 1950u);
	uint64_t gap_us   = 10u + (r2 % 190u);
	uint8_t mem[320] __attribute__((aligned(64)));

	for (size_t i = 0; i < sizeof mem; i += 8) {
		uint64_t v = prng_u64(p);
		*(uint64_t *)(void *)(mem + i) = v;
	}

	uint64_t start = now_ns();
	uint64_t end   = start + burst_us * 1000ull;
	uint64_t iters = 0;
	do {
		/* Unroll the kernel a few times so the now_ns() poll is amortised. */
		burst_kernel(p, mem); burst_kernel(p, mem); burst_kernel(p, mem); burst_kernel(p, mem);
		burst_kernel(p, mem); burst_kernel(p, mem); burst_kernel(p, mem); burst_kernel(p, mem);
		iters += 8;
	} while (now_ns() < end);

	usleep((useconds_t)gap_us);

	if (st) {
		st->bursts++;
		st->total_burst_ns += (now_ns() - start);
	}
	(void)iters;
}
