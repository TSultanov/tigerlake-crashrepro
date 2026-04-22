/* Scalar reference implementations for every class in insns.h.
 *
 * Each oracle is annotated NOVEC so clang/gcc will not lower it to AVX / AVX2
 * / AVX-512 instructions — which would defeat the whole purpose of having an
 * independent reference. SSE(2) remains available since the x86_64 ABI
 * requires it, and it plays no role in the crash we are chasing. */

#include <stdint.h>
#include <string.h>

#if defined(__clang__) || defined(__GNUC__)
#define NOVEC __attribute__((target("no-avx")))
#else
#define NOVEC
#endif

/* Helpers: extract mask bit for a given element at granularity G (bits). */
static inline int mask_bit(uint64_t m, int elem) {
	return (int)((m >> elem) & 1);
}

/* ---------- moves ---------- */

NOVEC void oracle_vmovdqu64(const void *a_in, const void *b_in, void *dst,
                      uint64_t m, int zeromask) {
	(void)b_in;
	const uint64_t *a = (const uint64_t *)a_in;
	uint64_t *d = (uint64_t *)dst;
	for (int i = 0; i < 8; i++) {
		if (mask_bit(m, i)) {
			d[i] = a[i];
		} else if (zeromask) {
			d[i] = 0;
		}
	}
}

NOVEC void oracle_vmovdqa64(const void *a, const void *b, void *dst,
                     uint64_t m, int z) {
	/* Same semantics as vmovdqu64 — only alignment differs at the asm level. */
	oracle_vmovdqu64(a, b, dst, m, z);
}

NOVEC void oracle_vmovdqu32(const void *a_in, const void *b_in, void *dst,
                     uint64_t m, int zeromask) {
	(void)b_in;
	const uint32_t *a = (const uint32_t *)a_in;
	uint32_t *d = (uint32_t *)dst;
	for (int i = 0; i < 16; i++) {
		if (mask_bit(m, i)) {
			d[i] = a[i];
		} else if (zeromask) {
			d[i] = 0;
		}
	}
}

NOVEC void oracle_vmovdqu8(const void *a_in, const void *b_in, void *dst,
                    uint64_t m, int zeromask) {
	(void)b_in;
	const uint8_t *a = (const uint8_t *)a_in;
	uint8_t *d = (uint8_t *)dst;
	for (int i = 0; i < 64; i++) {
		if (mask_bit(m, i)) {
			d[i] = a[i];
		} else if (zeromask) {
			d[i] = 0;
		}
	}
}

/* ---------- integer add ---------- */

NOVEC void oracle_vpaddq(const void *a_in, const void *b_in, void *dst,
                  uint64_t m, int zeromask) {
	const uint64_t *a = (const uint64_t *)a_in;
	const uint64_t *b = (const uint64_t *)b_in;
	uint64_t *d = (uint64_t *)dst;
	for (int i = 0; i < 8; i++) {
		if (mask_bit(m, i)) {
			d[i] = a[i] + b[i];
		} else if (zeromask) {
			d[i] = 0;
		}
	}
}

NOVEC void oracle_vpaddb(const void *a_in, const void *b_in, void *dst,
                  uint64_t m, int zeromask) {
	const uint8_t *a = (const uint8_t *)a_in;
	const uint8_t *b = (const uint8_t *)b_in;
	uint8_t *d = (uint8_t *)dst;
	for (int i = 0; i < 64; i++) {
		if (mask_bit(m, i)) {
			d[i] = (uint8_t)(a[i] + b[i]);
		} else if (zeromask) {
			d[i] = 0;
		}
	}
}

/* ---------- logical ---------- */

NOVEC void oracle_vpxorq(const void *a_in, const void *b_in, void *dst,
                  uint64_t m, int zeromask) {
	const uint64_t *a = (const uint64_t *)a_in;
	const uint64_t *b = (const uint64_t *)b_in;
	uint64_t *d = (uint64_t *)dst;
	for (int i = 0; i < 8; i++) {
		if (mask_bit(m, i)) {
			d[i] = a[i] ^ b[i];
		} else if (zeromask) {
			d[i] = 0;
		}
	}
}

/* ---------- ternary logic, fixed imm8=0xCA ---------- *
 *
 * Intel spec: VPTERNLOGQ dest, src1, src2, imm8.
 * Per-bit index = (dest_bit<<2) | (src1_bit<<1) | src2_bit.
 * Result bit = (imm8 >> index) & 1.
 * Our asm binds: dest=zmm2 (= dst arg), src1=zmm0 (= a_in), src2=zmm1 (= b_in).
 * Masking is at the qword granularity for vpternlogq. */

NOVEC void oracle_vpternlogq_ca(const void *a_in, const void *b_in, void *dst,
                         uint64_t m, int zeromask) {
	const uint64_t *a = (const uint64_t *)a_in;
	const uint64_t *b = (const uint64_t *)b_in;
	uint64_t *d = (uint64_t *)dst;
	const uint8_t imm8 = 0xCA;
	for (int i = 0; i < 8; i++) {
		uint64_t dv = d[i];
		uint64_t r = 0;
		for (int bit = 0; bit < 64; bit++) {
			unsigned db  = (unsigned)((dv    >> bit) & 1);
			unsigned s1b = (unsigned)((a[i] >> bit) & 1);
			unsigned s2b = (unsigned)((b[i] >> bit) & 1);
			unsigned idx = (db << 2) | (s1b << 1) | s2b;
			unsigned rb  = (imm8 >> idx) & 1;
			r |= (uint64_t)rb << bit;
		}
		if (mask_bit(m, i)) {
			d[i] = r;
		} else if (zeromask) {
			d[i] = 0;
		}
	}
}

/* ---------- variable shift ---------- *
 *
 * Intel: "if the shift count is greater than or equal to the operand size,
 *  the destination is set to 0" — per-qword. */

NOVEC void oracle_vpsllvq(const void *a_in, const void *b_in, void *dst,
                   uint64_t m, int zeromask) {
	const uint64_t *a = (const uint64_t *)a_in;
	const uint64_t *b = (const uint64_t *)b_in;
	uint64_t *d = (uint64_t *)dst;
	for (int i = 0; i < 8; i++) {
		uint64_t r = (b[i] >= 64) ? 0 : (a[i] << b[i]);
		if (mask_bit(m, i)) {
			d[i] = r;
		} else if (zeromask) {
			d[i] = 0;
		}
	}
}

/* ---------- qword multiply (low 64 bits) ---------- */

NOVEC void oracle_vpmullq(const void *a_in, const void *b_in, void *dst,
                   uint64_t m, int zeromask) {
	const uint64_t *a = (const uint64_t *)a_in;
	const uint64_t *b = (const uint64_t *)b_in;
	uint64_t *d = (uint64_t *)dst;
	for (int i = 0; i < 8; i++) {
		uint64_t r = a[i] * b[i];
		if (mask_bit(m, i)) {
			d[i] = r;
		} else if (zeromask) {
			d[i] = 0;
		}
	}
}

/* ---------- unary popcnt / lzcnt ---------- */

static inline uint64_t popcnt64(uint64_t x) {
#if defined(__GNUC__) || defined(__clang__)
	return (uint64_t)__builtin_popcountll(x);
#else
	uint64_t c = 0; while (x) { c += x & 1; x >>= 1; } return c;
#endif
}

static inline uint64_t lzcnt64(uint64_t x) {
	/* __builtin_clzll is UB for x==0; define 64 for x==0 to match
	 * the VPLZCNTQ spec ("leading zero count"; full width when 0). */
	if (x == 0) return 64;
#if defined(__GNUC__) || defined(__clang__)
	return (uint64_t)__builtin_clzll(x);
#else
	uint64_t c = 0; while (!(x & (1ull << 63))) { c++; x <<= 1; } return c;
#endif
}

NOVEC void oracle_vpopcntq(const void *a_in, const void *b_in, void *dst,
                    uint64_t m, int zeromask) {
	(void)b_in;
	const uint64_t *a = (const uint64_t *)a_in;
	uint64_t *d = (uint64_t *)dst;
	for (int i = 0; i < 8; i++) {
		uint64_t r = popcnt64(a[i]);
		if (mask_bit(m, i)) {
			d[i] = r;
		} else if (zeromask) {
			d[i] = 0;
		}
	}
}

NOVEC void oracle_vplzcntq(const void *a_in, const void *b_in, void *dst,
                    uint64_t m, int zeromask) {
	(void)b_in;
	const uint64_t *a = (const uint64_t *)a_in;
	uint64_t *d = (uint64_t *)dst;
	for (int i = 0; i < 8; i++) {
		uint64_t r = lzcnt64(a[i]);
		if (mask_bit(m, i)) {
			d[i] = r;
		} else if (zeromask) {
			d[i] = 0;
		}
	}
}
