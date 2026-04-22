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

static inline uint32_t bounded_dword_offset(uint32_t raw) {
	return raw & 60u;
}

static inline uint32_t load_u32_unaligned(const uint8_t *p) {
	uint32_t v;
	memcpy(&v, p, sizeof v);
	return v;
}

static void sanitize_scatter_offsets_dword(const void *b_in, uint32_t *off_out,
	                                       uint32_t lanes) {
	uint32_t raw[16];
	uint32_t slots[16];

	memcpy(raw, b_in, sizeof raw);
	for (uint32_t i = 0; i < lanes; i++) {
		slots[i] = i;
	}
	for (uint32_t i = 0; i < lanes; i++) {
		uint32_t remain = lanes - i;
		uint32_t pick = raw[i] % remain;
		off_out[i] = slots[pick] * 4u;
		slots[pick] = slots[remain - 1u];
	}
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

NOVEC void oracle_vpaddd(const void *a_in, const void *b_in, void *dst,
	                 uint64_t m, int zeromask) {
	const uint32_t *a = (const uint32_t *)a_in;
	const uint32_t *b = (const uint32_t *)b_in;
	uint32_t *d = (uint32_t *)dst;
	for (int i = 0; i < 16; i++) {
		if (mask_bit(m, i)) {
			d[i] = a[i] + b[i];
		} else if (zeromask) {
			d[i] = 0;
		}
	}
}

NOVEC void oracle_vpaddw(const void *a_in, const void *b_in, void *dst,
	                 uint64_t m, int zeromask) {
	const uint16_t *a = (const uint16_t *)a_in;
	const uint16_t *b = (const uint16_t *)b_in;
	uint16_t *d = (uint16_t *)dst;
	for (int i = 0; i < 32; i++) {
		if (mask_bit(m, i)) {
			d[i] = (uint16_t)(a[i] + b[i]);
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

static void oracle_vpexpandd_vl(const void *a_in, void *dst, uint64_t m,
	                            int zeromask, int lanes) {
	const uint32_t *a = (const uint32_t *)a_in;
	uint32_t old[16];
	uint32_t out[16] = {0};
	int src = 0;

	memcpy(old, dst, sizeof old);
	for (int i = 0; i < lanes; i++) {
		if (mask_bit(m, i)) {
			out[i] = a[src++];
		} else if (zeromask) {
			out[i] = 0;
		} else {
			out[i] = old[i];
		}
	}
	memcpy(dst, out, sizeof out);
}

static void oracle_vpcompressd_vl(const void *a_in, void *dst, uint64_t m,
	                             int lanes) {
	uint32_t src[16];
	uint32_t *d = (uint32_t *)dst;
	int out = 0;

	memcpy(src, a_in, sizeof src);
	for (int i = 0; i < lanes; i++) {
		if (mask_bit(m, i)) {
			d[out++] = src[i];
		}
	}
}

NOVEC void oracle_vpexpandd(const void *a_in, const void *b_in, void *dst,
	                    uint64_t m, int zeromask) {
	(void)b_in;
	oracle_vpexpandd_vl(a_in, dst, m, zeromask, 16);
}

NOVEC void oracle_vpexpandd_ymm(const void *a_in, const void *b_in, void *dst,
	                        uint64_t m, int zeromask) {
	(void)b_in;
	oracle_vpexpandd_vl(a_in, dst, m, zeromask, 8);
}

NOVEC void oracle_vpexpandd_xmm(const void *a_in, const void *b_in, void *dst,
	                        uint64_t m, int zeromask) {
	(void)b_in;
	oracle_vpexpandd_vl(a_in, dst, m, zeromask, 4);
}

NOVEC void oracle_vpgatherdd(const void *a_in, const void *b_in, void *dst,
	                    uint64_t m, int zeromask) {
	const uint32_t *idx = (const uint32_t *)a_in;
	const uint8_t *base = (const uint8_t *)b_in;
	uint32_t old[16];
	uint32_t out[16];

	memcpy(old, dst, sizeof old);
	for (int i = 0; i < 16; i++) {
		if (mask_bit(m, i)) {
			out[i] = load_u32_unaligned(base + bounded_dword_offset(idx[i]));
		} else if (zeromask) {
			out[i] = 0;
		} else {
			out[i] = old[i];
		}
	}
	memcpy(dst, out, sizeof out);
}

NOVEC void oracle_vpcompressd(const void *a_in, const void *b_in, void *dst,
	                       uint64_t m, int zeromask) {
	(void)b_in;
	(void)zeromask;
	oracle_vpcompressd_vl(a_in, dst, m, 16);
}

NOVEC void oracle_vpcompressd_ymm(const void *a_in, const void *b_in, void *dst,
	                           uint64_t m, int zeromask) {
	(void)b_in;
	(void)zeromask;
	oracle_vpcompressd_vl(a_in, dst, m, 8);
}

NOVEC void oracle_vpcompressd_xmm(const void *a_in, const void *b_in, void *dst,
	                           uint64_t m, int zeromask) {
	(void)b_in;
	(void)zeromask;
	oracle_vpcompressd_vl(a_in, dst, m, 4);
}

NOVEC void oracle_vpscatterdd(const void *a_in, const void *b_in, void *dst,
	                       uint64_t m, int zeromask) {
	uint32_t src[16];
	uint32_t off[16];
	uint8_t *d = (uint8_t *)dst;
	(void)zeromask;

	memcpy(src, a_in, sizeof src);
	sanitize_scatter_offsets_dword(b_in, off, 16u);
	for (int i = 0; i < 16; i++) {
		if (mask_bit(m, i)) {
			memcpy(d + off[i], &src[i], sizeof src[i]);
		}
	}
}

/* No-op oracle for the intentional-fault class: the executor is expected
 * to trap, and on recovery the dst buffer is left untouched — so the
 * oracle must leave it untouched too. */
NOVEC void oracle_intentional_fault(const void *a_in, const void *b_in,
                                    void *dst, uint64_t m, int zeromask) {
	(void)a_in; (void)b_in; (void)dst; (void)m; (void)zeromask;
}
