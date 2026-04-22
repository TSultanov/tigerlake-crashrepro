/* AVX-512 inline-asm executors for every class listed in insns.h.
 *
 * Conventions:
 * - Register bank: zmm0 = A, zmm1 = B, zmm2 = dst/result, k1 = mask.
 *   (A dedicated "bank B" using zmm28/29/30 + k3 lives at the end and is
 *   selected by the caller through _hi variants.)
 * - For merge-masking, the dst memory is loaded into zmm2 *before* the
 *   masked op so non-selected lanes keep their prior values — that mirrors
 *   what the hardware does with an in-register destination.
 * - vmovdqu{64,32,8} for loads/stores so unaligned offsets are legal;
 *   vmovdqa64 path uses aligned moves and the fuzz loop must hand in
 *   64-aligned pointers. */

#include "insns.h"

#include <stdint.h>
#include <string.h>

/* ---------- helpers ---------- */

#define LOAD_DST_ZMM2(ptr)                                     \
	"vmovdqu64 (" ptr "), %%zmm2\n\t"

#define STORE_ZMM2(ptr)                                        \
	"vmovdqu64 %%zmm2, (" ptr ")\n\t"

/* ---------- moves ---------- */

static void exec_vmovdqu64(const void *a, const void *b, void *dst,
                           uint64_t mask, int zeromask) {
	(void)b;
	if (zeromask) {
		__asm__ volatile(
			"kmovq %2, %%k1\n\t"
			"vmovdqu64 (%0), %%zmm2 %{%%k1%}%{z%}\n\t"
			"vmovdqu64 %%zmm2, (%1)\n\t"
			: : "r"(a), "r"(dst), "r"(mask)
			: "zmm2", "k1", "memory");
	} else {
		__asm__ volatile(
			"vmovdqu64 (%1), %%zmm2\n\t"
			"kmovq %2, %%k1\n\t"
			"vmovdqu64 (%0), %%zmm2 %{%%k1%}\n\t"
			"vmovdqu64 %%zmm2, (%1)\n\t"
			: : "r"(a), "r"(dst), "r"(mask)
			: "zmm2", "k1", "memory");
	}
}

static void exec_vmovdqa64(const void *a, const void *b, void *dst,
                           uint64_t mask, int zeromask) {
	(void)b;
	if (zeromask) {
		__asm__ volatile(
			"kmovq %2, %%k1\n\t"
			"vmovdqa64 (%0), %%zmm2 %{%%k1%}%{z%}\n\t"
			"vmovdqa64 %%zmm2, (%1)\n\t"
			: : "r"(a), "r"(dst), "r"(mask)
			: "zmm2", "k1", "memory");
	} else {
		__asm__ volatile(
			"vmovdqa64 (%1), %%zmm2\n\t"
			"kmovq %2, %%k1\n\t"
			"vmovdqa64 (%0), %%zmm2 %{%%k1%}\n\t"
			"vmovdqa64 %%zmm2, (%1)\n\t"
			: : "r"(a), "r"(dst), "r"(mask)
			: "zmm2", "k1", "memory");
	}
}

static void exec_vmovdqu32(const void *a, const void *b, void *dst,
                           uint64_t mask, int zeromask) {
	(void)b;
	if (zeromask) {
		__asm__ volatile(
			"kmovw %k2, %%k1\n\t"
			"vmovdqu32 (%0), %%zmm2 %{%%k1%}%{z%}\n\t"
			"vmovdqu64 %%zmm2, (%1)\n\t"
			: : "r"(a), "r"(dst), "r"((uint32_t)mask)
			: "zmm2", "k1", "memory");
	} else {
		__asm__ volatile(
			"vmovdqu64 (%1), %%zmm2\n\t"
			"kmovw %k2, %%k1\n\t"
			"vmovdqu32 (%0), %%zmm2 %{%%k1%}\n\t"
			"vmovdqu64 %%zmm2, (%1)\n\t"
			: : "r"(a), "r"(dst), "r"((uint32_t)mask)
			: "zmm2", "k1", "memory");
	}
}

static void exec_vmovdqu8(const void *a, const void *b, void *dst,
                          uint64_t mask, int zeromask) {
	(void)b;
	if (zeromask) {
		__asm__ volatile(
			"kmovq %2, %%k1\n\t"
			"vmovdqu8 (%0), %%zmm2 %{%%k1%}%{z%}\n\t"
			"vmovdqu64 %%zmm2, (%1)\n\t"
			: : "r"(a), "r"(dst), "r"(mask)
			: "zmm2", "k1", "memory");
	} else {
		__asm__ volatile(
			"vmovdqu64 (%1), %%zmm2\n\t"
			"kmovq %2, %%k1\n\t"
			"vmovdqu8 (%0), %%zmm2 %{%%k1%}\n\t"
			"vmovdqu64 %%zmm2, (%1)\n\t"
			: : "r"(a), "r"(dst), "r"(mask)
			: "zmm2", "k1", "memory");
	}
}

/* ---------- integer add ---------- */

static void exec_vpaddq(const void *a, const void *b, void *dst,
                        uint64_t mask, int zeromask) {
	if (zeromask) {
		__asm__ volatile(
			"vmovdqu64 (%0), %%zmm0\n\t"
			"vmovdqu64 (%1), %%zmm1\n\t"
			"kmovq %3, %%k1\n\t"
			"vpaddq %%zmm1, %%zmm0, %%zmm2 %{%%k1%}%{z%}\n\t"
			"vmovdqu64 %%zmm2, (%2)\n\t"
			: : "r"(a), "r"(b), "r"(dst), "r"(mask)
			: "zmm0", "zmm1", "zmm2", "k1", "memory");
	} else {
		__asm__ volatile(
			"vmovdqu64 (%0), %%zmm0\n\t"
			"vmovdqu64 (%1), %%zmm1\n\t"
			"vmovdqu64 (%2), %%zmm2\n\t"
			"kmovq %3, %%k1\n\t"
			"vpaddq %%zmm1, %%zmm0, %%zmm2 %{%%k1%}\n\t"
			"vmovdqu64 %%zmm2, (%2)\n\t"
			: : "r"(a), "r"(b), "r"(dst), "r"(mask)
			: "zmm0", "zmm1", "zmm2", "k1", "memory");
	}
}

static void exec_vpaddb(const void *a, const void *b, void *dst,
                        uint64_t mask, int zeromask) {
	if (zeromask) {
		__asm__ volatile(
			"vmovdqu64 (%0), %%zmm0\n\t"
			"vmovdqu64 (%1), %%zmm1\n\t"
			"kmovq %3, %%k1\n\t"
			"vpaddb %%zmm1, %%zmm0, %%zmm2 %{%%k1%}%{z%}\n\t"
			"vmovdqu64 %%zmm2, (%2)\n\t"
			: : "r"(a), "r"(b), "r"(dst), "r"(mask)
			: "zmm0", "zmm1", "zmm2", "k1", "memory");
	} else {
		__asm__ volatile(
			"vmovdqu64 (%0), %%zmm0\n\t"
			"vmovdqu64 (%1), %%zmm1\n\t"
			"vmovdqu64 (%2), %%zmm2\n\t"
			"kmovq %3, %%k1\n\t"
			"vpaddb %%zmm1, %%zmm0, %%zmm2 %{%%k1%}\n\t"
			"vmovdqu64 %%zmm2, (%2)\n\t"
			: : "r"(a), "r"(b), "r"(dst), "r"(mask)
			: "zmm0", "zmm1", "zmm2", "k1", "memory");
	}
}

/* ---------- logical ---------- */

static void exec_vpxorq(const void *a, const void *b, void *dst,
                        uint64_t mask, int zeromask) {
	if (zeromask) {
		__asm__ volatile(
			"vmovdqu64 (%0), %%zmm0\n\t"
			"vmovdqu64 (%1), %%zmm1\n\t"
			"kmovq %3, %%k1\n\t"
			"vpxorq %%zmm1, %%zmm0, %%zmm2 %{%%k1%}%{z%}\n\t"
			"vmovdqu64 %%zmm2, (%2)\n\t"
			: : "r"(a), "r"(b), "r"(dst), "r"(mask)
			: "zmm0", "zmm1", "zmm2", "k1", "memory");
	} else {
		__asm__ volatile(
			"vmovdqu64 (%0), %%zmm0\n\t"
			"vmovdqu64 (%1), %%zmm1\n\t"
			"vmovdqu64 (%2), %%zmm2\n\t"
			"kmovq %3, %%k1\n\t"
			"vpxorq %%zmm1, %%zmm0, %%zmm2 %{%%k1%}\n\t"
			"vmovdqu64 %%zmm2, (%2)\n\t"
			: : "r"(a), "r"(b), "r"(dst), "r"(mask)
			: "zmm0", "zmm1", "zmm2", "k1", "memory");
	}
}

/* ---------- ternary logic, fixed imm8=0xCA ---------- */

static void exec_vpternlogq_ca(const void *a, const void *b, void *dst,
                               uint64_t mask, int zeromask) {
	/* dst = f_{0xCA}(dst, a, b) per-bit. Destructive on zmm2. */
	if (zeromask) {
		__asm__ volatile(
			"vmovdqu64 (%0), %%zmm0\n\t"
			"vmovdqu64 (%1), %%zmm1\n\t"
			"vmovdqu64 (%2), %%zmm2\n\t"
			"kmovq %3, %%k1\n\t"
			"vpternlogq $0xCA, %%zmm1, %%zmm0, %%zmm2 %{%%k1%}%{z%}\n\t"
			"vmovdqu64 %%zmm2, (%2)\n\t"
			: : "r"(a), "r"(b), "r"(dst), "r"(mask)
			: "zmm0", "zmm1", "zmm2", "k1", "memory");
	} else {
		/* Merge-mask: pre-load dst twice is fine (same memory). */
		__asm__ volatile(
			"vmovdqu64 (%0), %%zmm0\n\t"
			"vmovdqu64 (%1), %%zmm1\n\t"
			"vmovdqu64 (%2), %%zmm2\n\t"
			"kmovq %3, %%k1\n\t"
			"vpternlogq $0xCA, %%zmm1, %%zmm0, %%zmm2 %{%%k1%}\n\t"
			"vmovdqu64 %%zmm2, (%2)\n\t"
			: : "r"(a), "r"(b), "r"(dst), "r"(mask)
			: "zmm0", "zmm1", "zmm2", "k1", "memory");
	}
}

/* ---------- variable shift ---------- */

static void exec_vpsllvq(const void *a, const void *b, void *dst,
                         uint64_t mask, int zeromask) {
	if (zeromask) {
		__asm__ volatile(
			"vmovdqu64 (%0), %%zmm0\n\t"
			"vmovdqu64 (%1), %%zmm1\n\t"
			"kmovq %3, %%k1\n\t"
			"vpsllvq %%zmm1, %%zmm0, %%zmm2 %{%%k1%}%{z%}\n\t"
			"vmovdqu64 %%zmm2, (%2)\n\t"
			: : "r"(a), "r"(b), "r"(dst), "r"(mask)
			: "zmm0", "zmm1", "zmm2", "k1", "memory");
	} else {
		__asm__ volatile(
			"vmovdqu64 (%0), %%zmm0\n\t"
			"vmovdqu64 (%1), %%zmm1\n\t"
			"vmovdqu64 (%2), %%zmm2\n\t"
			"kmovq %3, %%k1\n\t"
			"vpsllvq %%zmm1, %%zmm0, %%zmm2 %{%%k1%}\n\t"
			"vmovdqu64 %%zmm2, (%2)\n\t"
			: : "r"(a), "r"(b), "r"(dst), "r"(mask)
			: "zmm0", "zmm1", "zmm2", "k1", "memory");
	}
}

/* ---------- qword multiply (AVX-512DQ) ---------- */

static void exec_vpmullq(const void *a, const void *b, void *dst,
                         uint64_t mask, int zeromask) {
	if (zeromask) {
		__asm__ volatile(
			"vmovdqu64 (%0), %%zmm0\n\t"
			"vmovdqu64 (%1), %%zmm1\n\t"
			"kmovq %3, %%k1\n\t"
			"vpmullq %%zmm1, %%zmm0, %%zmm2 %{%%k1%}%{z%}\n\t"
			"vmovdqu64 %%zmm2, (%2)\n\t"
			: : "r"(a), "r"(b), "r"(dst), "r"(mask)
			: "zmm0", "zmm1", "zmm2", "k1", "memory");
	} else {
		__asm__ volatile(
			"vmovdqu64 (%0), %%zmm0\n\t"
			"vmovdqu64 (%1), %%zmm1\n\t"
			"vmovdqu64 (%2), %%zmm2\n\t"
			"kmovq %3, %%k1\n\t"
			"vpmullq %%zmm1, %%zmm0, %%zmm2 %{%%k1%}\n\t"
			"vmovdqu64 %%zmm2, (%2)\n\t"
			: : "r"(a), "r"(b), "r"(dst), "r"(mask)
			: "zmm0", "zmm1", "zmm2", "k1", "memory");
	}
}

/* ---------- unary: popcnt / lzcnt (AVX-512VPOPCNTDQ / CD) ---------- */

static void exec_vpopcntq(const void *a, const void *b, void *dst,
                          uint64_t mask, int zeromask) {
	(void)b;
	if (zeromask) {
		__asm__ volatile(
			"vmovdqu64 (%0), %%zmm0\n\t"
			"kmovq %2, %%k1\n\t"
			"vpopcntq %%zmm0, %%zmm2 %{%%k1%}%{z%}\n\t"
			"vmovdqu64 %%zmm2, (%1)\n\t"
			: : "r"(a), "r"(dst), "r"(mask)
			: "zmm0", "zmm2", "k1", "memory");
	} else {
		__asm__ volatile(
			"vmovdqu64 (%0), %%zmm0\n\t"
			"vmovdqu64 (%1), %%zmm2\n\t"
			"kmovq %2, %%k1\n\t"
			"vpopcntq %%zmm0, %%zmm2 %{%%k1%}\n\t"
			"vmovdqu64 %%zmm2, (%1)\n\t"
			: : "r"(a), "r"(dst), "r"(mask)
			: "zmm0", "zmm2", "k1", "memory");
	}
}

static void exec_vplzcntq(const void *a, const void *b, void *dst,
                          uint64_t mask, int zeromask) {
	(void)b;
	if (zeromask) {
		__asm__ volatile(
			"vmovdqu64 (%0), %%zmm0\n\t"
			"kmovq %2, %%k1\n\t"
			"vplzcntq %%zmm0, %%zmm2 %{%%k1%}%{z%}\n\t"
			"vmovdqu64 %%zmm2, (%1)\n\t"
			: : "r"(a), "r"(dst), "r"(mask)
			: "zmm0", "zmm2", "k1", "memory");
	} else {
		__asm__ volatile(
			"vmovdqu64 (%0), %%zmm0\n\t"
			"vmovdqu64 (%1), %%zmm2\n\t"
			"kmovq %2, %%k1\n\t"
			"vplzcntq %%zmm0, %%zmm2 %{%%k1%}\n\t"
			"vmovdqu64 %%zmm2, (%1)\n\t"
			: : "r"(a), "r"(dst), "r"(mask)
			: "zmm0", "zmm2", "k1", "memory");
	}
}

/* ---------- intentional fault executors ----------
 *
 * Each variant issues exactly one AVX-512 load or store through a caller-
 * supplied bad pointer and is expected to fault. noinline so RIP at the
 * fault points into the variant the caller selected, which makes it easy
 * to tell from a crash dump which encoding tripped. Store variants first
 * materialize a known constant in zmm2 so register state at fault is
 * predictable for post-mortem. */

static __attribute__((noinline))
void fault_load_u64(uintptr_t bad) {
	__asm__ volatile("vmovdqu64 (%0), %%zmm2\n\t"
	                 : : "r"(bad) : "zmm2", "memory");
}

static __attribute__((noinline))
void fault_store_u64(uintptr_t bad) {
	__asm__ volatile("vpxorq %%zmm2, %%zmm2, %%zmm2\n\t"
	                 "vmovdqu64 %%zmm2, (%0)\n\t"
	                 : : "r"(bad) : "zmm2", "memory");
}

static __attribute__((noinline))
void fault_load_a64(uintptr_t bad) {
	__asm__ volatile("vmovdqa64 (%0), %%zmm2\n\t"
	                 : : "r"(bad) : "zmm2", "memory");
}

static __attribute__((noinline))
void fault_store_a64(uintptr_t bad) {
	__asm__ volatile("vpxorq %%zmm2, %%zmm2, %%zmm2\n\t"
	                 "vmovdqa64 %%zmm2, (%0)\n\t"
	                 : : "r"(bad) : "zmm2", "memory");
}

static __attribute__((noinline))
void fault_load_u32(uintptr_t bad) {
	__asm__ volatile("vmovdqu32 (%0), %%zmm2\n\t"
	                 : : "r"(bad) : "zmm2", "memory");
}

static __attribute__((noinline))
void fault_store_u8(uintptr_t bad) {
	__asm__ volatile("vpxorq %%zmm2, %%zmm2, %%zmm2\n\t"
	                 "vmovdqu8 %%zmm2, (%0)\n\t"
	                 : : "r"(bad) : "zmm2", "memory");
}

static void exec_intentional_fault(const void *a, const void *b, void *dst,
                                   uint64_t mask, int zeromask) {
	(void)b; (void)dst; (void)zeromask;
	uintptr_t bad = (uintptr_t)a;
	uint32_t variant = (uint32_t)(mask & 0x7u);
	switch (variant) {
	case INSN_FAULT_VAR_LOAD_U64:  fault_load_u64(bad);  break;
	case INSN_FAULT_VAR_STORE_U64: fault_store_u64(bad); break;
	case INSN_FAULT_VAR_LOAD_A64:  fault_load_a64(bad);  break;
	case INSN_FAULT_VAR_STORE_A64: fault_store_a64(bad); break;
	case INSN_FAULT_VAR_LOAD_U32:  fault_load_u32(bad);  break;
	case INSN_FAULT_VAR_STORE_U8:  fault_store_u8(bad);  break;
	default:                       fault_load_u64(bad);  break;
	}
}

/* ---------- table ---------- */

/* Forward decls for oracle funcs (in insns_oracle.c). */
void oracle_vmovdqu64  (const void *a, const void *b, void *dst, uint64_t m, int z);
void oracle_vmovdqa64  (const void *a, const void *b, void *dst, uint64_t m, int z);
void oracle_vmovdqu32  (const void *a, const void *b, void *dst, uint64_t m, int z);
void oracle_vmovdqu8   (const void *a, const void *b, void *dst, uint64_t m, int z);
void oracle_vpaddq     (const void *a, const void *b, void *dst, uint64_t m, int z);
void oracle_vpaddb     (const void *a, const void *b, void *dst, uint64_t m, int z);
void oracle_vpxorq     (const void *a, const void *b, void *dst, uint64_t m, int z);
void oracle_vpternlogq_ca(const void *a, const void *b, void *dst, uint64_t m, int z);
void oracle_vpsllvq    (const void *a, const void *b, void *dst, uint64_t m, int z);
void oracle_vpmullq    (const void *a, const void *b, void *dst, uint64_t m, int z);
void oracle_vpopcntq   (const void *a, const void *b, void *dst, uint64_t m, int z);
void oracle_vplzcntq   (const void *a, const void *b, void *dst, uint64_t m, int z);
void oracle_intentional_fault(const void *a, const void *b, void *dst, uint64_t m, int z);

const insn_spec_t insn_specs[INSN_CLASS_COUNT] = {
	[INSN_VMOVDQU64]     = {"vmovdqu64",     0, 0, exec_vmovdqu64,     oracle_vmovdqu64},
	[INSN_VMOVDQA64]     = {"vmovdqa64",     1, 0, exec_vmovdqa64,     oracle_vmovdqa64},
	[INSN_VMOVDQU32]     = {"vmovdqu32",     0, 0, exec_vmovdqu32,     oracle_vmovdqu32},
	[INSN_VMOVDQU8]      = {"vmovdqu8",      0, 0, exec_vmovdqu8,      oracle_vmovdqu8},
	[INSN_VPADDQ]        = {"vpaddq",        0, 1, exec_vpaddq,        oracle_vpaddq},
	[INSN_VPADDB]        = {"vpaddb",        0, 1, exec_vpaddb,        oracle_vpaddb},
	[INSN_VPXORQ]        = {"vpxorq",        0, 1, exec_vpxorq,        oracle_vpxorq},
	[INSN_VPTERNLOGQ_CA] = {"vpternlogq_CA", 0, 1, exec_vpternlogq_ca, oracle_vpternlogq_ca},
	[INSN_VPSLLVQ]       = {"vpsllvq",       0, 1, exec_vpsllvq,       oracle_vpsllvq},
	[INSN_VPMULLQ]       = {"vpmullq",       0, 1, exec_vpmullq,       oracle_vpmullq},
	[INSN_VPOPCNTQ]      = {"vpopcntq",      0, 0, exec_vpopcntq,      oracle_vpopcntq},
	[INSN_VPLZCNTQ]      = {"vplzcntq",      0, 0, exec_vplzcntq,      oracle_vplzcntq},
	[INSN_INTENTIONAL_FAULT] = {"intentional_fault", 0, 0,
	                            exec_intentional_fault, oracle_intentional_fault},
};

const char *insn_name(uint32_t class_id) {
	if (class_id >= INSN_CLASS_COUNT) return "(unknown)";
	return insn_specs[class_id].name;
}
