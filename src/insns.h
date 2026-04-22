#ifndef CRASHREPRO_INSNS_H
#define CRASHREPRO_INSNS_H

#include <stdint.h>

/* AVX-512 instruction class IDs. The on-disk log stores these verbatim as
 * uint32, so append-only — never renumber. */
typedef enum {
	INSN_VMOVDQU64 = 0,
	INSN_VMOVDQA64 = 1,
	INSN_VMOVDQU32 = 2,
	INSN_VMOVDQU8  = 3,
	INSN_VPADDQ    = 4,
	INSN_VPADDB    = 5,
	INSN_VPXORQ    = 6,
	INSN_VPTERNLOGQ_CA = 7,
	INSN_VPSLLVQ   = 8,
	INSN_VPMULLQ   = 9,
	INSN_VPOPCNTQ  = 10,
	INSN_VPLZCNTQ  = 11,

	INSN_CLASS_COUNT
} insn_class_t;

/* Unified contract for every class:
 *   a_in, b_in: 64 bytes each, aligned-or-not per the test shape.
 *   dst:        64 bytes; on entry holds the "original" destination used
 *               for merge-masking tests; on exit holds the result.
 *   mask:       full 64-bit k-register value. Each op uses only the low N
 *               bits matching its element granularity.
 *   zeromask:   non-zero selects {z}, zero selects merge-masking.
 * Unary ops ignore b_in. */
typedef void (*insn_fn_t)(const void *a_in, const void *b_in, void *dst,
                          uint64_t mask, int zeromask);

typedef struct {
	const char *name;
	int      needs_align64;  /* 1 for vmovdqa64 — fuzz loop must supply 64-aligned ptrs */
	int      binary;         /* 0 for unary / mov ops */
	insn_fn_t exec;          /* AVX-512 inline-asm version */
	insn_fn_t oracle;        /* scalar reference */
} insn_spec_t;

extern const insn_spec_t insn_specs[INSN_CLASS_COUNT];

const char *insn_name(uint32_t class_id);

#endif
