#ifndef CRASHREPRO_CPUID_H
#define CRASHREPRO_CPUID_H

#include <stdint.h>

typedef struct {
	char vendor[13];     /* "GenuineIntel" + NUL */
	char brand[49];      /* brand string + NUL */
	uint32_t family;
	uint32_t model;      /* already combined with extended model */
	uint32_t stepping;

	int avx512f;
	int avx512dq;
	int avx512cd;
	int avx512bw;
	int avx512vl;
	int avx512vbmi;
	int avx512vbmi2;
	int avx512ifma;
	int avx512vnni;
	int avx512bitalg;
	int avx512vpopcntdq;

	/* True if this looks like the target Tiger Lake i5-1135G7 family.
	 * Used to warn — not to refuse to run on other hosts, since we also
	 * want to smoke-test on different AVX-512 SKUs. */
	int is_tigerlake;
} cpuinfo_t;

void cpuinfo_detect(cpuinfo_t *out);
void cpuinfo_print(const cpuinfo_t *ci);

#endif
