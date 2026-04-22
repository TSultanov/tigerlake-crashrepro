#include "cpuid.h"

#include <stdio.h>
#include <string.h>

static inline void cpuid(uint32_t leaf, uint32_t sub,
                         uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
	__asm__ volatile("cpuid"
	                 : "=a"(*a), "=b"(*b), "=c"(*c), "=d"(*d)
	                 : "a"(leaf), "c"(sub));
}

void cpuinfo_detect(cpuinfo_t *out) {
	memset(out, 0, sizeof(*out));

	uint32_t a, b, c, d;
	cpuid(0, 0, &a, &b, &c, &d);
	uint32_t max_basic = a;
	memcpy(out->vendor + 0, &b, 4);
	memcpy(out->vendor + 4, &d, 4);
	memcpy(out->vendor + 8, &c, 4);
	out->vendor[12] = '\0';

	if (max_basic >= 1) {
		cpuid(1, 0, &a, &b, &c, &d);
		uint32_t family = (a >> 8) & 0xf;
		uint32_t model = (a >> 4) & 0xf;
		uint32_t ext_family = (a >> 20) & 0xff;
		uint32_t ext_model = (a >> 16) & 0xf;
		if (family == 0xf) family += ext_family;
		if (family == 0x6 || family == 0xf) model |= ext_model << 4;
		out->family = family;
		out->model = model;
		out->stepping = a & 0xf;
	}

	if (max_basic >= 7) {
		cpuid(7, 0, &a, &b, &c, &d);
		out->avx512f        = (b >> 16) & 1;
		out->avx512dq       = (b >> 17) & 1;
		out->avx512ifma     = (b >> 21) & 1;
		out->avx512cd       = (b >> 28) & 1;
		out->avx512bw       = (b >> 30) & 1;
		out->avx512vl       = (b >> 31) & 1;
		out->avx512vbmi     = (c >>  1) & 1;
		out->avx512vbmi2    = (c >>  6) & 1;
		out->avx512vnni     = (c >> 11) & 1;
		out->avx512bitalg   = (c >> 12) & 1;
		out->avx512vpopcntdq= (c >> 14) & 1;
	}

	cpuid(0x80000000, 0, &a, &b, &c, &d);
	uint32_t max_ext = a;
	if (max_ext >= 0x80000004) {
		uint32_t *bp = (uint32_t *)out->brand;
		cpuid(0x80000002, 0, &bp[0],  &bp[1],  &bp[2],  &bp[3]);
		cpuid(0x80000003, 0, &bp[4],  &bp[5],  &bp[6],  &bp[7]);
		cpuid(0x80000004, 0, &bp[8],  &bp[9],  &bp[10], &bp[11]);
		out->brand[48] = '\0';
	}

	/* Tiger Lake mobile (i5-1135G7 and friends): family 6, model 0x8C/0x8D. */
	out->is_tigerlake =
		strcmp(out->vendor, "GenuineIntel") == 0 &&
		out->family == 6 &&
		(out->model == 0x8C || out->model == 0x8D);
}

void cpuinfo_print(const cpuinfo_t *ci) {
	printf("CPU: %s\n", ci->brand[0] ? ci->brand : "(unknown)");
	printf("vendor=%s family=0x%x model=0x%x stepping=%u%s\n",
	       ci->vendor, ci->family, ci->model, ci->stepping,
	       ci->is_tigerlake ? " [Tiger Lake — target SKU]" : "");
	printf("avx512: f=%d dq=%d cd=%d bw=%d vl=%d vbmi=%d vbmi2=%d "
	       "ifma=%d vnni=%d bitalg=%d vpopcntdq=%d\n",
	       ci->avx512f, ci->avx512dq, ci->avx512cd, ci->avx512bw,
	       ci->avx512vl, ci->avx512vbmi, ci->avx512vbmi2,
	       ci->avx512ifma, ci->avx512vnni, ci->avx512bitalg,
	       ci->avx512vpopcntdq);
}
