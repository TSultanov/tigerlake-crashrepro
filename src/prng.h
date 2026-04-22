#ifndef CRASHREPRO_PRNG_H
#define CRASHREPRO_PRNG_H

#include <stdint.h>

/* xoshiro256** — fast, statistically strong, 256-bit state. Deterministic
 * from a single u64 seed via splitmix64 expansion, which is exactly what we
 * need for seed-based crash replay. */
typedef struct {
	uint64_t s[4];
} prng_t;

void prng_seed(prng_t *p, uint64_t seed);
uint64_t prng_u64(prng_t *p);

static inline uint32_t prng_u32(prng_t *p) {
	return (uint32_t)prng_u64(p);
}

/* Uniform in [0, bound). Rejection-free biased version is fine for our
 * dispatch weighting — we are not doing cryptography. */
static inline uint32_t prng_below(prng_t *p, uint32_t bound) {
	return (uint32_t)(((uint64_t)prng_u32(p) * bound) >> 32);
}

static inline int prng_bool(prng_t *p) {
	return (int)(prng_u64(p) & 1);
}

#endif
