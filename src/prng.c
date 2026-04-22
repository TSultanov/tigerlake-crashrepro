#include "prng.h"

static uint64_t splitmix64(uint64_t *x) {
	uint64_t z = (*x += 0x9E3779B97F4A7C15ull);
	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
	z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
	return z ^ (z >> 31);
}

void prng_seed(prng_t *p, uint64_t seed) {
	uint64_t x = seed;
	for (int i = 0; i < 4; i++) {
		p->s[i] = splitmix64(&x);
	}
	/* xoshiro256** requires a non-zero state; splitmix64 output from any
	 * seed is non-zero in practice, but guard anyway. */
	if ((p->s[0] | p->s[1] | p->s[2] | p->s[3]) == 0) {
		p->s[0] = 1;
	}
}

static inline uint64_t rotl64(uint64_t x, int k) {
	return (x << k) | (x >> (64 - k));
}

uint64_t prng_u64(prng_t *p) {
	const uint64_t result = rotl64(p->s[1] * 5, 7) * 9;
	const uint64_t t = p->s[1] << 17;
	p->s[2] ^= p->s[0];
	p->s[3] ^= p->s[1];
	p->s[1] ^= p->s[2];
	p->s[0] ^= p->s[3];
	p->s[2] ^= t;
	p->s[3] = rotl64(p->s[3], 45);
	return result;
}
