#ifndef CRASHREPRO_POWER_H
#define CRASHREPRO_POWER_H

#include <stdint.h>
#include "prng.h"

/* Deliberate AVX-512 frequency / voltage churn. Interleaves bursts of
 * heavy zmm-register arithmetic and memory traffic (which drive the
 * AVX-512 frequency license and demand peak VR draw) with several kinds
 * of short gaps: passive sleeps, active scalar busy loops, AVX2 bridge
 * phases, and rapid multi-burst re-entry trains. This keeps the package
 * transitioning between AVX-512, lighter vector, and scalar states. On
 * Tiger Lake i5-1135G7 those transitions are the most plausible root
 * cause for whole-system crashes induced by user-space AVX-512 code. */

typedef struct {
	uint64_t bursts;
	uint64_t total_burst_ns;
} power_stats_t;

/* Run one burst-then-gap cycle with randomised parameters.
 * Safe to call from any thread; uses only zmm registers the caller has
 * not pinned to other uses. */
void power_churn_cycle(prng_t *p, power_stats_t *st);

#endif
