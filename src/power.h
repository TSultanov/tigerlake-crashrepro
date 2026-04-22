#ifndef CRASHREPRO_POWER_H
#define CRASHREPRO_POWER_H

#include <stdint.h>
#include "prng.h"

typedef enum {
	POWER_PROFILE_RANDOM = 0,
	POWER_PROFILE_PASSIVE = 1,
	POWER_PROFILE_SCALAR = 2,
	POWER_PROFILE_AVX2 = 3,
	POWER_PROFILE_TRAIN = 4,
	POWER_PROFILE_COUNT
} power_profile_t;

static inline const char *power_profile_name(power_profile_t profile) {
	switch (profile) {
	case POWER_PROFILE_RANDOM:  return "random";
	case POWER_PROFILE_PASSIVE: return "passive";
	case POWER_PROFILE_SCALAR:  return "scalar";
	case POWER_PROFILE_AVX2:    return "avx2";
	case POWER_PROFILE_TRAIN:   return "train";
	default:                   return "unknown";
	}
}

typedef struct {
	power_profile_t profile;
	uint32_t        burst_min_us;
	uint32_t        burst_max_us;
	uint32_t        gap_min_us;
	uint32_t        gap_max_us;
	uint32_t        reentry_min_us;
	uint32_t        reentry_max_us;
} power_cfg_t;

static inline power_cfg_t power_cfg_default(void) {
	power_cfg_t cfg;
	cfg.profile = POWER_PROFILE_RANDOM;
	cfg.burst_min_us = 50u;
	cfg.burst_max_us = 1999u;
	cfg.gap_min_us = 10u;
	cfg.gap_max_us = 199u;
	cfg.reentry_min_us = 5u;
	cfg.reentry_max_us = 120u;
	return cfg;
}

typedef struct {
	power_profile_t profile;
	uint32_t        burst_us;
	uint32_t        gap_us;
	uint32_t        reentry_us;
} power_plan_t;

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
void power_churn_plan(prng_t *p, const power_cfg_t *cfg, power_plan_t *plan);
void power_churn_cycle(prng_t *p, const power_plan_t *plan, power_stats_t *st);

#endif
