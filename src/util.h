#ifndef CRASHREPRO_UTIL_H
#define CRASHREPRO_UTIL_H

#include <stdint.h>
#include <time.h>

#define ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))

static inline uint64_t now_ns(void) {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static inline uint64_t rdtsc(void) {
	uint32_t lo, hi;
	__asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
	return ((uint64_t)hi << 32) | lo;
}

static inline void cpu_pause(void) {
	__asm__ volatile("pause" ::: "memory");
}

static inline void compiler_barrier(void) {
	__asm__ volatile("" ::: "memory");
}

#endif
