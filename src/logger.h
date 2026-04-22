#ifndef CRASHREPRO_LOGGER_H
#define CRASHREPRO_LOGGER_H

#include <stdint.h>

/* Each worker thread owns one mmap'd log file that records the currently
 * executing iteration. Written and msync()'d before every AVX-512 dispatch
 * so that if the machine hard-crashes we can recover the last-known state
 * per thread from disk on reboot. */

#define LOG_MAGIC "CRSHRPR\0"
#define LOG_VERSION 1u
#define LOG_RING_LEN 64u
#define LOG_FILE_SIZE 8192u  /* two pages; header + 64 entries won't fit in one */

/* On-disk entry. Keep small and fixed-layout. */
typedef struct {
	uint64_t iter;              /* iteration number within the thread */
	uint64_t timestamp_ns;      /* CLOCK_MONOTONIC at dispatch */
	uint32_t insn_class;        /* enum insn_class */
	uint32_t operand_shape;     /* enum operand_shape, see fuzz.h */
	uint32_t mask_pattern;      /* k-register value used */
	uint32_t alignment_offset;  /* bytes added to base pointer */
	uint32_t zmm_dst;           /* 0..31 */
	uint32_t flags;             /* bit 0: zero-masking; bit 1: store variant */
	uint64_t status;            /* 0=in-flight, 1=completed, >=2=mismatch */
	uint64_t input_hash;        /* fnv1a of input bytes */
	uint64_t output_hash;       /* fnv1a of output bytes */
} log_entry_t;

typedef struct {
	char     magic[8];          /* LOG_MAGIC */
	uint32_t version;
	uint32_t thread_id;
	uint64_t seed;
	uint64_t start_ns;
	uint64_t iter;              /* mirrors latest entry's iter */
	uint32_t ring_pos;          /* next write index in entries[] */
	uint32_t ring_len;
	uint64_t _reserved[4];
	log_entry_t entries[LOG_RING_LEN];
} log_file_t;

_Static_assert(sizeof(log_file_t) <= LOG_FILE_SIZE,
               "log_file_t must fit in one page");

typedef struct {
	int           fd;
	log_file_t   *map;          /* mmap'd LOG_FILE_SIZE bytes */
	uint32_t      thread_id;
} logger_t;

/* Create or truncate the per-thread log file and mmap it. */
int  logger_open(logger_t *lg, const char *logdir, uint32_t thread_id,
                 uint64_t seed);
void logger_close(logger_t *lg);

/* Begin an iteration: writes a new entry with status=in-flight and msyncs.
 * Returns pointer to the entry so the caller can patch output_hash/status
 * once the instruction returns. */
log_entry_t *logger_begin(logger_t *lg, uint64_t iter,
                          uint32_t insn_class, uint32_t operand_shape,
                          uint32_t mask_pattern, uint32_t alignment_offset,
                          uint32_t zmm_dst, uint32_t flags,
                          uint64_t input_hash);

/* Patch the entry with final output hash and status, then msync again. */
void logger_end(logger_t *lg, log_entry_t *e,
                uint64_t output_hash, uint64_t status);

/* Simple streaming FNV-1a 64. */
uint64_t fnv1a64(const void *data, uint32_t len);

/* Replay: dump one log file. Returns 0 on OK, -1 on missing / corrupt. */
int logger_dump(const char *path);

/* Replay: scan a directory for state.t*.bin files and dump each. */
int logger_replay_dir(const char *logdir);

#endif
