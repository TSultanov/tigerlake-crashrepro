#ifndef CRASHREPRO_LOGGER_H
#define CRASHREPRO_LOGGER_H

#include <stdint.h>

/* Each worker thread owns one mmap'd log file that records the currently
 * executing iteration. Written and msync()'d before every AVX-512 dispatch
 * so that if the machine hard-crashes we can recover the last-known state
 * per thread from disk on reboot. */

#define LOG_MAGIC "CRSHRPR\0"
#define LOG_VERSION 2u
#define LOG_RING_LEN 64u
#define LOG_FILE_SIZE 8192u  /* two pages; header + 64 entries won't fit in one */

/* status codes for log_entry_t::status */
#define LOG_STATUS_IN_FLIGHT        0u
#define LOG_STATUS_OK               1u
#define LOG_STATUS_MISMATCH         2u
#define LOG_STATUS_EXPECTED_FAULT   3u  /* intentional bad-address access faulted at the target */
#define LOG_STATUS_FAULT_MISSED     4u  /* intentional bad-address access returned without faulting */

/* bits for log_entry_t::flags */
#define LOG_FLAG_ZEROMASK           (1u << 0)
#define LOG_FLAG_STORE_VARIANT      (1u << 1)
#define LOG_FLAG_EXPECTING_FAULT    (1u << 2)  /* op was intentionally aimed at a bad address */
#define LOG_FLAG_SHARED_DST         (1u << 3)
#define LOG_FLAG_INTERRUPT_PRESSURE (1u << 4)
#define LOG_FLAG_CHURN_ACTIVE       (1u << 5)
#define LOG_FLAG_DIRTY_UPPER        (1u << 6)
#define LOG_FLAG_PARTIAL_FAULT      (1u << 7)
#define LOG_FLAG_KREG_SHIFT         8u
#define LOG_FLAG_KREG_MASK          (7u << LOG_FLAG_KREG_SHIFT)
#define LOG_ENCODE_KREG(kreg)       ((((uint32_t)(kreg)) & 7u) << LOG_FLAG_KREG_SHIFT)
#define LOG_DECODE_KREG(flags)      ((((uint32_t)(flags)) & LOG_FLAG_KREG_MASK) >> LOG_FLAG_KREG_SHIFT)
#define LOG_FLAG_CHURN_PROFILE_SHIFT 12u
#define LOG_FLAG_CHURN_PROFILE_MASK  (7u << LOG_FLAG_CHURN_PROFILE_SHIFT)
#define LOG_ENCODE_CHURN_PROFILE(profile) ((((uint32_t)(profile)) & 7u) << LOG_FLAG_CHURN_PROFILE_SHIFT)
#define LOG_DECODE_CHURN_PROFILE(flags) ((((uint32_t)(flags)) & LOG_FLAG_CHURN_PROFILE_MASK) >> LOG_FLAG_CHURN_PROFILE_SHIFT)
#define LOG_FLAG_TLB_NOISE          (1u << 15)
#define LOG_FLAG_SMT_ANTAGONIST     (1u << 16)
#define LOG_FLAG_FORK_CHURN         (1u << 17)
#define LOG_FLAG_INTERRUPT_VARIANT_SHIFT 18u
#define LOG_FLAG_INTERRUPT_VARIANT_MASK  (3u << LOG_FLAG_INTERRUPT_VARIANT_SHIFT)
#define LOG_ENCODE_INTERRUPT_VARIANT(variant) ((((uint32_t)(variant)) & 3u) << LOG_FLAG_INTERRUPT_VARIANT_SHIFT)
#define LOG_DECODE_INTERRUPT_VARIANT(flags) ((((uint32_t)(flags)) & LOG_FLAG_INTERRUPT_VARIANT_MASK) >> LOG_FLAG_INTERRUPT_VARIANT_SHIFT)

/* On-disk entry. Keep small and fixed-layout. Append-only — any new field
 * goes at the end and bumps LOG_VERSION. */
typedef struct {
	uint64_t iter;              /* iteration number within the thread */
	uint64_t timestamp_ns;      /* CLOCK_MONOTONIC at dispatch */
	uint32_t insn_class;        /* enum insn_class */
	uint32_t operand_shape;     /* enum operand_shape, see fuzz.h */
	uint32_t mask_pattern;      /* k-register value used */
	uint32_t alignment_offset;  /* bytes added to base pointer */
	uint32_t zmm_dst;           /* 0..31 */
	uint32_t flags;             /* see LOG_FLAG_* */
	uint64_t status;            /* see LOG_STATUS_* */
	uint64_t input_hash;        /* fnv1a of input bytes */
	uint64_t output_hash;       /* fnv1a of output bytes */
	uint64_t expected_fault_addr; /* for LOG_FLAG_EXPECTING_FAULT ops: bad pointer dispatched */
	uint64_t actual_fault_addr; /* CR2/si_addr observed by handler; 0 if no fault */
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
	int           verbose;      /* 1 = print every iter; 0 = heartbeat ~1/s */
	uint64_t      last_print_ns;
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

/* Variant for intentional-fault ops: sets LOG_FLAG_EXPECTING_FAULT,
 * records expected_fault_addr, and uses a distinct console echo. */
log_entry_t *logger_begin_fault(logger_t *lg, uint64_t iter,
                                uint32_t insn_class, uint32_t flags,
                                uint64_t expected_fault_addr,
                                uint32_t variant);

/* Patch the entry with final output hash and status, then msync again. */
void logger_end(logger_t *lg, log_entry_t *e,
                uint64_t output_hash, uint64_t status);

/* Patch only the flags for an entry and msync the entry again. */
void logger_update_flags(logger_t *lg, log_entry_t *e, uint32_t flags);

/* Simple streaming FNV-1a 64. */
uint64_t fnv1a64(const void *data, uint32_t len);

/* Replay: dump one log file. Returns 0 on OK, -1 on missing / corrupt. */
int logger_dump(const char *path);

/* Replay: scan a directory for state.t*.bin files and dump each. */
int logger_replay_dir(const char *logdir);

#endif
