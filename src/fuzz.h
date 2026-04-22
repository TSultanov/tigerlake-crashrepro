#ifndef CRASHREPRO_FUZZ_H
#define CRASHREPRO_FUZZ_H

#include <stdint.h>

/* How a/b/dst relate in one iteration. Stored in the durable log so replay
 * can tell whether an iteration used distinct buffers, exact aliasing, or a
 * partial overlap intended to stress read-before-write and forwarding paths. */
typedef enum {
	OPERAND_SHAPE_DISTINCT = 0,
	OPERAND_SHAPE_DST_EQ_A = 1,
	OPERAND_SHAPE_DST_EQ_B = 2,
	OPERAND_SHAPE_A_EQ_B = 3,
	OPERAND_SHAPE_DST_OVERLAPS_A = 4,
	OPERAND_SHAPE_A_OVERLAPS_DST = 5,
	OPERAND_SHAPE_DST_OVERLAPS_B = 6,
	OPERAND_SHAPE_B_OVERLAPS_DST = 7,
	OPERAND_SHAPE_COUNT
} operand_shape_t;

static inline const char *operand_shape_name(uint32_t shape) {
	switch ((operand_shape_t)shape) {
	case OPERAND_SHAPE_DISTINCT:         return "distinct";
	case OPERAND_SHAPE_DST_EQ_A:         return "dst_eq_a";
	case OPERAND_SHAPE_DST_EQ_B:         return "dst_eq_b";
	case OPERAND_SHAPE_A_EQ_B:           return "a_eq_b";
	case OPERAND_SHAPE_DST_OVERLAPS_A:   return "dst_overlaps_a";
	case OPERAND_SHAPE_A_OVERLAPS_DST:   return "a_overlaps_dst";
	case OPERAND_SHAPE_DST_OVERLAPS_B:   return "dst_overlaps_b";
	case OPERAND_SHAPE_B_OVERLAPS_DST:   return "b_overlaps_dst";
	default:                             return "unknown";
	}
}

typedef struct {
	uint32_t    thread_id;
	uint64_t    seed;          /* per-thread seed = base_seed ^ thread_id */
	uint64_t    iters;         /* 0 = infinite */
	const char *logdir;
	uint64_t    class_mask;    /* bit i set => class i enabled; 0 => all */
	uint32_t    shape_mask;    /* bit i set => operand shape i enabled; 0 => all */
	int         verify;        /* scalar oracle compare on/off */
	int         churn;         /* frequency/power churn on/off */
	int         faults;        /* intentional AVX-512 bad-address faults on/off */
	int         pin_core;      /* -1 = no pin */
	int         quiet;
	int         verbose;       /* per-iter console echo from the logger */
} fuzz_cfg_t;

/* Main worker entry point. Blocks until config->iters completed or until
 * fuzz_request_stop() is called (e.g. from SIGINT). Returns 0 on clean
 * exit, non-zero if an oracle mismatch was observed. */
int  fuzz_run(const fuzz_cfg_t *cfg);

/* Ask all running fuzz_run loops to exit at the next iteration boundary. */
void fuzz_request_stop(void);

/* Has anyone called fuzz_request_stop? */
int  fuzz_should_stop(void);

#endif
