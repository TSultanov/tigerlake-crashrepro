#ifndef CRASHREPRO_FUZZ_H
#define CRASHREPRO_FUZZ_H

#include <stdint.h>

typedef struct {
	uint32_t    thread_id;
	uint64_t    seed;          /* per-thread seed = base_seed ^ thread_id */
	uint64_t    iters;         /* 0 = infinite */
	const char *logdir;
	uint64_t    class_mask;    /* bit i set => class i enabled; 0 => all */
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
