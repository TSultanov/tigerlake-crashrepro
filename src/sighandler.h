#ifndef CRASHREPRO_SIGHANDLER_H
#define CRASHREPRO_SIGHANDLER_H

#include <setjmp.h>
#include <stdint.h>

#include "logger.h"

/* Install the process-wide sigaction for SIGSEGV/SIGILL/SIGBUS/SIGFPE/SIGTRAP.
 * Call once from main before threads start. */
int sighandler_install_global(const char *logdir);

/* Per-thread: allocate an alt signal stack (so handlers still run if the
 * main stack is clobbered), set the thread-local logger pointer so the
 * handler can dump the ring buffer, and open a per-thread crash-log fd. */
int sighandler_thread_init(logger_t *lg);

/* Expected-fault recovery.
 *
 * The fuzz loop uses these to issue AVX-512 loads/stores at deliberately
 * invalid addresses without terminating on the resulting SIGSEGV/SIGBUS.
 *
 * Pattern (must be in the caller's frame, since sigsetjmp relies on that
 * frame still existing when siglongjmp fires):
 *
 *     if (sigsetjmp(sighandler_recovery_buf, 1) == 0) {
 *         sighandler_arm_expected_fault(addr, entry);
 *         spec->exec(...);
 *         sighandler_disarm_expected_fault();   // didn't fault
 *         logger_end(&lg, entry, 0, LOG_STATUS_FAULT_MISSED);
 *     } else {
 *         // recovered: handler already stamped entry->status=EXPECTED_FAULT
 *     }
 *
 * The handler treats SIGSEGV/SIGBUS raised while the expected-fault window
 * is armed as recoverable. The observed si_addr/CR2 is still logged for
 * triage because some x86 fault paths report a synthetic address that does
 * not match the original memory operand. */
extern __thread sigjmp_buf sighandler_recovery_buf;

void sighandler_arm_expected_fault(uint64_t expected_addr, log_entry_t *e);
void sighandler_disarm_expected_fault(void);

#endif
