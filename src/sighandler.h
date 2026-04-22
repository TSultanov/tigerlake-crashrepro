#ifndef CRASHREPRO_SIGHANDLER_H
#define CRASHREPRO_SIGHANDLER_H

#include "logger.h"

/* Install the process-wide sigaction for SIGSEGV/SIGILL/SIGBUS/SIGFPE/SIGTRAP.
 * Call once from main before threads start. */
int sighandler_install_global(const char *logdir);

/* Per-thread: allocate an alt signal stack (so handlers still run if the
 * main stack is clobbered), set the thread-local logger pointer so the
 * handler can dump the ring buffer, and open a per-thread crash-log fd. */
int sighandler_thread_init(logger_t *lg);

#endif
