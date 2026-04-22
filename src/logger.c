#include "logger.h"
#include "util.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

uint64_t fnv1a64(const void *data, uint32_t len) {
	const uint8_t *p = (const uint8_t *)data;
	uint64_t h = 0xcbf29ce484222325ull;
	for (uint32_t i = 0; i < len; i++) {
		h ^= p[i];
		h *= 0x100000001b3ull;
	}
	return h;
}

static int mkdir_p(const char *path) {
	/* lightweight mkdir -p: handles absolute paths with no leading . */
	char buf[1024];
	size_t n = strlen(path);
	if (n >= sizeof buf) { errno = ENAMETOOLONG; return -1; }
	memcpy(buf, path, n + 1);
	for (size_t i = 1; i < n; i++) {
		if (buf[i] == '/') {
			buf[i] = '\0';
			if (mkdir(buf, 0755) < 0 && errno != EEXIST) return -1;
			buf[i] = '/';
		}
	}
	if (mkdir(buf, 0755) < 0 && errno != EEXIST) return -1;
	return 0;
}

int logger_open(logger_t *lg, const char *logdir, uint32_t thread_id,
                uint64_t seed) {
	memset(lg, 0, sizeof *lg);
	lg->fd = -1;
	lg->thread_id = thread_id;

	if (mkdir_p(logdir) < 0) {
		fprintf(stderr, "logger: mkdir %s: %s\n", logdir, strerror(errno));
		return -1;
	}

	char path[1024];
	snprintf(path, sizeof path, "%s/state.t%u.bin", logdir, thread_id);
	int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		fprintf(stderr, "logger: open %s: %s\n", path, strerror(errno));
		return -1;
	}
	if (ftruncate(fd, LOG_FILE_SIZE) < 0) {
		fprintf(stderr, "logger: ftruncate: %s\n", strerror(errno));
		close(fd);
		return -1;
	}

	void *map = mmap(NULL, LOG_FILE_SIZE, PROT_READ | PROT_WRITE,
	                 MAP_SHARED, fd, 0);
	if (map == MAP_FAILED) {
		fprintf(stderr, "logger: mmap: %s\n", strerror(errno));
		close(fd);
		return -1;
	}

	log_file_t *lf = (log_file_t *)map;
	memset(lf, 0, sizeof *lf);
	memcpy(lf->magic, LOG_MAGIC, 8);
	lf->version   = LOG_VERSION;
	lf->thread_id = thread_id;
	lf->seed      = seed;
	lf->start_ns  = now_ns();
	lf->iter      = 0;
	lf->ring_pos  = 0;
	lf->ring_len  = LOG_RING_LEN;

	lg->fd  = fd;
	lg->map = lf;
	msync(lf, LOG_FILE_SIZE, MS_SYNC);
	return 0;
}

void logger_close(logger_t *lg) {
	if (lg->map) {
		msync(lg->map, LOG_FILE_SIZE, MS_SYNC);
		munmap(lg->map, LOG_FILE_SIZE);
		lg->map = NULL;
	}
	if (lg->fd >= 0) {
		close(lg->fd);
		lg->fd = -1;
	}
}

log_entry_t *logger_begin(logger_t *lg, uint64_t iter,
                          uint32_t insn_class, uint32_t operand_shape,
                          uint32_t mask_pattern, uint32_t alignment_offset,
                          uint32_t zmm_dst, uint32_t flags,
                          uint64_t input_hash) {
	log_file_t *lf = lg->map;
	uint32_t pos = lf->ring_pos;
	log_entry_t *e = &lf->entries[pos];
	e->iter = iter;
	e->timestamp_ns = now_ns();
	e->insn_class = insn_class;
	e->operand_shape = operand_shape;
	e->mask_pattern = mask_pattern;
	e->alignment_offset = alignment_offset;
	e->zmm_dst = zmm_dst;
	e->flags = flags;
	e->status = 0;                 /* in-flight */
	e->input_hash = input_hash;
	e->output_hash = 0;
	lf->iter = iter;
	lf->ring_pos = (pos + 1) % lf->ring_len;
	msync(e, sizeof *e, MS_SYNC);
	msync(lf, offsetof(log_file_t, entries), MS_SYNC);
	return e;
}

void logger_end(logger_t *lg, log_entry_t *e,
                uint64_t output_hash, uint64_t status) {
	e->output_hash = output_hash;
	e->status = status;
	/* msync only the affected entry to keep the per-iteration cost low.
	 * The kernel will still write-back the whole page but the syscall
	 * itself is what we're minimising. */
	msync(e, sizeof *e, MS_SYNC);
}

static const char *status_str(uint64_t s) {
	switch (s) {
	case 0: return "IN_FLIGHT";
	case 1: return "OK";
	default: return "MISMATCH";
	}
}

int logger_dump(const char *path) {
	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "dump: open %s: %s\n", path, strerror(errno));
		return -1;
	}
	void *map = mmap(NULL, LOG_FILE_SIZE, PROT_READ, MAP_SHARED, fd, 0);
	close(fd);
	if (map == MAP_FAILED) {
		fprintf(stderr, "dump: mmap %s: %s\n", path, strerror(errno));
		return -1;
	}
	const log_file_t *lf = (const log_file_t *)map;
	if (memcmp(lf->magic, LOG_MAGIC, 8) != 0) {
		fprintf(stderr, "dump: %s: bad magic\n", path);
		munmap(map, LOG_FILE_SIZE);
		return -1;
	}

	printf("=== %s ===\n", path);
	printf("version=%u thread=%u seed=0x%016llx iter=%llu start_ns=%llu ring_pos=%u\n",
	       lf->version, lf->thread_id,
	       (unsigned long long)lf->seed,
	       (unsigned long long)lf->iter,
	       (unsigned long long)lf->start_ns,
	       lf->ring_pos);

	/* Print entries in chronological order: ring_pos points to the oldest. */
	for (uint32_t i = 0; i < lf->ring_len; i++) {
		uint32_t idx = (lf->ring_pos + i) % lf->ring_len;
		const log_entry_t *e = &lf->entries[idx];
		if (e->timestamp_ns == 0) continue;
		printf("  iter=%-8llu ts=%llu insn=%u shape=%u k=0x%08x "
		       "off=%u zmm=%u flags=0x%x status=%s in=%016llx out=%016llx\n",
		       (unsigned long long)e->iter,
		       (unsigned long long)e->timestamp_ns,
		       e->insn_class, e->operand_shape, e->mask_pattern,
		       e->alignment_offset, e->zmm_dst, e->flags,
		       status_str(e->status),
		       (unsigned long long)e->input_hash,
		       (unsigned long long)e->output_hash);
	}

	munmap(map, LOG_FILE_SIZE);
	return 0;
}

int logger_replay_dir(const char *logdir) {
	DIR *d = opendir(logdir);
	if (!d) {
		fprintf(stderr, "replay: opendir %s: %s\n", logdir, strerror(errno));
		return -1;
	}
	struct dirent *de;
	int any = 0;
	while ((de = readdir(d)) != NULL) {
		if (strncmp(de->d_name, "state.t", 7) != 0) continue;
		char path[1024];
		snprintf(path, sizeof path, "%s/%s", logdir, de->d_name);
		logger_dump(path);
		any++;
	}
	closedir(d);
	if (!any) {
		fprintf(stderr, "replay: no state.t*.bin files in %s\n", logdir);
		return -1;
	}
	return 0;
}
