/*
 * Copyright (c) 2015-16  David Lamparter, for NetDEF, Inc.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _FRR_ZLOG_H
#define _FRR_ZLOG_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <syslog.h>

#include "atomlist.h"

extern void vzlog(int prio, const char *fmt, va_list ap);
extern void zlog(int prio, const char *fmt, ...)
	__attribute__ ((format (printf, 2, 3)));

#define zlog_err(...)    zlog(LOG_ERR, __VA_ARGS__)
#define zlog_warn(...)   zlog(LOG_WARNING, __VA_ARGS__)
#define zlog_info(...)   zlog(LOG_INFO, __VA_ARGS__)
#define zlog_notice(...) zlog(LOG_NOTICE, __VA_ARGS__)
#define zlog_debug(...)  zlog(LOG_DEBUG, __VA_ARGS__)

enum zlog_target_type {
	ZLOG_TARGET_FD = 1,
	ZLOG_TARGET_SYSLOG,
	ZLOG_TARGET_FILE,
};

struct zlog_msg;

ATOMLIST_MAKEITEM(zlog_targets)
struct zlog_target {
	struct zlog_targets_item head;

	/* read-only after creation */
	enum zlog_target_type type;
	void (*logfn)(struct zlog_target *zt, struct zlog_msg *msg);

	/* don't touch directly from config; use zlog_rotate() */
	_Atomic int fd;

	int prio_min;

	bool record_priority;
	uint8_t ts_subsec;

	/* non-critical fields not used during logging, only in reconfig
	 * protected by zlog_conf_mutex */
	char *file_name;
	int syslog_facility;

};
ATOMLIST_MAKEFUNCS(zlog_targets, struct zlog_target, head);
extern struct zlog_targets_head zlog_targets;

/* for log target plugins */
extern struct zlog_target *zlog_new(void);

/* these do _not_ activate the target */
extern struct zlog_target *zlog_file_new(const char *file_name);
extern struct zlog_target *zlog_fd_new(int fd);
extern struct zlog_target *zlog_syslog_new(void);

extern bool zlog_file_name_set(struct zlog_target *zt, const char *file_name);
extern bool zlog_activate(struct zlog_target *zt);

extern void zlog_delete(struct zlog_target *zt);

extern void zlog_rotate(void);
extern void zlog_init(const char *logprefix);

/**************************************************************************
 * structured key/value logging extensions
 */

/* encapsulate key name as global symbol for pointer comparison. */
struct zlogmeta_key {
	const char *name;
};

struct zlogmeta_val {
	struct zlogmeta_key *key;
	const char *val;
};

/* stack chain entry for logging metadata.  functions that want to add
 * metadata put one of these on the stack and link/unlink it on
 * zlogmeta_stackptr */
struct zlogmeta_frame {
	struct zlogmeta_frame *up;

	/* if logprefix is NULL, try up->logprefix.  otherwise, use this
	 * and end (no chaining of prefixes here - done in formatting) */
	char *logprefix;
	size_t logprefixsz;

	/* unlike logprefix, values ARE chained, but only the bottommost
	 * value is used for each key.  this is static at 8 entries to reduce
	 * cacheline clobbering. */
	struct zlogmeta_val val[8];
};

/*
 * zlog metadata stack management
 */
extern _Thread_local struct zlogmeta_frame *zlogmeta_stackptr;

static inline void zlogmeta_pop(struct zlogmeta_frame *frame)
{
	zlogmeta_stackptr = frame->up;
}
#define ZLOGMETA_FRAME() \
	struct zlogmeta_frame zlogmeta_frame \
		__attribute__((cleanup(zlogmeta_pop))) \
		= { .up = zlogmeta_stackptr }; \
	zlogmeta_stackptr = &zlogmeta_frame
#define STATIC_ZLOGMETA_FRAME() \
	static struct zlogmeta_frame zlogmeta_frame; \
	zlogmeta_frame.up = zlogmeta_stackptr; \
	zlogmeta_stackptr = &zlogmeta_frame

/*
 * log message prefix prepending
 */
extern void zlog_prefixf(struct zlogmeta_frame *frame, char *buf, size_t bufsz,
		const char *fmt, ...)
	__attribute__ ((format (printf, 4, 5)));
#define ZLOG_PREFIXF(...) \
		zlog_prefixf(&zlogmeta_frame, alloca(256), 256, __VA_ARGS__)

/*
 * key/value log metadata
 *
 * use ZLOGMETA if you have a preexisting char * that is guaranteed to
 * stay alive during the function call - it keeps a copy of the pointer.
 *
 * otherwise, use ZLOGMETAF (possibly with "%s" as format string)
 */
extern void zlog_meta(struct zlogmeta_frame *frame, struct zlogmeta_key *key,
		const char *val);
#define ZLOG_META(key, val)	zlog_meta(&zlogmeta_frame, key, val)

extern void zlog_metaf(struct zlogmeta_frame *frame, struct zlogmeta_key *key,
		char *buf, size_t bufsz, const char *fmt, ...)
	__attribute__ ((format (printf, 5, 6)));
#define ZLOG_METAF(key, ...)	zlog_metaf(&zlogmeta_frame, key, \
		alloca(256), 256, __VA_ARGS__)

/* global keys */
extern struct zlogmeta_key zl_THR_ID;		/* thread ID */
extern struct zlogmeta_key zl_THR_NAME;		/* thread name */

extern struct zlogmeta_key zl_VRF;		/* VRF ID */
extern struct zlogmeta_key zl_REMOTE;		/* remote system / packet address */
extern struct zlogmeta_key zl_PREFIX;		/* route destination prefix */
extern struct zlogmeta_key zl_SRCPREFIX;	/* route source prefix (SADR) */

#endif /* _FRR_ZLOG_H */
