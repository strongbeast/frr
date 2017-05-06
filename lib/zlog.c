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

#include "zebra.h"

#include <alloca.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include "memory.h"
#include "atomlist.h"
#include "frrcu.h"
#include "zlog.h"

DEFINE_MTYPE_STATIC(LIB, LOG_TARGET,   "log target")
DEFINE_MTYPE_STATIC(LIB, LOG_FILENAME, "log filename")

struct zlog_targets_head zlog_targets;

/* global setup */

static char logprefix[128] = "";
static size_t logprefixsz = 0;

/* message buffering */

#define ZLOG_TS_PREC		0xf

#define ZLOG_TS_ISO8601		(1 << 8)
#define ZLOG_TS_LEGACY		(1 << 9)
#define ZLOG_TS_FORMAT		(ZLOG_TS_ISO8601 | ZLOG_TS_LEGACY)

#define ZLOG_TS_UTC		(1 << 10)
#define ZLOG_TS_FLAGS		~0xfU

struct zlog_msg {
	char *text;
	size_t textlen;
	int prio;

	uint32_t ts_flags;
	struct timespec ts;
	char ts_str[32], *ts_dot, ts_zonetail[16];
};

/* prepend timestamp so it ends right before "target"
 *
 * buffer "XXXXXXXXXXXXXXXXXXXXXXXXXXXXX Message here"
 *         ^limit                       ^target
 *        "XXXXXXXXX2017-05-01 00:00:00Z Message here"
 *                  ^return value
 */
static size_t zlog_ts(struct zlog_msg *msg, char *out, size_t outsz,
		uint32_t flags)
{
	size_t len1, len2;

	if (!(flags & ZLOG_TS_FORMAT))
		return 0;

	if ((flags ^ msg->ts_flags) & ZLOG_TS_FLAGS) {
		struct tm tm;
		if (flags & ZLOG_TS_UTC)
			gmtime_r(&msg->ts.tv_sec, &tm);
		else
			localtime_r(&msg->ts.tv_sec, &tm);

		if (flags & ZLOG_TS_ISO8601) {
			strftime(msg->ts_str, sizeof(msg->ts_str),
					"%Y-%m-%dT%H:%M:%S", &tm);
			if (flags & ZLOG_TS_UTC) {
				msg->ts_zonetail[0] = 'Z';
				msg->ts_zonetail[1] = '\0';
			} else
				snprintf(msg->ts_zonetail,
						sizeof(msg->ts_zonetail),
						"%+03d:%02d",
						(int)(tm.tm_gmtoff / 3600),
						(int)(abs(tm.tm_gmtoff) / 60) % 60);
		} else {
			strftime(msg->ts_str, sizeof(msg->ts_str),
					"%Y/%m/%d %H:%M:%S", &tm);
			msg->ts_zonetail[0] = '\0';
		}
		msg->ts_dot = msg->ts_str + strlen(msg->ts_str);
		snprintf(msg->ts_dot,
				msg->ts_str + sizeof(msg->ts_str) - msg->ts_dot,
				".%09lu", (unsigned long)msg->ts.tv_nsec);

		msg->ts_flags = flags & ZLOG_TS_FLAGS;
	}

	len1 = flags & ZLOG_TS_PREC;
	len1 = (msg->ts_dot - msg->ts_str) + (len1 ? len1 + 1 : 0);
	if (len1 > strlen(msg->ts_str))
		len1 = strlen(msg->ts_str);
	len2 = strlen(msg->ts_zonetail);

	if (len1 + len2 + 1 > outsz)
		return 0;

	memcpy(out, msg->ts_str, len1);
	memcpy(out + len1, msg->ts_zonetail, len2);
	out[len1 + len2] = '\0';
	return len1 + len2;
}

void zlog(int prio, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vzlog(prio, fmt, ap);
	va_end(ap);
}

static void zlog_fd(struct zlog_target *zt, struct zlog_msg *msg);

void vzlog(int prio, const char *fmt, va_list ap)
{
	struct zlog_msg msg;
	char fixbuf[256];
	ssize_t sz;
	struct zlog_target *zt;

	prio &= LOG_PRIMASK;

	msg.prio = prio;
	msg.text = fixbuf;

	sz = vsnprintf(msg.text, sizeof(fixbuf), fmt, ap);
	if (sz < 0)
		return; /* error */
	if ((size_t)sz >= sizeof(fixbuf)) {
		msg.text = alloca(sz + 1);
		vsnprintf(msg.text, sz + 1, fmt, ap);
	}
	msg.textlen = sz;

	clock_gettime(CLOCK_REALTIME, &msg.ts);
	msg.ts_flags = 0;

	rcu_hold();
	atomlist_for_each(zlog_targets, zt, &zlog_targets) {
		if (prio > zt->prio_min)
			continue;

		switch (zt->type) {
		case ZLOG_TARGET_SYSLOG:
			syslog(prio | zt->syslog_facility, "%s", msg.text);
			break;
		default:
			zt->logfn(zt, &msg);
			break;
		}
	}
	rcu_release();
}

static const char *prionames[] = {
	[LOG_EMERG] =	"emergencies: ",
	[LOG_ALERT] =	"alerts: ",
	[LOG_CRIT] =	"critical: ",
	[LOG_ERR] =	"errors: ",
	[LOG_WARNING] =	"warnings: ",
	[LOG_NOTICE] =	"notifications: ",
	[LOG_INFO] =	"informational: ",
	[LOG_DEBUG] =	"debugging: ",
};

static void zlog_fd(struct zlog_target *zt, struct zlog_msg *msg)
{
	int fd;
	struct iovec iov[5];
	char ts_buf[64];

	iov[0].iov_base = ts_buf;
	iov[0].iov_len = zlog_ts(msg, ts_buf, sizeof(ts_buf) - 1,
			ZLOG_TS_LEGACY | zt->ts_subsec);
	ts_buf[iov[0].iov_len++] = ' ';

	iov[1].iov_base = (char *)prionames[msg->prio];
	iov[1].iov_len = zt->record_priority ? strlen(iov[1].iov_base) : 0;

	iov[2].iov_base = logprefix;
	iov[2].iov_len = logprefixsz;

	iov[3].iov_base = msg->text;
	iov[3].iov_len = msg->textlen;

	iov[4].iov_base = (char *)"\n";
	iov[4].iov_len = 1;

	fd = atomic_load(&zt->fd);
	writev(fd, iov, array_size(iov));
}

/*
 * (re-)configuration
 */

static bool zlog_rotate_one(struct zlog_target *zt)
{
	int fd = open(zt->file_name, O_WRONLY | O_APPEND | O_CREAT
			| O_CLOEXEC | O_NOCTTY, 0666);
	if (fd < 0)
		return false;

	fd = atomic_exchange(&zt->fd, fd);
	rcu_close(fd);
	return true;
}

void zlog_rotate(void)
{
	struct zlog_target *zt;
	atomlist_for_each(zlog_targets, zt, &zlog_targets) {
		if (zt->type == ZLOG_TARGET_FILE)
			zlog_rotate_one(zt);
	}
}

struct zlog_target *zlog_new(void)
{
	struct zlog_target *zt = XCALLOC(MTYPE_LOG_TARGET, sizeof(*zt));
	return zt;
}

struct zlog_target *zlog_file_new(const char *file_name)
{
	struct zlog_target *zt = zlog_new();
	zt->type = ZLOG_TARGET_FILE;
	zt->logfn = zlog_fd;
	zt->file_name = XSTRDUP(MTYPE_LOG_FILENAME, file_name);
	return zt;
}

struct zlog_target *zlog_fd_new(int fd)
{
	struct zlog_target *zt = zlog_new();
	zt->type = ZLOG_TARGET_FD;
	zt->logfn = zlog_fd;
	zt->fd = fd;
	return zt;
}

struct zlog_target *zlog_syslog_new(void)
{
	struct zlog_target *zt = zlog_new();
	zt->type = ZLOG_TARGET_SYSLOG;
	return zt;
}


bool zlog_activate(struct zlog_target *zt)
{
	/* TBD: LOGFILE_MASK */
	if (zt->type == ZLOG_TARGET_FILE) {
		zt->fd = open(zt->file_name, O_WRONLY | O_APPEND | O_CREAT
				| O_CLOEXEC | O_NOCTTY, 0666);
		if (zt->fd < 0)
			return false;
	};

	zlog_targets_add_tail(&zlog_targets, zt);
	return true;
}

bool zlog_file_name_set(struct zlog_target *zt, const char *file_name)
{
	assert(zt->type == ZLOG_TARGET_FILE);

	if (!strcmp(zt->file_name, file_name))
		return true;

	rcu_free(MTYPE_LOG_FILENAME, zt->file_name);
	zt->file_name = XSTRDUP(MTYPE_LOG_FILENAME, file_name);

	return zlog_rotate_one(zt);
}

void zlog_delete(struct zlog_target *zt)
{
	zlog_targets_del(&zlog_targets, zt);

	if (zt->type == ZLOG_TARGET_FILE)
		rcu_close(zt->fd);
	rcu_free(MTYPE_LOG_FILENAME, (char *)zt->file_name);
	rcu_free(MTYPE_LOG_TARGET, zt);
}

void zlog_init(const char *_logprefix)
{
	strlcpy(logprefix, _logprefix, sizeof(logprefix));
	logprefixsz = strlen(logprefix);
}
