#include "zebra.h"

#include <stdio.h>
#include <string.h>

#include "memory.h"
#include "zlog.h"
#include "libfrr.h"
#include "version.h"

#define SD_JOURNAL_SUPPRESS_LOCATION
#include <systemd/sd-journal.h>

extern char logprefix[];

struct zlog_msg {
	char *text;
	size_t textlen;
	int prio;

	struct zlogmeta_frame *zlf, *zlf_pfx;

	uint32_t ts_flags;
	struct timespec ts;
	char ts_str[32], *ts_dot, ts_zonetail[16];
};

static void zlog_sd(struct zlog_target *zt, struct zlog_msg *msg)
{
	char buf[2048], *pos = buf, *end = buf + sizeof(buf);
	struct iovec iov[32];
	size_t i = 0, j;
	struct zlogmeta_frame *zlf;

#define add(...) \
	iov[i].iov_base = pos; \
	iov[i].iov_len = snprintf(pos, end - pos, __VA_ARGS__); \
	pos += iov[i++].iov_len + 1;

	add("MESSAGE=%s%s%s",
		logprefix, msg->zlf_pfx ? msg->zlf_pfx->logprefix : "",
		msg->text);
	add("PRIORITY=%d", msg->prio);
	add("SYSLOG_FACILITY=%d", LOG_FAC(zt->syslog_facility));

	for (zlf = msg->zlf; zlf; zlf = zlf->up) {
		for (j = 0; j < array_size(zlf->val); j++) {
			if (i == array_size(iov) || pos == end)
				break;
			if (zlf->val[j].key && zlf->val[j].val) {
				add("%s=%s",
					zlf->val[j].key->name,
					zlf->val[j].val);

				if (i == array_size(iov) || pos == end)
					goto break2;
			}
		}
	}
break2:
	sd_journal_sendv(iov, i);
}

static struct zlog_target *zt_sd;

static int
zlog_sd_journal_init (void)
{
	zt_sd = zlog_new();
	zt_sd->type = 99;
	zt_sd->logfn = zlog_sd;
	zt_sd->prio_min = 99;
	zlog_activate(zt_sd);
	return 0;
}

FRR_MODULE_SETUP(
	.name = "sd_journal",
	.version = FRR_VERSION,
	.description = "systemd journal logging",
	.init = zlog_sd_journal_init
)
