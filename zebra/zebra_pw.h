/* Zebra PW code
 * Copyright (C) 2016 Volta Networks, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
 * MA 02110-1301 USA
 */

#ifndef ZEBRA_PW_H_
#define ZEBRA_PW_H_

#include <net/if.h>
#include <netinet/in.h>

#include "hook.h"

#define PW_INSTALL_RETRY_INTERVAL	30

struct zebra_pw {
	RB_ENTRY(zebra_pw) entry;
	vrf_id_t vrf_id;
	char ifname[IF_NAMESIZE];
	ifindex_t ifindex;
	int type;
	int af;
	union g_addr nexthop;
	uint32_t local_label;
	uint32_t remote_label;
	uint8_t flags;
	union pw_protocol_fields data;
	int enabled;
	int status;
	uint8_t protocol;
	struct zserv *client;
	struct rnh *rnh;
	struct thread *install_retry_timer;
};

RB_HEAD(zebra_pw_head, zebra_pw);
RB_PROTOTYPE(zebra_pw_head, zebra_pw, entry, zebra_pw_compare);

DECLARE_HOOK(pw_install, (struct zebra_pw * pw), (pw))
DECLARE_HOOK(pw_uninstall, (struct zebra_pw * pw), (pw))

struct zebra_pw *zebra_pw_add(struct zebra_vrf *, const char *,
			      uint8_t, struct zserv *);
void zebra_pw_del(struct zebra_vrf *, struct zebra_pw *);
void zebra_pw_change(struct zebra_pw *, ifindex_t, int, int, union g_addr *,
		     uint32_t, uint32_t, uint8_t, union pw_protocol_fields *);
struct zebra_pw *zebra_pw_find(struct zebra_vrf *, const char *);
void zebra_pw_update(struct zebra_pw *);
void zebra_pw_install_failure(struct zebra_pw *);
void zebra_pw_client_close(struct zserv *);
void zebra_pw_init(struct zebra_vrf *);
void zebra_pw_exit(struct zebra_vrf *);

#endif				/* ZEBRA_PW_H_ */
