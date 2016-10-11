/*
 * Authentication/Confidentiality for OSPFv3 - RFC 4552
 *
 * Copyright (C) 2013 Digistar, Inc.
 *
 * This file is part of Quagga routing suite.
 *
 * Quagga is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * Quagga is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#ifndef _QUAGGA_OSPF6_VTY_IPSEC_H
#define _QUAGGA_OSPF6_VTY_IPSEC_H

#include "ipsec.h"

struct ospf6_ipsec
{
  enum ipsec_proto proto;
  u_int32_t spi;
  u_int8_t auth_type;
  char auth_key[HMAC_MAX_KEY_SIZE+1];
  u_int8_t enc_type;
  char enc_key[IPSEC_KEY_SIZE_MAX+1];
};

/* Function declarations. */
struct ospf6_interface;
extern void ospf6_update_ipsec (struct ospf6_interface *);
extern struct ipsec_entry *ospf6_ipsec_install (struct ospf6_interface *,
						struct in6_addr *, u_int8_t,
						u_int32_t, u_int8_t, u_int8_t,
						char [], u_int8_t, char [],
						int, int);
extern void ospf6_ipsec_uninstall (struct ospf6_interface *,
				   struct ipsec_entry *);
extern int vty_ospf6_ipsec (struct vty *, struct vty_arg *[]);
extern int vty_ospf6_ipsec_debug (struct vty *, struct vty_arg *[]);
extern void ospf6_vty_ipsec_init (void);
int config_write_ospf6_debug_ipsec (struct vty *);
void ospf6_ipsec_init (void);

#endif /* _QUAGGA_OSPF6_VTY_IPSEC_H */
