/*
 * Copyright (C) 2016 by Open Source Routing.
 *
 * This file is part of Quagga
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
 * along with Quagga; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#ifndef _IPSEC_H
#define _IPSEC_H

#include <zebra.h>

#include "privs.h"

#define HASH_HMAC_MD5		1
#define HASH_HMAC_SHA1		2
#define HASH_HMAC_SHA256	3
#define HASH_HMAC_SHA384	4
#define HASH_HMAC_SHA512	5
#define HASH_ALGO_MAX		6

#define HASH_SIZE_MD5		16U
#define HASH_SIZE_SHA1		20U
#define HASH_SIZE_SHA256	32U
#define HASH_SIZE_SHA384	48U
#define HASH_SIZE_SHA512	64U
#define HASH_SIZE_MAX		64U

#define HMAC_MD5_KEY_SIZE	32
#define HMAC_SHA1_KEY_SIZE	40
#define HMAC_MAX_KEY_SIZE	HMAC_SHA1_KEY_SIZE

#define IPSEC_ENC_3DES		1
#define IPSEC_ENC_AES_128	2
#define IPSEC_ENC_AES_192	3
#define IPSEC_ENC_AES_256	4
#define IPSEC_ENC_DES		5
#define IPSEC_ENC_NULL		6

#define IPSEC_KEY_SIZE_MAX	64

enum ipsec_proto {
  IPSEC_DISABLED = 0,
  IPSEC_AH,
  IPSEC_ESP
};

enum ipsec_spd_dir {
  IPSEC_SPD_IN = 1,
  IPSEC_SPD_OUT
};

struct ipsec_entry
{
  enum ipsec_proto ipsec_proto;
  struct in6_addr dst;
  u_int32_t spi;
  u_int8_t ip_proto;
  u_int8_t auth_type;
  char auth_key[HMAC_MAX_KEY_SIZE+1];
  u_int8_t enc_type;
  char enc_key[IPSEC_KEY_SIZE_MAX+1];
  char ifname[IFNAMSIZ];
  int in;
  int out;
#ifdef GNU_LINUX
  u_int32_t reqid;
#endif
};

extern const u_int8_t ipsec_enc_key_size[];
extern const struct message hash_algo_cli_str[];
extern const size_t hash_algo_cli_str_max;
extern const struct message ipsec_enc_cli_str[];
extern const size_t ipsec_enc_cli_str_max;

/* prototypes */
void ipsec_sad_add (struct ipsec_entry *);
void ipsec_sad_del (struct ipsec_entry *);
void ipsec_spd_add (struct ipsec_entry *, enum ipsec_spd_dir);
void ipsec_spd_del (struct ipsec_entry *, enum ipsec_spd_dir);
void ipsec_finish (void);
void ipsec_init (struct zebra_privs_t *);

#endif /* _IPSEC_H */
