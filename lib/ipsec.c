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

#include <zebra.h>

#include "thread.h"
#include "memory.h"
#include "log.h"
#include "ipsec.h"

static struct zebra_privs_t *ipsec_privs;
static u_int32_t reqid = 1;

const u_int8_t ipsec_enc_key_size[] =
{
  [IPSEC_ENC_3DES]       = 48,
  [IPSEC_ENC_AES_128]    = 32,
  [IPSEC_ENC_AES_192]    = 48,
  [IPSEC_ENC_AES_256]    = 64,
  [IPSEC_ENC_DES]        = 16,
  [IPSEC_ENC_NULL]       = 0,
};

const struct message hash_algo_cli_str[] =
{
  { HASH_HMAC_MD5,        "md5"              },
  { HASH_HMAC_SHA1,       "sha1"             },
  { HASH_HMAC_SHA256,     "sha256"           },
  { HASH_HMAC_SHA384,     "sha384"           },
  { HASH_HMAC_SHA512,     "sha512"           },
};
const size_t hash_algo_cli_str_max = sizeof (hash_algo_cli_str) /
     sizeof (struct message);

const struct message ipsec_enc_cli_str[] =
{
  { IPSEC_ENC_3DES,       "3des"	},
  { IPSEC_ENC_AES_128,    "aes-cbc 128"	},
  { IPSEC_ENC_AES_192,    "aes-cbc 192"	},
  { IPSEC_ENC_AES_256,    "aes-cbc 256"	},
  { IPSEC_ENC_DES,        "des"		},
  { IPSEC_ENC_NULL,       "null"	},
};
const size_t ipsec_enc_cli_str_max = sizeof (ipsec_enc_cli_str) /
     sizeof (struct message);

const struct message ipsec_enc_xfrm_str[] =
{
  { IPSEC_ENC_3DES,       "des3_ede"	},
  { IPSEC_ENC_AES_128,    "aes"		},
  { IPSEC_ENC_AES_192,    "aes"		},
  { IPSEC_ENC_AES_256,    "aes"		},
  { IPSEC_ENC_DES,        "des"		},
  { IPSEC_ENC_NULL,       "cipher_null"	},
};
const size_t ipsec_enc_xfrm_str_max = sizeof (ipsec_enc_xfrm_str) /
     sizeof (struct message);

#ifdef GNU_LINUX
static void
linux_xfrm_kernel (const char *cmd)
{
  if (ipsec_privs->change (ZPRIVS_RAISE))
    zlog_err ("%s: could not raise privs", __func__);
  if (system (cmd) != 0)
    zlog_err ("%s: could not modify ipsec policy in the kernel", __func__);
  if (ipsec_privs->change (ZPRIVS_LOWER))
    zlog_err ("%s: could not lower privs", __func__);
}

static void
linux_ipsec_sad (int add, struct ipsec_entry *ie)
{
  char cmd[512];
  char dst_str[INET6_ADDRSTRLEN];
  const char *cmd_str;
  const char *proto_str;
  char enc_key_str[IPSEC_KEY_SIZE_MAX + 3];

  inet_ntop (AF_INET6, &ie->dst, dst_str, INET6_ADDRSTRLEN);
  if (add)
    cmd_str = "add";
  else
    cmd_str = "del";
  if (ie->ipsec_proto == IPSEC_AH)
    proto_str = "ah";
  else
    {
      proto_str = "esp";
      if (add)
	{
	  if (ie->enc_type == IPSEC_ENC_NULL)
	    sprintf (enc_key_str, "\"\"");
	  else
	    sprintf (enc_key_str, "0x%s", ie->enc_key);
	}
    }

  sprintf (cmd, "ip -6 xfrm state %s dst %s proto %s spi %u", cmd_str, dst_str,
	   proto_str, ie->spi);
  if (add)
    {
      sprintf (cmd + strlen (cmd), " reqid %u mode transport auth \"hmac(%s)\" "
	       "0x%s", reqid, LOOKUP (hash_algo_cli_str, ie->auth_type),
	       ie->auth_key);
      if (ie->ipsec_proto == IPSEC_ESP)
	sprintf (cmd + strlen (cmd), " enc %s %s",
		 LOOKUP (ipsec_enc_xfrm_str, ie->enc_type), enc_key_str);

      ie->reqid = reqid;
      reqid++;
    }

  linux_xfrm_kernel (cmd);
}

static void
linux_ipsec_spd (int add, struct ipsec_entry *ie, enum ipsec_spd_dir dir)
{
  char cmd[512];
  char dst_str[INET6_ADDRSTRLEN];
  const char *cmd_str;
  const char *proto_str;
  const char *dir_str;

  inet_ntop (AF_INET6, &ie->dst, dst_str, INET6_ADDRSTRLEN);
  if (add)
    cmd_str = "add";
  else
    cmd_str = "del";
  if (ie->ipsec_proto == IPSEC_AH)
    proto_str = "ah";
  else
    proto_str = "esp";
  if (dir == IPSEC_SPD_IN)
    dir_str = "in";
  else
    dir_str = "out";

  sprintf (cmd, "ip -6 xfrm policy %s dst %s/128 dev %s proto %u dir %s",
	   cmd_str, dst_str, ie->ifname, ie->ip_proto, dir_str);
  if (add)
    sprintf (cmd + strlen (cmd), " tmpl proto %s reqid %u level required mode "
	     "transport", proto_str, ie->reqid);

  linux_xfrm_kernel (cmd);
}
#endif /* GNU_LINUX */

void
ipsec_sad_add (struct ipsec_entry *ie)
{
#ifdef GNU_LINUX
  linux_ipsec_sad (1, ie);
#endif
}

void
ipsec_sad_del (struct ipsec_entry *ie)
{
#ifdef GNU_LINUX
  linux_ipsec_sad (0, ie);
#endif
}

void
ipsec_spd_add (struct ipsec_entry *ie, enum ipsec_spd_dir dir)
{
#ifdef GNU_LINUX
  linux_ipsec_spd (1, ie, dir);
#endif
}

void
ipsec_spd_del (struct ipsec_entry *ie, enum ipsec_spd_dir dir)
{
#ifdef GNU_LINUX
  linux_ipsec_spd (0, ie, dir);
#endif
}

void
ipsec_finish (void)
{
  /* TODO */
}

void
ipsec_init (struct zebra_privs_t *privs)
{
  ipsec_privs = privs;

  /* TODO init netlink socket... */
}
