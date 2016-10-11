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

#include <zebra.h>

#include "command.h"
#include "if.h"
#include "vrf.h"
#include "log.h"
#include "command.h"
#include "privs.h"
#include "memory.h"

#include "ospf6d.h"
#include "ospf6_area.h"
#include "ospf6_interface.h"
#include "ospf6_message.h"
#include "ospf6_neighbor.h"
#include "ospf6_ipsec.h"

extern struct zebra_privs_t ospf6d_privs;

/* Debug option */
static unsigned char conf_debug_ospf6_ipsec;
#define OSPF6_DEBUG_IPSEC_ON() \
  (conf_debug_ospf6_ipsec = 1)
#define OSPF6_DEBUG_IPSEC_OFF() \
  (conf_debug_ospf6_ipsec = 0)
#define IS_OSPF6_DEBUG_IPSEC \
  (conf_debug_ospf6_ipsec)

static int
is_hexstr (const char *string)
{
  size_t i;

  for (i = 0; i < strlen (string); i++)
    if (! isxdigit (string[i]))
      return 0;

  return 1;
}

struct ipsec_entry *
ospf6_ipsec_install (struct ospf6_interface *oi, struct in6_addr *dst,
		     u_int8_t ipsec_proto, u_int32_t spi, u_int8_t ip_proto,
		     u_int8_t auth_type, char auth_key[], u_int8_t enc_type,
		     char enc_key[], int in, int out)
{
  struct ipsec_entry *ie;

  ie = XCALLOC (MTYPE_TMP, sizeof (*ie));
  ie->ipsec_proto = ipsec_proto;
  memcpy (&ie->dst, dst, sizeof (struct in6_addr));
  ie->spi = spi;
  ie->ip_proto = ip_proto;
  ie->auth_type = auth_type;
  strncpy (ie->auth_key, auth_key, HMAC_MAX_KEY_SIZE);
  ie->enc_type = enc_type;
  strncpy (ie->enc_key, enc_key, IPSEC_KEY_SIZE_MAX);
  strlcpy (ie->ifname, oi->interface->name, sizeof (ie->ifname));
  ie->in = in;
  ie->out = out;
  listnode_add (oi->ipsec_entries, ie);

  ipsec_sad_add (ie);
  if (in)
    ipsec_spd_add (ie, IPSEC_SPD_IN);
  if (out)
    ipsec_spd_add (ie, IPSEC_SPD_OUT);

  return ie;
}

void
ospf6_ipsec_uninstall (struct ospf6_interface *oi, struct ipsec_entry *ie)
{
  struct ospf6_neighbor *on;
  struct listnode *node;

  ipsec_sad_del (ie);
  if (ie->in)
    ipsec_spd_del (ie, IPSEC_SPD_IN);
  if (ie->out)
    ipsec_spd_del (ie, IPSEC_SPD_OUT);

  for (ALL_LIST_ELEMENTS_RO (oi->neighbor_list, node, on))
    on->ipsec_entry = NULL;

  listnode_delete (oi->ipsec_entries, ie);
  free (ie);
}

void
ospf6_update_ipsec (struct ospf6_interface *oi)
{
  struct ospf6_ipsec *ipsec = &oi->ipsec;
  struct in6_addr dst;
  struct listnode *node, *nnode;
  struct ipsec_entry *ie;
  struct ospf6_neighbor *on;

  /* remove previously installed IPsec entries on this interface */
  for (ALL_LIST_ELEMENTS (oi->ipsec_entries, node, nnode, ie))
    ospf6_ipsec_uninstall (oi, ie);

  /* OSPFv3 All SPF routers */
  inet_pton (AF_INET6, "ff02::5", &dst);
  ospf6_ipsec_install (oi, &dst, ipsec->proto, ipsec->spi, IPPROTO_OSPFIGP,
		       ipsec->auth_type, ipsec->auth_key, ipsec->enc_type,
		       ipsec->enc_key, 1, 1);

  /* OSPFv3 All DR routers */
  inet_pton (AF_INET6, "ff02::6", &dst);
  ospf6_ipsec_install (oi, &dst, ipsec->proto, ipsec->spi, IPPROTO_OSPFIGP,
		       ipsec->auth_type, ipsec->auth_key, ipsec->enc_type,
		       ipsec->enc_key, 1, 1);

  /* Incoming unicast */
  if (oi->linklocal_addr)
    {
      ospf6_ipsec_install (oi, oi->linklocal_addr, ipsec->proto, ipsec->spi,
			   IPPROTO_OSPFIGP, ipsec->auth_type, ipsec->auth_key,
			   ipsec->enc_type, ipsec->enc_key, 1, 0);
    }

  /* Outgoing unicast */
  for (ALL_LIST_ELEMENTS_RO (oi->neighbor_list, node, on))
    if (on->ospf6_if == oi && on->state != OSPF6_NEIGHBOR_DOWN)
      {
	ospf6_ipsec_install (oi, &on->linklocal_addr, ipsec->proto, ipsec->spi,
			     IPPROTO_OSPFIGP, ipsec->auth_type, ipsec->auth_key,
			     ipsec->enc_type, ipsec->enc_key, 0, 1);
      }
}

int
vty_ospf6_ipsec (struct vty *vty, struct vty_arg *args[])
{
  VTY_DECLVAR_CONTEXT(interface, ifp);
  struct ospf6_interface *oi, *oi_tmp;
  struct ospf6_ipsec *ipsec;
  int remove;
  u_int8_t proto;
  u_int32_t spi;
  const char *auth_type_str;
  int auth_type = 0;
  int auth_key_len = 0;
  const char *auth_key = NULL;
  const char *enc_type_str;
  int enc_type = 0;
  int enc_key_len = 0;
  const char *enc_key = NULL;
  struct listnode *node;

  oi = (struct ospf6_interface *) ifp->info;
  if (oi == NULL)
    oi = ospf6_interface_create (ifp);
  assert (oi);
  ipsec = &oi->ipsec;

  remove = vty_get_arg_value (args, "no") ? 1 : 0;

  if (strcmp (vty_get_arg_value (args, "ipsec"), "authentication") == 0)
    proto = IPSEC_AH;
  else
    proto = IPSEC_ESP;

  spi = atoi (vty_get_arg_value (args, "spi"));

  auth_type_str = vty_get_arg_value (args, "auth_type");
  auth_key = vty_get_arg_value (args, "auth_key");
  if (auth_type_str)
    {
      if (strcmp (auth_type_str, "md5") == 0)
	{
	  auth_type = HASH_HMAC_MD5;
	  auth_key_len = HMAC_MD5_KEY_SIZE;
	}
      else
	{
	  auth_type = HASH_HMAC_SHA1;
	  auth_key_len = HMAC_SHA1_KEY_SIZE;
	}
    }

  enc_type_str = vty_get_arg_value (args, "enc_type");
  if (enc_type_str)
    {
      if (strcmp (enc_type_str, "3des") == 0)
	enc_type = IPSEC_ENC_3DES;
      else if (strcmp (enc_type_str, "aes-cbc") == 0)
	{
	  const char *aes_key_len_str;

	  aes_key_len_str = vty_get_arg_value (args, "aes_key_len");
	  if (strcmp (aes_key_len_str, "128") == 0)
	    enc_type = IPSEC_ENC_AES_128;
	  else if (strcmp (aes_key_len_str, "192") == 0)
	    enc_type = IPSEC_ENC_AES_192;
	  else if (strcmp (aes_key_len_str, "256") == 0)
	    enc_type = IPSEC_ENC_AES_256;
	  else
	    assert (0);

	}
      else if (strcmp (enc_type_str, "des") == 0)
	enc_type = IPSEC_ENC_DES;
      else if (strcmp (enc_type_str, "null") == 0)
	enc_type = IPSEC_ENC_NULL;
      else
	assert (0);

      if (enc_type != IPSEC_ENC_NULL)
	{
	  enc_key = vty_get_arg_value (args, "enc_key");
	  enc_key_len = ipsec_enc_key_size[enc_type];
	}
    }

  if (remove)
    {
      if (ipsec->proto != proto)
	return CMD_SUCCESS;
      if (ipsec->spi != spi)
	return CMD_SUCCESS;

      memset (ipsec, 0, sizeof (*ipsec));
      ipsec->proto = IPSEC_DISABLED;
    }
  else
    {
      /* validate keys */
      if (strlen (auth_key) != (size_t) auth_key_len)
	{
	  vty_out (vty, "%% Invalid authentication key length%s", VNL);
	  return CMD_WARNING;
	}
      if (! is_hexstr (auth_key))
	{
	  vty_out (vty, "%% Invalid authentication key%s", VNL);
	  return CMD_WARNING;
	}
      if (proto == IPSEC_ESP)
	{
	  if (enc_type != IPSEC_ENC_NULL &&
	      strlen (enc_key) != (size_t) enc_key_len)
	    {
	      vty_out (vty, "%% Invalid encryption key length%s", VNL);
	      return CMD_WARNING;
	    }
	  if (enc_type != IPSEC_ENC_NULL &&
	      ! is_hexstr (enc_key))
	    {
	      vty_out (vty, "%% Invalid encryption key%s", VNL);
	      return CMD_WARNING;
	    }
	}

      /* additional consistency checks */
      if (proto == IPSEC_ESP && ipsec->proto == IPSEC_AH)
	{
	  vty_out (vty, "OSPFv3: Interface %s is already configured with "
		   "authentication so%s cannot configure encryption%s",
		   oi->interface->name, VNL, VNL);
	  return CMD_WARNING;
	}
      else if (proto == IPSEC_AH && ipsec->proto == IPSEC_ESP)
	{
	  vty_out (vty, "OSPFv3: Interface %s is already configured with "
		   "encryption so%s cannot configure authentication%s",
		   oi->interface->name, VNL, VNL);
	  return CMD_WARNING;
	}
      if (ipsec->proto != IPSEC_DISABLED && ipsec->spi == spi)
	{
	  /* warning only */
	  vty_out (vty, "OSPFv3: Interface %s is already configured with SPI "
		   "%u%s", oi->interface->name, spi, VNL);
	}
      for (ALL_LIST_ELEMENTS_RO (vrf_iflist (VRF_DEFAULT), node, ifp))
	{
	  oi_tmp = (struct ospf6_interface *) ifp->info;
	  if (!oi_tmp)
	    continue;

	  if (oi_tmp->ipsec.spi == spi && oi != oi_tmp)
	    {
	      vty_out (vty, "%% SPI %u is already in use%s", spi, VNL);
	      return CMD_WARNING;
	    }
	}

      ipsec->proto = proto;
      ipsec->spi = spi;
      ipsec->auth_type = auth_type;
      memset (ipsec->auth_key, 0, HMAC_MAX_KEY_SIZE + 1);
      strncpy (ipsec->auth_key, auth_key, auth_key_len);
      if (proto == IPSEC_ESP)
	{
	  ipsec->enc_type = enc_type;
	  if (ipsec->enc_type != IPSEC_ENC_NULL)
	    {
	      memset (ipsec->enc_key, 0, IPSEC_KEY_SIZE_MAX + 1);
	      strncpy (ipsec->enc_key, enc_key, enc_key_len);
	    }
	}
    }

  ospf6_update_ipsec (oi);

  return CMD_SUCCESS;
}

int
vty_ospf6_ipsec_debug (struct vty *vty, struct vty_arg *args[])
{
  if (vty_get_arg_value (args, "no"))
    OSPF6_DEBUG_IPSEC_OFF ();
  else
    OSPF6_DEBUG_IPSEC_ON ();

  return CMD_SUCCESS;
}

int
config_write_ospf6_debug_ipsec (struct vty *vty)
{
  if (IS_OSPF6_DEBUG_IPSEC)
    vty_out (vty, "debug ospf6 ipsec%s", VNL);
  return 0;
}

void
ospf6_ipsec_init(void)
{
  ipsec_init (&ospf6d_privs);
  ospf6_vty_ipsec_init ();
}
