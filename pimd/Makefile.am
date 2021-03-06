## Process this file with automake to produce Makefile.in.

# qpimd - pimd for quagga
# Copyright (C) 2008 Everton da Silva Marques
#
# qpimd is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 2,
# or (at your option) any later version.
# 
# qpimd is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public
# License along with qpimd; see the file COPYING.  If not, write
# to the Free Software Foundation, Inc., 59 Temple Place - Suite
# 330, Boston, MA 02111-1307, USA.

# PIM_DEBUG_BYDEFAULT: Automatically enables all pimd "debug ..." commands
# PIM_CHECK_RECV_IFINDEX_SANITY: Compare socket ifindex with recv ifindex
# PIM_REPORT_RECV_IFINDEX_MISMATCH: Report sock/recv ifindex mismatch
# PIM_ENFORCE_LOOPFREE_MFC: Refuse adding looping MFC entries
# PIM_UNEXPECTED_KERNEL_UPCALL: Report unexpected kernel upcall

PIM_DEFS =
#PIM_DEFS += -DPIM_DEBUG_BYDEFAULT
#PIM_DEFS += -DPIM_CHECK_RECV_IFINDEX_SANITY
#PIM_DEFS += -DPIM_REPORT_RECV_IFINDEX_MISMATCH
PIM_DEFS += -DPIM_ENFORCE_LOOPFREE_MFC
#PIM_DEFS += -DPIM_UNEXPECTED_KERNEL_UPCALL

AM_CPPFLAGS = -I.. -I$(top_srcdir) -I$(top_srcdir)/lib -I$(top_builddir)/lib
DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\" $(PIM_DEFS)
INSTALL_SDATA=@INSTALL@ -m 600
LIBS = @LIBS@

AM_CFLAGS = $(WERROR)

noinst_LIBRARIES = libpim.a
sbin_PROGRAMS = pimd 
noinst_PROGRAMS = test_igmpv3_join

libpim_a_SOURCES = \
	pim_memory.c \
	pimd.c pim_version.c pim_cmd.c pim_signals.c pim_iface.c \
	pim_vty.c pim_igmp.c pim_sock.c pim_zebra.c pim_igmpv2.c \
	pim_igmpv3.c pim_str.c pim_mroute.c pim_util.c pim_time.c \
	pim_oil.c pim_zlookup.c pim_pim.c pim_tlv.c pim_neighbor.c \
	pim_hello.c pim_ifchannel.c pim_join.c pim_assert.c \
	pim_msg.c pim_upstream.c pim_rpf.c pim_macro.c \
	pim_ssmpingd.c pim_int.c pim_rp.c \
	pim_static.c pim_br.c pim_register.c pim_routemap.c \
	pim_msdp.c pim_msdp_socket.c pim_msdp_packet.c \
	pim_jp_agg.c pim_nht.c pim_ssm.c pim_bfd.c

noinst_HEADERS = \
	pim_memory.h \
	pimd.h pim_version.h pim_cmd.h pim_signals.h pim_iface.h \
	pim_vty.h pim_igmp.h pim_sock.h pim_zebra.h pim_igmpv2.h \
	pim_igmpv3.h pim_str.h pim_mroute.h pim_util.h pim_time.h \
	pim_oil.h pim_zlookup.h pim_pim.h pim_tlv.h pim_neighbor.h \
	pim_hello.h pim_ifchannel.h pim_join.h pim_assert.h \
	pim_msg.h pim_upstream.h pim_rpf.h pim_macro.h \
	pim_igmp_join.h pim_ssmpingd.h pim_int.h pim_rp.h \
	pim_static.h pim_br.h pim_register.h \
	pim_msdp.h pim_msdp_socket.h pim_msdp_packet.h pim_nht.h \
	pim_jp_agg.h pim_ssm.h pim_bfd.h

pimd_SOURCES = \
	pim_main.c $(libpim_a_SOURCES)

test_igmpv3_join_SOURCES = \
	test_igmpv3_join.c

pimd_LDADD = ../lib/libfrr.la @LIBCAP@
test_igmpv3_join_LDADD = ../lib/libfrr.la

examplesdir = $(exampledir)
dist_examples_DATA = pimd.conf.sample
