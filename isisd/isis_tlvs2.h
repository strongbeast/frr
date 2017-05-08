#ifndef ISIS_TLVS2_H
#define ISIS_TLVS2_H

#include "prefix.h"

struct isis_extended_reach;
struct isis_extended_reach {
	struct isis_extended_reach *next;

	uint8_t id[7];
	uint32_t metric;
};

struct isis_extended_ip_reach;
struct isis_extended_ip_reach {
	struct isis_extended_ip_reach *next;

	uint32_t metric;
	bool down;
	struct prefix_ipv4 prefix;
};

struct isis_item;
struct isis_item {
	struct isis_item *next;
};

struct isis_tlvs {
	struct isis_extended_reach *extended_reach;
	struct isis_extended_reach **extended_reach_next;
	struct isis_extended_ip_reach *extended_ip_reach;
	struct isis_extended_ip_reach **extended_ip_reach_next;
};

enum isis_tlv_context {
	ISIS_CONTEXT_LSP,
	ISIS_CONTEXT_SUBTLV_NE_REACH,
	ISIS_CONTEXT_SUBTLV_IP_REACH,
	ISIS_CONTEXT_MAX
};

enum isis_tlv_type {
	ISIS_TLV_PADDING = 8,
	ISIS_TLV_EXTENDED_REACH = 22,
	ISIS_TLV_EXTENDED_IP_REACH = 135,
	ISIS_TLV_MAX = 256
};

struct stream;
int isis_pack_tlvs(struct isis_tlvs *tlvs, struct stream *stream);
void isis_free_tlvs(struct isis_tlvs *tlvs);
struct isis_tlvs *isis_alloc_tlvs(void);
int isis_unpack_tlvs(size_t avail_len,
		     struct stream *stream,
		     struct isis_tlvs **dest,
		     const char **error_log);
const char *isis_format_tlvs(struct isis_tlvs *tlvs);
struct isis_tlvs *isis_copy_tlvs(struct isis_tlvs *tlvs);

#define ISIS_EXTENDED_IP_REACH_DOWN 0x80
#define ISIS_EXTENDED_IP_REACH_SUBTLV 0x40

#endif
