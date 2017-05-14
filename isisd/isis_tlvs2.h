#ifndef ISIS_TLVS2_H
#define ISIS_TLVS2_H

#include "openbsd-tree.h"
#include "prefix.h"

struct isis_subtlvs;

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

struct isis_ipv6_reach;
struct isis_ipv6_reach {
	struct isis_ipv6_reach *next;

	uint32_t metric;
	bool down;
	bool external;

	struct prefix_ipv6 prefix;

	struct isis_subtlvs *subtlvs;
};

struct isis_item;
struct isis_item {
	struct isis_item *next;
};

struct isis_item_list;
struct isis_item_list {
	struct isis_item *head;
	struct isis_item **tail;

	uint32_t mtid;
	RB_ENTRY(isis_item_list) mt_tree;
};

RB_HEAD(isis_mt_item_list, isis_item_list);

struct isis_item_list *isis_get_mt_items(struct isis_mt_item_list *m, uint32_t mtid);
struct isis_item_list *isis_lookup_mt_items(struct isis_mt_item_list *m, uint32_t mtid);

struct isis_tlvs {
	struct isis_item_list extended_reach;
	struct isis_mt_item_list mt_reach;
	struct isis_item_list extended_ip_reach;
	struct isis_mt_item_list mt_ip_reach;
	struct isis_item_list ipv6_reach;
	struct isis_mt_item_list mt_ipv6_reach;
};

struct isis_subtlvs {
	/* draft-baker-ipv6-isis-dst-src-routing-06 */
	struct prefix_ipv6 *source_prefix;
};

enum isis_tlv_context {
	ISIS_CONTEXT_LSP,
	ISIS_CONTEXT_SUBTLV_NE_REACH,
	ISIS_CONTEXT_SUBTLV_IP_REACH,
	ISIS_CONTEXT_SUBTLV_IPV6_REACH,
	ISIS_CONTEXT_MAX
};

enum isis_tlv_type {
	ISIS_TLV_PADDING = 8,
	ISIS_TLV_EXTENDED_REACH = 22,
	ISIS_TLV_EXTENDED_IP_REACH = 135,
	ISIS_TLV_IPV6_REACH = 236,
	ISIS_TLV_MAX = 256,

	ISIS_SUBTLV_IPV6_SOURCE_PREFIX = 22
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

#define ISIS_IPV6_REACH_DOWN 0x80
#define ISIS_IPV6_REACH_EXTERNAL 0x40
#define ISIS_IPV6_REACH_SUBTLV 0x20

#endif
