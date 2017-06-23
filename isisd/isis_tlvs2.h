#ifndef ISIS_TLVS2_H
#define ISIS_TLVS2_H

#include "openbsd-tree.h"
#include "prefix.h"

struct isis_subtlvs;

struct isis_area_address;
struct isis_area_address {
	struct isis_area_address *next;

	uint8_t addr[20];
	uint8_t len;
};

struct isis_oldstyle_reach;
struct isis_oldstyle_reach {
	struct isis_oldstyle_reach *next;

	uint8_t id[7];
	uint8_t metric;
};

struct isis_oldstyle_ip_reach;
struct isis_oldstyle_ip_reach {
	struct isis_oldstyle_ip_reach *next;

	uint8_t metric;
	struct prefix_ipv4 prefix;
};

struct isis_lsp_entry;
struct isis_lsp_entry {
	struct isis_lsp_entry *next;

	uint16_t rem_lifetime;
	uint8_t id[8];
	uint16_t checksum;
	uint32_t seqno;

	struct isis_lsp *lsp;
};

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

struct isis_protocols_supported {
	uint8_t count;
	uint8_t *protocols;
};

struct isis_item;
struct isis_item {
	struct isis_item *next;
};

struct isis_lan_neighbor;
struct isis_lan_neighbor {
	struct isis_lan_neighbor *next;

	uint8_t mac[6];
};

struct isis_ipv4_address;
struct isis_ipv4_address {
	struct isis_ipv4_address *next;

	struct in_addr addr;
};

struct isis_ipv6_address;
struct isis_ipv6_address {
	struct isis_ipv6_address *next;

	struct in6_addr addr;
};

struct isis_mt_router_info;
struct isis_mt_router_info {
	struct isis_mt_router_info *next;

	bool overload;
	bool attached;
	uint16_t mtid;
};

struct isis_auth;
struct isis_auth {
	struct isis_auth *next;

	uint8_t type;
	uint8_t length;
	uint8_t value[256];

	uint8_t plength;
	uint8_t passwd[256];

	size_t offset; /* Only valid after packing */
};

struct isis_item_list;
struct isis_item_list {
	struct isis_item *head;
	struct isis_item **tail;

	RB_ENTRY(isis_item_list) mt_tree;
	uint16_t mtid;
	unsigned int count;
};

RB_HEAD(isis_mt_item_list, isis_item_list);

struct isis_item_list *isis_get_mt_items(struct isis_mt_item_list *m, uint16_t mtid);
struct isis_item_list *isis_lookup_mt_items(struct isis_mt_item_list *m, uint16_t mtid);

struct isis_tlvs {
	struct isis_item_list isis_auth;
	struct isis_item_list area_addresses;
	struct isis_item_list oldstyle_reach;
	struct isis_item_list lan_neighbor;
	struct isis_item_list lsp_entries;
	struct isis_item_list extended_reach;
	struct isis_mt_item_list mt_reach;
	struct isis_item_list oldstyle_ip_reach;
	struct isis_protocols_supported protocols_supported;
	struct isis_item_list oldstyle_ip_reach_ext;
	struct isis_item_list ipv4_address;
	struct isis_item_list ipv6_address;
	struct isis_item_list mt_router_info;
	bool mt_router_info_empty;
	struct isis_item_list extended_ip_reach;
	struct isis_mt_item_list mt_ip_reach;
	char *hostname;
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

/* TODO: 12 Checksum
        134 TE Router ID
*/


enum isis_tlv_type {
	ISIS_TLV_AREA_ADDRESSES = 1,
	ISIS_TLV_OLDSTYLE_REACH = 2,
	ISIS_TLV_LAN_NEIGHBORS = 6,
	ISIS_TLV_PADDING = 8,
	ISIS_TLV_LSP_ENTRY = 9,
	ISIS_TLV_AUTH = 10,
	ISIS_TLV_EXTENDED_REACH = 22,

	ISIS_TLV_OLDSTYLE_IP_REACH = 128,
	ISIS_TLV_PROTOCOLS_SUPPORTED = 129,
	ISIS_TLV_OLDSTYLE_IP_REACH_EXT = 130,
	ISIS_TLV_IPV4_ADDRESS = 132,
	ISIS_TLV_EXTENDED_IP_REACH = 135,
	ISIS_TLV_DYNAMIC_HOSTNAME = 137,
	ISIS_TLV_MT_REACH = 222,
	ISIS_TLV_MT_ROUTER_INFO = 229,
	ISIS_TLV_IPV6_ADDRESS = 232,
	ISIS_TLV_MT_IP_REACH = 235,
	ISIS_TLV_IPV6_REACH = 236,
	ISIS_TLV_MT_IPV6_REACH = 237,
	ISIS_TLV_MAX = 256,

	ISIS_SUBTLV_IPV6_SOURCE_PREFIX = 22
};

#define IS_COMPAT_MT_TLV(tlv_type) \
	(  (tlv_type == ISIS_TLV_MT_REACH) \
	 ||(tlv_type == ISIS_TLV_MT_IP_REACH) \
	 ||(tlv_type == ISIS_TLV_MT_IPV6_REACH))

struct stream;
int isis_pack_tlvs(struct isis_tlvs *tlvs, struct stream *stream,
                   size_t len_pointer, bool pad);
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

#ifndef ISIS_MT_MASK
#define ISIS_MT_MASK           0x0fff
#define ISIS_MT_OL_MASK        0x8000
#define ISIS_MT_AT_MASK        0x4000
#endif

void isis_tlvs_add_auth(struct isis_tlvs *tlvs, struct isis_passwd *passwd);
void isis_tlvs_add_area_addresses(struct isis_tlvs *tlvs, struct list *addresses);
void isis_tlvs_add_lan_neighbors(struct isis_tlvs *tlvs, struct list *neighbors);
void isis_tlvs_set_protocols_supported(struct isis_tlvs *tlvs, struct nlpids *nlpids);
void isis_tlvs_add_mt_router_info(struct isis_tlvs *tlvs, uint16_t mtid,
                                  bool overload, bool attached);
void isis_tlvs_add_ipv4_addresses(struct isis_tlvs *tlvs, struct list *addresses);
void isis_tlvs_add_ipv6_addresses(struct isis_tlvs *tlvs, struct list *addresses);
bool isis_tlvs_auth_is_valid(struct isis_tlvs *tlvs, struct isis_passwd *passwd,
                             struct stream *stream);
bool isis_tlvs_area_addresses_match(struct isis_tlvs *tlvs, struct list *addresses);
struct isis_adjacency;
void isis_tlvs_to_adj(struct isis_tlvs *tlvs, struct isis_adjacency *adj, bool *changed);
bool isis_tlvs_own_snpa_found(struct isis_tlvs *tlvs, uint8_t *snpa);
void isis_tlvs_add_lsp_entry(struct isis_tlvs *tlvs, struct isis_lsp *lsp);
#endif
