#include <zebra.h>

#include "memory.h"
#include "stream.h"
#include "sbuf.h"

#include "isisd/isisd.h"
#include "isisd/isis_memory.h"
#include "isis_tlvs2.h"
#include "isis_common2.h"

DEFINE_MTYPE_STATIC(ISISD, ISIS_TLV2, "ISIS TLVs (new)")
DEFINE_MTYPE_STATIC(ISISD, ISIS_SUBTLV, "ISIS Sub-TLVs")
DEFINE_MTYPE_STATIC(ISISD, ISIS_MT_ITEM_LIST, "ISIS MT Item Lists")

typedef int(*unpack_tlv_func)(enum isis_tlv_context context,
			     uint8_t tlv_type, uint8_t tlv_len,
			     struct stream *s, struct sbuf *log,
			     void *dest, int indent);
typedef int(*pack_item_func)(struct isis_item *item, struct stream *s);
typedef void(*free_item_func)(struct isis_item *i);
typedef int(*unpack_item_func)(uint8_t len, struct stream *s,
			       struct sbuf *log, void *dest,
			       int indent);
typedef void(*format_item_func)(struct isis_item *i, struct sbuf *buf,
				int indent);
typedef struct isis_item *(*copy_item_func)(struct isis_item *i);

struct tlv_ops {
	const char *name;
	unpack_tlv_func unpack;

	pack_item_func pack_item;
	free_item_func free_item;
	unpack_item_func unpack_item;
	format_item_func format_item;
	copy_item_func copy_item;
};

static int isis_mt_item_list_cmp(struct isis_item_list *a, struct isis_item_list *b)
{
	if (a->mtid < b->mtid)
		return -1;
	if (a->mtid > b->mtid)
		return 1;
	return 0;
}

RB_GENERATE_STATIC(isis_mt_item_list, isis_item_list, mt_tree, isis_mt_item_list_cmp);

static void init_item_list(struct isis_item_list *items)
{
	items->head = NULL;
	items->tail = &items->head;
}

struct isis_item_list *isis_get_mt_items(struct isis_mt_item_list *m, uint32_t mtid)
{
	struct isis_item_list *rv;

	rv = isis_lookup_mt_items(m, mtid);
	if (!rv) {
		rv = XMALLOC(MTYPE_ISIS_MT_ITEM_LIST, sizeof(*rv));
		init_item_list(rv);
		rv->mtid = mtid;
		RB_INSERT(isis_mt_item_list, m, rv);
	}

	return rv;
}

struct isis_item_list *isis_lookup_mt_items(struct isis_mt_item_list *m, uint32_t mtid)
{
	struct isis_item_list key = {
		.mtid = mtid
	};

	return RB_FIND(isis_mt_item_list, m, &key);
}

static void free_items(enum isis_tlv_context context, enum isis_tlv_type type,
		       struct isis_item_list *items);

static void free_mt_items(enum isis_tlv_context context, enum isis_tlv_type type,
                          struct isis_mt_item_list *m)
{
	struct isis_item_list *n, *nnext;

	RB_FOREACH_SAFE(n, isis_mt_item_list, m, nnext) {
		free_items(context, type, n);
		RB_REMOVE(isis_mt_item_list, m, n);
		XFREE(MTYPE_ISIS_MT_ITEM_LIST, n);
	}
}

/* This is a forward definition. The table is actually filled
 * in at the bottom. */
static const struct tlv_ops *tlv_table[ISIS_CONTEXT_MAX][ISIS_TLV_MAX];

/* End of _ops forward definition. */

static int pack_subtlv_ipv6_source_prefix(struct prefix_ipv6 *p, struct stream *s)
{
	if (!p)
		return 0;

	if (STREAM_WRITEABLE(s) < 3 + (unsigned)PSIZE(p->prefixlen))
		return 1;

	stream_putc(s, ISIS_SUBTLV_IPV6_SOURCE_PREFIX);
	stream_putc(s, 1 + PSIZE(p->prefixlen));
	stream_putc(s, p->prefixlen);
	stream_put(s, &p->prefix, PSIZE(p->prefixlen));
	return 0;
}

static int pack_subtlvs(struct isis_subtlvs *subtlvs, struct stream *s)
{
	int rv;
	size_t subtlv_len_pos = stream_get_endp(s);

	if (STREAM_WRITEABLE(s) < 1)
		return 1;

	stream_putc(s, 0); /* Put 0 as subtlvs length, filled in later */

	rv = pack_subtlv_ipv6_source_prefix(subtlvs->source_prefix, s);
	if (rv)
		return rv;

	size_t subtlv_len = stream_get_endp(s) - subtlv_len_pos - 1;
	if (subtlv_len > 255)
		return 1;

	stream_putc_at(s, subtlv_len_pos, subtlv_len);
	return 0;
}

static int pack_item_extended_reach(struct isis_item *i,
				    struct stream *s)
{
	struct isis_extended_reach *r = (struct isis_extended_reach*)i;

	if (STREAM_WRITEABLE(s) < 11)
		return 1;
	stream_put(s, r->id, sizeof(r->id));
	stream_put3(s, r->metric);
	stream_putc(s, 0); /* Put 0 as subtlv length, filled in later */
#if 0 /* old subtlv code */
	rv = isis_pack_tlvs(r->subtlvs, s);
	if (rv)
		return rv;

	/* Fill in subtlv len */
	subtlv_len = stream_get_endp(s) - subtlv_len_pos - 1;
	if (subtlv_len > 255)
		return 1;

	stream_putc_at(s, subtlv_len_pos, subtlv_len);
#endif
	return 0;
}

static int pack_item_extended_ip_reach(struct isis_item *i,
				       struct stream *s)
{
	struct isis_extended_ip_reach *r = (struct isis_extended_ip_reach*)i;
	uint8_t control;

	if (STREAM_WRITEABLE(s) < 5)
		return 1;
	stream_putl(s, r->metric);

	control = r->down ? ISIS_EXTENDED_IP_REACH_DOWN : 0;
#if 0
	control |= TODO_HAS_SUB ? ISIS_EXTENDED_IP_REACH_SUBTLV : 0;
#endif
	control |= r->prefix.prefixlen;
	stream_putc(s, control);

	if (STREAM_WRITEABLE(s) < (unsigned)PSIZE(r->prefix.prefixlen))
		return 1;
	stream_put(s, &r->prefix.prefix.s_addr, PSIZE(r->prefix.prefixlen));

#if 0
	if (r->subtlvs) {
		subtlv_len_pos = stream_get_endp(s);
		stream_putc(s, 0); /* Put 0 as subtlv length, filled in later */
		rv = isis_pack_tlvs(r->subtlvs, s);
		if (rv)
			return rv;

		/* Fill in subtlv len */
		subtlv_len = stream_get_endp(s) - subtlv_len_pos - 1;
		if (subtlv_len > 255)
			return 1;

		stream_putc_at(s, subtlv_len_pos, subtlv_len);
	}
#endif

	return 0;
}

static int pack_item_ipv6_reach(struct isis_item *i,
				struct stream *s)
{
	struct isis_ipv6_reach *r = (struct isis_ipv6_reach*)i;
	uint8_t control;

	if (STREAM_WRITEABLE(s) < 6)
		return 1;
	stream_putl(s, r->metric);

	control = r->down ? ISIS_IPV6_REACH_DOWN : 0;
	control |= r->external ? ISIS_IPV6_REACH_EXTERNAL : 0;
	control |= r->subtlvs ? ISIS_IPV6_REACH_SUBTLV : 0;

	stream_putc(s, control);
	stream_putc(s, r->prefix.prefixlen);

	if (STREAM_WRITEABLE(s) < (unsigned)PSIZE(r->prefix.prefixlen))
		return 1;
	stream_put(s, &r->prefix.prefix.s6_addr, PSIZE(r->prefix.prefixlen));

	if (r->subtlvs)
		return pack_subtlvs(r->subtlvs, s);

	return 0;
}

static int pack_item(enum isis_tlv_context context, enum isis_tlv_type type,
		     struct isis_item *i, struct stream *s)
{
	const struct tlv_ops *ops = tlv_table[context][type];

	if (ops && ops->pack_item)
		return ops->pack_item(i, s);

	assert(!"Unknown item tlv type!");
	return 1;
}

static int pack_items(enum isis_tlv_context context, enum isis_tlv_type type,
		      struct isis_item_list *items, struct stream *s)
{
	size_t len_pos, last_len, len;
	struct isis_item *item = NULL;
	int rv;

	if (!items->head)
		return 0;

top:
	if (STREAM_WRITEABLE(s) < 2)
		return 1;
	stream_putc(s, type);
	len_pos = stream_get_endp(s);
	stream_putc(s, 0); /* Put 0 as length for now */

	last_len = len = 0;
	for (item = item ? item : items->head; item; item = item->next) {
		rv = pack_item(context, type, item, s);
		if (rv)
			return rv;

		len = stream_get_endp(s) - len_pos - 1;
		if (len > 255) {
			if (!last_len) /* strange, not a single item fit */
				return 1;
			/* drop last tlv, otherwise, its too long */
			stream_set_endp(s, len_pos + 1 + last_len);
			len = last_len;
			break;
		}
		last_len = len;
	}

	stream_putc_at(s, len_pos, len);
	if (item)
		goto top;

	return 0;
}

int isis_pack_tlvs(struct isis_tlvs *tlvs, struct stream *stream)
{
	int rv;

	rv = pack_items(ISIS_CONTEXT_LSP, ISIS_TLV_EXTENDED_REACH,
			&tlvs->extended_reach, stream);
	if (rv)
		return rv;

	rv = pack_items(ISIS_CONTEXT_LSP, ISIS_TLV_EXTENDED_IP_REACH,
			&tlvs->extended_ip_reach, stream);
	if (rv)
		return rv;

	rv = pack_items(ISIS_CONTEXT_LSP, ISIS_TLV_IPV6_REACH,
			&tlvs->ipv6_reach, stream);
	if (rv)
		return rv;

	return 0;
}

static void isis_free_subtlvs(struct isis_subtlvs *subtlvs)
{
	if (!subtlvs)
		return;

	XFREE(MTYPE_ISIS_SUBTLV, subtlvs->source_prefix);

	XFREE(MTYPE_ISIS_SUBTLV, subtlvs);
}

static void free_item_extended_reach(struct isis_item *i)
{
	struct isis_extended_reach *item = (struct isis_extended_reach*)i;
	XFREE(MTYPE_ISIS_TLV2, item);
}

static void free_item_extended_ip_reach(struct isis_item *i)
{
	struct isis_extended_ip_reach *item = (struct isis_extended_ip_reach*)i;
	XFREE(MTYPE_ISIS_TLV2, item);
}

static void free_item_ipv6_reach(struct isis_item *i)
{
	struct isis_ipv6_reach *item = (struct isis_ipv6_reach*)i;

	isis_free_subtlvs(item->subtlvs);
	XFREE(MTYPE_ISIS_TLV2, item);
}

static void free_item(enum isis_tlv_context tlv_context,
		      enum isis_tlv_type tlv_type,
		      struct isis_item *item)
{
	const struct tlv_ops *ops = tlv_table[tlv_context][tlv_type];

	if (ops && ops->free_item) {
		ops->free_item(item);
		return;
	}

	assert(!"Unknown item tlv type!");
}

static void free_items(enum isis_tlv_context context, enum isis_tlv_type type,
		       struct isis_item_list *items)
{
	struct isis_item *item, *next_item;

	for (item = items->head; item; item = next_item) {
		next_item = item->next;
		free_item(context, type, item);
	}
}

void isis_free_tlvs(struct isis_tlvs *tlvs)
{
	if (!tlvs)
		return;

	free_items(ISIS_CONTEXT_LSP, ISIS_TLV_EXTENDED_REACH,
		   &tlvs->extended_reach);
	free_mt_items(ISIS_CONTEXT_LSP, ISIS_TLV_EXTENDED_REACH,
		   &tlvs->mt_reach);
	free_items(ISIS_CONTEXT_LSP, ISIS_TLV_EXTENDED_IP_REACH,
		   &tlvs->extended_ip_reach);
	free_mt_items(ISIS_CONTEXT_LSP, ISIS_TLV_EXTENDED_IP_REACH,
		   &tlvs->mt_ip_reach);
	free_items(ISIS_CONTEXT_LSP, ISIS_TLV_IPV6_REACH,
		   &tlvs->ipv6_reach);
	free_mt_items(ISIS_CONTEXT_LSP, ISIS_TLV_IPV6_REACH,
		   &tlvs->mt_ipv6_reach);

	XFREE(MTYPE_ISIS_TLV2, tlvs);
}

static void append_item(struct isis_item_list *dest, struct isis_item *item)
{
	*dest->tail = item;
	dest->tail = &(*dest->tail)->next;
}

static struct isis_subtlvs *isis_alloc_subtlvs(void);
static int unpack_tlvs(enum isis_tlv_context context,
                       size_t avail_len, struct stream *stream,
                       struct sbuf *log, void *dest, int indent);

static void format_item_extended_reach(struct isis_item *i,
				       struct sbuf *buf, int indent);

static int unpack_item_extended_reach(uint8_t len,
				      struct stream *s,
				      struct sbuf *log,
				      void *dest,
				      int indent)
{
	struct isis_tlvs *tlvs = dest;
	struct isis_extended_reach *rv = NULL;
	uint8_t subtlv_len;

	sbuf_push(log, indent, "Unpacking extended reachability...\n");

	if (len < 11) {
		sbuf_push(log, indent, "Not enough data left. "
			  "(expected 11 or more bytes, got %" PRIu8 ")\n", len);
		goto out;
	}

	rv = XCALLOC(MTYPE_ISIS_TLV2, sizeof(*rv));
	stream_get(rv->id, s, 7);
	rv->metric = stream_get3(s);
	subtlv_len = stream_getc(s);

	format_item_extended_reach((struct isis_item*)rv, log, indent + 2);

	if ((size_t)len < ((size_t)11) + subtlv_len) {
		sbuf_push(log, indent, "Not enough data left for subtlv size %" PRIu8
		          ", there are only %" PRIu8 " bytes left.\n",
			  subtlv_len, len - 11);
		goto out;
	}

	sbuf_push(log, indent, "Skipping %" PRIu8 " bytes of subtlvs\n",
		  subtlv_len);

	stream_forward_getp(s, subtlv_len);

	append_item(&tlvs->extended_reach, (struct isis_item*)rv);
	return 0;
out:
	if (rv)
		free_item_extended_reach((struct isis_item*)rv);

	return 1;
}

static void format_item_extended_ip_reach(struct isis_item *i,
					  struct sbuf *buf, int indent);

static int unpack_item_extended_ip_reach(uint8_t len,
					 struct stream *s,
					 struct sbuf *log,
					 void *dest,
					 int indent)
{
	struct isis_tlvs *tlvs = dest;
	struct isis_extended_ip_reach *rv = NULL;
	size_t consume;
	uint8_t control, subtlv_len;

	sbuf_push(log, indent, "Unpacking extended IPv4 reachability...\n");
	consume = 5;
	if (len < consume) {
		sbuf_push(log, indent, "Not enough data left. "
			  "(expected 5 or more bytes, got %" PRIu8 ")\n", len);
		goto out;
	}

	rv = XCALLOC(MTYPE_ISIS_TLV2, sizeof(*rv));

	rv->metric = stream_getl(s);
	control = stream_getc(s);
	rv->down = (control & ISIS_EXTENDED_IP_REACH_DOWN);
	rv->prefix.family = AF_INET;
	rv->prefix.prefixlen = control & 0x3f;
	if (rv->prefix.prefixlen > 32) {
		sbuf_push(log, indent, "Prefixlen %u is inplausible for IPv4\n",
			  rv->prefix.prefixlen);
		goto out;
	}

	consume += PSIZE(rv->prefix.prefixlen);
	if (len < consume) {
		sbuf_push(log, indent, "Expected %u bytes of prefix, but only %u"
			  " bytes available.\n", PSIZE(rv->prefix.prefixlen),
			  len - 5);
		goto out;
	}
	stream_get(&rv->prefix.prefix.s_addr, s, PSIZE(rv->prefix.prefixlen));
	in_addr_t orig_prefix = rv->prefix.prefix.s_addr;
	apply_mask_ipv4(&rv->prefix);
	if (orig_prefix != rv->prefix.prefix.s_addr)
		sbuf_push(log, indent + 2, "WARNING: Prefix had hostbits set.\n");
	format_item_extended_ip_reach((struct isis_item*)rv, log, indent + 2);

	if (control & ISIS_EXTENDED_IP_REACH_SUBTLV) {
		consume += 1;
		if (len < consume) {
			sbuf_push(log, indent, "Expected 1 byte of subtlv len, but "
			          "no more data present.\n");
			goto out;
		}
		subtlv_len = stream_getc(s);

		if (!subtlv_len) {
			sbuf_push(log, indent + 2, "  WARNING: subtlv bit is set, but "
				  "there are no subtlvs.\n");
		}
		consume += subtlv_len;
		if (len < consume) {
			sbuf_push(log, indent, "Expected %" PRIu8 " bytes of subtlvs,"
				  " but only %u bytes available.\n",
				  subtlv_len,
				  len - 6 - PSIZE(rv->prefix.prefixlen));
			goto out;
		}
		sbuf_push(log, indent, "Skipping %" PRIu8 " bytes of subvls",
			  subtlv_len);
		stream_forward_getp(s, subtlv_len);
	}

	append_item(&tlvs->extended_ip_reach, (struct isis_item*)rv);
	return 0;
out:
	if (rv)
		free_item_extended_ip_reach((struct isis_item*)rv);
	return 1;
}

static void format_item_ipv6_reach(struct isis_item *i,
				   struct sbuf *buf, int indent);

static int unpack_item_ipv6_reach(uint8_t len,
				  struct stream *s,
				  struct sbuf *log,
				  void *dest,
				  int indent)
{
	struct isis_tlvs *tlvs = dest;
	struct isis_ipv6_reach *rv = NULL;
	size_t consume;
	uint8_t control, subtlv_len;

	sbuf_push(log, indent, "Unpacking IPv6 reachability...\n");
	consume = 6;
	if (len < consume) {
		sbuf_push(log, indent, "Not enough data left. "
		          "(expected 6 or more bytes, got %" PRIu8 ")\n", len);
		goto out;
	}

	rv = XCALLOC(MTYPE_ISIS_TLV2, sizeof(*rv));

	rv->metric = stream_getl(s);
	control = stream_getc(s);
	rv->down = (control & ISIS_IPV6_REACH_DOWN);
	rv->external = (control & ISIS_IPV6_REACH_EXTERNAL);

	rv->prefix.family = AF_INET6;
	rv->prefix.prefixlen = stream_getc(s);
	if (rv->prefix.prefixlen > 128) {
		sbuf_push(log, indent, "Prefixlen %u is inplausible for IPv6\n",
		          rv->prefix.prefixlen);
		goto out;
	}

	consume += PSIZE(rv->prefix.prefixlen);
	if (len < consume) {
		sbuf_push(log, indent, "Expected %u bytes of prefix, but only %u"
		          " bytes available.\n", PSIZE(rv->prefix.prefixlen),
		          len - 5);
		goto out;
	}
	stream_get(&rv->prefix.prefix.s6_addr, s, PSIZE(rv->prefix.prefixlen));
	struct in6_addr orig_prefix = rv->prefix.prefix;
	apply_mask_ipv6(&rv->prefix);
	if (memcmp(&orig_prefix, &rv->prefix.prefix, sizeof(orig_prefix)))
		sbuf_push(log, indent + 2, "WARNING: Prefix had hostbits set.\n");
	format_item_ipv6_reach((struct isis_item*)rv, log, indent + 2);

	if (control & ISIS_IPV6_REACH_SUBTLV) {
		consume += 1;
		if (len < consume) {
			sbuf_push(log, indent, "Expected 1 byte of subtlv len, but "
			          "no more data persent.\n");
			goto out;
		}
		subtlv_len = stream_getc(s);

		if (!subtlv_len) {
			sbuf_push(log, indent + 2, "  WARNING: subtlv bit set, but "
				  "there are no subtlvs.\n");
		}
		consume += subtlv_len;
		if (len < consume) {
			sbuf_push(log, indent, "Expected %" PRIu8 " bytes of subtlvs,"
			          " but only %u bytes available.\n",
			          subtlv_len,
			          len - 6 - PSIZE(rv->prefix.prefixlen));
			goto out;
		}

		rv->subtlvs = isis_alloc_subtlvs();
		if (unpack_tlvs(ISIS_CONTEXT_SUBTLV_IPV6_REACH, subtlv_len, s,
		                log, rv->subtlvs, indent + 4)) {
			goto out;
		}
	}

	append_item(&tlvs->ipv6_reach, (struct isis_item*)rv);
	return 0;
out:
	if (rv)
		free_item_ipv6_reach((struct isis_item*)rv);
	return 1;
}

static int unpack_item(enum isis_tlv_context context,
		       uint8_t tlv_type, uint8_t len,
		       struct stream *s, struct sbuf *log,
		       void *dest, int indent)
{
	const struct tlv_ops *ops = tlv_table[context][tlv_type];

	if (ops && ops->unpack_item)
		return ops->unpack_item(len, s, log, dest, indent);

	assert(!"Unknown item tlv type!");
	sbuf_push(log, indent, "Unknown item tlv type!\n");
	return 1;
}

static int unpack_tlv_with_items(enum isis_tlv_context context,
				 uint8_t tlv_type,
				 uint8_t tlv_len,
				 struct stream *s,
				 struct sbuf *log,
				 void *dest,
				 int indent)
{
	size_t items_start;
	size_t tlv_pos;
	int rv;

	sbuf_push(log, indent, "Unpacking as item TLV...\n");

	items_start = stream_get_getp(s);
	tlv_pos = 0;
	while (tlv_pos < (size_t)tlv_len) {
		rv = unpack_item(context, tlv_type,
				 tlv_len - tlv_pos, s,
				 log, dest, indent + 2);
		if (rv)
			return rv;

		tlv_pos = stream_get_getp(s) - items_start;
	}

	return 0;
}

static int unpack_subtlv_ipv6_source_prefix(enum isis_tlv_context context,
                                            uint8_t tlv_type,
                                            uint8_t tlv_len,
                                            struct stream *s,
                                            struct sbuf *log,
                                            void *dest,
                                            int indent)
{
	struct isis_subtlvs *subtlvs = dest;
	struct prefix_ipv6 p = {
		.family = AF_INET6,
	};

	sbuf_push(log, indent, "Unpacking IPv6 Source Prefix Sub-TLV...\n");

	if (tlv_len < 1) {
		sbuf_push(log, indent, "Not enough data left. "
		          "(expected 1 or more bytes, got %" PRIu8 ")\n", tlv_len);
		return 1;
	}

	p.prefixlen = stream_getc(s);
	if (p.prefixlen > 128) {
		sbuf_push(log, indent, "Prefixlen %u is inplausible for IPv6\n",
		          p.prefixlen);
		return 1;
	}

	if (tlv_len != 1 + PSIZE(p.prefixlen)) {
		sbuf_push(log, indent, "TLV size differs from expected size for the prefixlen. "
		          "(expected %u but got %" PRIu8 ")\n", 1 + PSIZE(p.prefixlen), tlv_len);
		return 1;
	}

	stream_get(&p.prefix, s, PSIZE(p.prefixlen));

	if (subtlvs->source_prefix) {
		sbuf_push(log, indent, "WARNING: source prefix Sub-TLV present multiple times.\n");
		/* Ignore all but first occurrence of the source prefix Sub-TLV */
		return 0;
	}

	subtlvs->source_prefix = XCALLOC(MTYPE_ISIS_SUBTLV, sizeof(p));
	memcpy(subtlvs->source_prefix, &p, sizeof(p));
	return 0;
}

static int unpack_tlv_unknown(enum isis_tlv_context context,
			      uint8_t tlv_type, uint8_t tlv_len,
			      struct stream *s, struct sbuf *log,
			      int indent)
{
	stream_forward_getp(s, tlv_len);
	sbuf_push(log, indent, "Skipping unknown TLV %" PRIu8 " (%" PRIu8
		  " bytes)\n", tlv_type, tlv_len);
	return 0;
}

static int unpack_tlv(enum isis_tlv_context context,
		      size_t avail_len,
		      struct stream *stream,
		      struct sbuf *log,
		      void *dest,
		      int indent)
{
	uint8_t tlv_type, tlv_len;
	const struct tlv_ops *ops;

	sbuf_push(log, indent, "Unpacking TLV...\n");

	if (avail_len < 2) {
		sbuf_push(log, indent + 2, "Available data %zu too short to contain a TLV header.\n",
			  avail_len);
		return 1;
	}

	tlv_type = stream_getc(stream);
	tlv_len = stream_getc(stream);

	sbuf_push(log, indent + 2, "Found TLV of type %" PRIu8 " and len %" PRIu8 ".\n",
		  tlv_type, tlv_len);

	if (avail_len < ((size_t)tlv_len) + 2) {
		sbuf_push(log, indent + 2, "Available data %zu too short for claimed TLV len.\n",
			  avail_len - 2, tlv_len, tlv_len);
		return 1;
	}

	ops = tlv_table[context][tlv_type];
	if (ops && ops->unpack) {
		return ops->unpack(context, tlv_type, tlv_len,
				   stream, log, dest, indent + 2);
	}

	return unpack_tlv_unknown(context, tlv_type, tlv_len,
				  stream, log, indent + 2);
}

static int unpack_tlvs(enum isis_tlv_context context,
		       size_t avail_len, struct stream *stream,
		       struct sbuf *log, void *dest, int indent)
{
	int rv;
	size_t tlv_start, tlv_pos;

	tlv_start = stream_get_getp(stream);
	tlv_pos = 0;

	sbuf_push(log, indent, "Unpacking %zu bytes of %s...\n", avail_len,
		  (context == ISIS_CONTEXT_LSP) ? "TLVs" : "sub-TLVs");

	while (tlv_pos < avail_len) {
		rv = unpack_tlv(context, avail_len - tlv_pos, stream,
				log, dest, indent + 2);
		if (rv)
			return rv;

		tlv_pos = stream_get_getp(stream) - tlv_start;
	}

	return 0;
}

struct isis_tlvs *isis_alloc_tlvs(void)
{
	struct isis_tlvs *result;

	result = XCALLOC(MTYPE_ISIS_TLV2, sizeof(*result));

	init_item_list(&result->extended_reach);
	RB_INIT(&result->mt_reach);
	init_item_list(&result->extended_ip_reach);
	RB_INIT(&result->mt_ip_reach);
	init_item_list(&result->ipv6_reach);
	RB_INIT(&result->mt_ipv6_reach);

	return result;
}

static struct isis_subtlvs *isis_alloc_subtlvs(void)
{
	struct isis_subtlvs *result;

	result = XCALLOC(MTYPE_ISIS_SUBTLV, sizeof(*result));

	return result;
}

int isis_unpack_tlvs(size_t avail_len,
		     struct stream *stream,
		     struct isis_tlvs **dest,
		     const char **log)
{
	static struct sbuf logbuf;
	int indent = 0;
	int rv;
	struct isis_tlvs *result;

	if (!sbuf_buf(&logbuf))
		sbuf_init(&logbuf, NULL, 0);

	sbuf_reset(&logbuf);
	if (avail_len > STREAM_READABLE(stream)) {
		sbuf_push(&logbuf, indent,
			 "Stream doesn't contain sufficient data. "
			 "Claimed %zu, available %zu\n", avail_len,
			 STREAM_READABLE(stream));
		return 1;
	}

	result = isis_alloc_tlvs();
	rv = unpack_tlvs(ISIS_CONTEXT_LSP, avail_len, stream, &logbuf, result,
			 indent);

	*log = sbuf_buf(&logbuf);
	*dest = result;

	return rv;
}

static void format_subtlv_ipv6_source_prefix(struct prefix_ipv6 *p, struct sbuf *buf, int indent)
{
	if (!p)
		return;

	char prefixbuf[PREFIX2STR_BUFFER];
	sbuf_push(buf, indent, "IPv6 Source Prefix: %s\n",
	          prefix2str(p, prefixbuf, sizeof(prefixbuf)));
}

static void format_subtlvs(struct isis_subtlvs *subtlvs, struct sbuf *buf, int indent)
{
	format_subtlv_ipv6_source_prefix(subtlvs->source_prefix, buf, indent);
}


static void format_item_extended_reach(struct isis_item *i,
				       struct sbuf *buf, int indent)
{
	struct isis_extended_reach *r = (struct isis_extended_reach*)i;

	sbuf_push(buf, indent, "Extended Reachability:\n");
	sbuf_push(buf, indent, "  ID: %s\n", isis_format_id(r->id, 7));
	sbuf_push(buf, indent, "  Metric: %u\n", r->metric);
#if 0
	if (r->subtlvs) {
		sbuf_push(buf, indent, "  Subtlvs:\n");
		format_tlvs(r->subtlvs, buf, indent + 4);
	}
#endif
}

static void format_item_extended_ip_reach(struct isis_item *i,
					  struct sbuf *buf, int indent)
{
	struct isis_extended_ip_reach *r = (struct isis_extended_ip_reach*)i;
	char prefixbuf[64];

	sbuf_push(buf, indent, "Extended IP Reachability:\n");
	sbuf_push(buf, indent, "  Metric: %u\n", r->metric);
	sbuf_push(buf, indent, "  Down: %s\n", r->down ? "Yes" : "No");
	sbuf_push(buf, indent, "  Prefix: %s\n", prefix2str(&r->prefix, prefixbuf,
							    sizeof(prefixbuf)));
#if 0
	if (r->subtlvs) {
		sbuf_push(buf, indent, "  Subtlvs:\n");
		format_tlvs(r->subtlvs, buf, indent + 4);
	}
#endif
}

static void format_item_ipv6_reach(struct isis_item *i,
                                  struct sbuf *buf, int indent)
{
	struct isis_ipv6_reach *r = (struct isis_ipv6_reach*)i;
	char prefixbuf[PREFIX2STR_BUFFER];

	sbuf_push(buf, indent, "IPv6 Reachability:\n");
	sbuf_push(buf, indent, "  Metric: %u\n", r->metric);
	sbuf_push(buf, indent, "  Down: %s\n", r->down ? "Yes" : "No");
	sbuf_push(buf, indent, "  External: %s\n", r->external ? "Yes" : "No");
	sbuf_push(buf, indent, "  Prefix: %s\n", prefix2str(&r->prefix, prefixbuf,
	                                                    sizeof(prefixbuf)));

	if (r->subtlvs) {
		sbuf_push(buf, indent, "  Subtlvs:\n");
		format_subtlvs(r->subtlvs, buf, indent + 4);
	}
}

static void format_item(enum isis_tlv_context context,
			enum isis_tlv_type type, struct isis_item *i,
			struct sbuf *buf, int indent)
{
	const struct tlv_ops *ops = tlv_table[context][type];

	if (ops && ops->format_item) {
		ops->format_item(i, buf, indent);
		return;
	}

	assert(!"Unknown item tlv type!");
}

static void format_items(enum isis_tlv_context context,
			 enum isis_tlv_type type, struct isis_item_list *items,
			 struct sbuf *buf, int indent)
{
	struct isis_item *i;

	for (i = items->head; i; i = i->next)
		format_item(context, type, i, buf, indent);
}

static void format_tlvs(struct isis_tlvs *tlvs, struct sbuf *buf, int indent)
{
	format_items(ISIS_CONTEXT_LSP, ISIS_TLV_EXTENDED_REACH,
		     &tlvs->extended_reach,
		     buf, indent);
	format_items(ISIS_CONTEXT_LSP, ISIS_TLV_EXTENDED_IP_REACH,
		     &tlvs->extended_ip_reach,
		     buf, indent);
	format_items(ISIS_CONTEXT_LSP, ISIS_TLV_IPV6_REACH,
		     &tlvs->ipv6_reach,
		     buf, indent);
}

const char *isis_format_tlvs(struct isis_tlvs *tlvs)
{
	static struct sbuf buf;

	if (!sbuf_buf(&buf))
		sbuf_init(&buf, NULL, 0);

	sbuf_reset(&buf);
	format_tlvs(tlvs, &buf, 0);
	return sbuf_buf(&buf);
}

static struct prefix_ipv6 *copy_subtlv_ipv6_source_prefix(struct prefix_ipv6 *p)
{
	if (!p)
		return NULL;

	struct prefix_ipv6 *rv = XCALLOC(MTYPE_ISIS_SUBTLV, sizeof(*rv));
	rv->family = p->family;
	rv->prefixlen = p->prefixlen;
	memcpy(&rv->prefix, &p->prefix, sizeof(rv->prefix));
	return rv;
}

static struct isis_subtlvs *copy_subtlvs(struct isis_subtlvs *subtlvs)
{
	if (!subtlvs)
		return NULL;

	struct isis_subtlvs *rv = XCALLOC(MTYPE_ISIS_SUBTLV, sizeof(*rv));

	rv->source_prefix = copy_subtlv_ipv6_source_prefix(subtlvs->source_prefix);
	return rv;
}

static struct isis_item *copy_item_extended_reach(struct isis_item *i)
{
	struct isis_extended_reach *r = (struct isis_extended_reach*)i;
	struct isis_extended_reach *rv = XCALLOC(MTYPE_ISIS_TLV2, sizeof(*rv));

	memcpy(rv->id, r->id, 7);
	rv->metric = r->metric;
#if 0
	rv->subtlvs = isis_copy_tlvs(r->subtlvs);
#endif

	return (struct isis_item*)rv;
}

static struct isis_item *copy_item_extended_ip_reach(struct isis_item *i)
{
	struct isis_extended_ip_reach *r = (struct isis_extended_ip_reach*)i;
	struct isis_extended_ip_reach *rv = XCALLOC(MTYPE_ISIS_TLV2,
						    sizeof(*rv));

	rv->metric = r->metric;
	rv->down = r->down;
	rv->prefix = r->prefix;
#if 0
	rv->subtlvs = isis_copy_tlvs(r->subtlvs);
#endif

	return (struct isis_item*)rv;
}

static struct isis_item *copy_item_ipv6_reach(struct isis_item *i)
{
	struct isis_ipv6_reach *r = (struct isis_ipv6_reach*)i;
	struct isis_ipv6_reach *rv = XCALLOC(MTYPE_ISIS_TLV2,
	                                     sizeof(*rv));
	rv->metric = r->metric;
	rv->down = r->down;
	rv->external = r->external;
	rv->prefix = r->prefix;
	rv->subtlvs = copy_subtlvs(r->subtlvs);

	return (struct isis_item*)rv;
}

static struct isis_item *copy_item(enum isis_tlv_context context,
				   enum isis_tlv_type type,
				   struct isis_item *item)
{
	const struct tlv_ops *ops = tlv_table[context][type];

	if (ops && ops->copy_item)
		return ops->copy_item(item);

	assert(!"Unknown item tlv type!");
	return NULL;
}

static void copy_items(enum isis_tlv_context context, enum isis_tlv_type type,
                       struct isis_item_list *src, struct isis_item_list *dest)
{
	struct isis_item *item;

	init_item_list(dest);

	for (item = src->head; item; item = item->next) {
		append_item(dest, copy_item(context, type, item));
	}
}

struct isis_tlvs *isis_copy_tlvs(struct isis_tlvs *tlvs)
{
	struct isis_tlvs *rv = XCALLOC(MTYPE_ISIS_TLV2, sizeof(*rv));

	copy_items(ISIS_CONTEXT_LSP, ISIS_TLV_EXTENDED_REACH,
	           &tlvs->extended_reach, &rv->extended_reach);
	copy_items(ISIS_CONTEXT_LSP, ISIS_TLV_EXTENDED_IP_REACH,
	           &tlvs->extended_ip_reach, &rv->extended_ip_reach);
	copy_items(ISIS_CONTEXT_LSP, ISIS_TLV_IPV6_REACH,
	           &tlvs->ipv6_reach, &rv->ipv6_reach);

	return rv;
}

#define TLV_OPS(_name_,_desc_) \
	static const struct tlv_ops tlv_##_name_##_ops = { \
		.name = _desc_, \
		.unpack = unpack_tlv_##_name_, \
	}

#define ITEM_TLV_OPS(_name_,_desc_) \
	static const struct tlv_ops tlv_##_name_##_ops = { \
		.name = _desc_, \
		.unpack = unpack_tlv_with_items, \
		\
		.pack_item = pack_item_##_name_, \
		.free_item = free_item_##_name_, \
		.unpack_item = unpack_item_##_name_, \
		.format_item = format_item_##_name_, \
		.copy_item = copy_item_##_name_ \
	}

#define SUBTLV_OPS(_name_,_desc_) \
	static const struct tlv_ops subtlv_##_name_##_ops = { \
		.name = _desc_, \
		.unpack = unpack_subtlv_##_name_, \
	}

ITEM_TLV_OPS(extended_reach, "TLV 22 Extended Reachability");
ITEM_TLV_OPS(extended_ip_reach, "TLV 135 Extended IP Reachability");
ITEM_TLV_OPS(ipv6_reach, "TLV 236 IPv6 Reachability");

SUBTLV_OPS(ipv6_source_prefix, "Sub-TLV 22 IPv6 Source Prefix");

static const struct tlv_ops *tlv_table[ISIS_CONTEXT_MAX][ISIS_TLV_MAX] = {
	[ISIS_CONTEXT_LSP] = {
		[ISIS_TLV_EXTENDED_REACH] = &tlv_extended_reach_ops,
		[ISIS_TLV_EXTENDED_IP_REACH] = &tlv_extended_ip_reach_ops,
		[ISIS_TLV_IPV6_REACH] = &tlv_ipv6_reach_ops,
	},
	[ISIS_CONTEXT_SUBTLV_NE_REACH] = {
	},
	[ISIS_CONTEXT_SUBTLV_IP_REACH] = {
	},
	[ISIS_CONTEXT_SUBTLV_IPV6_REACH] = {
		[ISIS_SUBTLV_IPV6_SOURCE_PREFIX] = &subtlv_ipv6_source_prefix_ops,
	}
};
