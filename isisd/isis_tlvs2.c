#include <zebra.h>

#include "memory.h"
#include "stream.h"
#include "sbuf.h"

#include "isis_tlvs2.h"
#include "isis_common2.h"

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

/* This is a forward definition. The table is actually filled
 * in at the bottom. */
static const struct tlv_ops *tlv_table[ISIS_CONTEXT_MAX][ISIS_TLV_MAX];

/* End of _ops forward definition. */

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

	if (STREAM_WRITEABLE(s) < PSIZE(r->prefix.prefixlen))
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
		      struct isis_item *items, struct stream *s)
{
	size_t len_pos, last_len, len;
	struct isis_item *item = NULL;
	int rv;

	if (!items)
		return 0;

top:
	if (STREAM_WRITEABLE(s) < 2)
		return 1;
	stream_putc(s, type);
	len_pos = stream_get_endp(s);
	stream_putc(s, 0); /* Put 0 as length for now */

	last_len = len = 0;
	for (item = item ? item : items; item; item = item->next) {
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
			(struct isis_item*)tlvs->extended_reach, stream);
	if (rv)
		return rv;

	rv = pack_items(ISIS_CONTEXT_LSP, ISIS_TLV_EXTENDED_IP_REACH,
			(struct isis_item*)tlvs->extended_ip_reach, stream);
	if (rv)
		return rv;

	return 0;
}

static void free_item_extended_reach(struct isis_item *i)
{
	struct isis_extended_reach *item = (struct isis_extended_reach*)i;
	XFREE(MTYPE_ISIS_TLV, item);
}

static void free_item_extended_ip_reach(struct isis_item *i)
{
	struct isis_extended_ip_reach *item = (struct isis_extended_ip_reach*)i;
	XFREE(MTYPE_ISIS_TLV, item);
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
		       struct isis_item *items)
{
	struct isis_item *item, *next_item;

	for (item = items; item; item = next_item) {
		next_item = item->next;
		free_item(context, type, item);
	}
}

void isis_free_tlvs(struct isis_tlvs *tlvs)
{
	if (!tlvs)
		return;

	free_items(ISIS_CONTEXT_LSP, ISIS_TLV_EXTENDED_REACH,
		   (struct isis_item*)tlvs->extended_reach);
	free_items(ISIS_CONTEXT_LSP, ISIS_TLV_EXTENDED_IP_REACH,
		   (struct isis_item*)tlvs->extended_ip_reach);

	XFREE(MTYPE_ISIS_TLV, tlvs);
}

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

	rv = XCALLOC(MTYPE_ISIS_TLV, sizeof(*rv));
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

	*tlvs->extended_reach_next = rv;
	tlvs->extended_reach_next = &rv->next;

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

	rv = XCALLOC(MTYPE_ISIS_TLV, sizeof(*rv));

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

	*tlvs->extended_ip_reach_next = rv;
	tlvs->extended_ip_reach_next = &rv->next;
	return 0;
out:
	if (rv)
		free_item_extended_ip_reach((struct isis_item*)rv);
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

	result = XCALLOC(MTYPE_ISIS_TLV, sizeof(*result));

	result->extended_reach_next = &result->extended_reach;
	result->extended_ip_reach_next = &result->extended_ip_reach;
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
			 enum isis_tlv_type type, struct isis_item *items,
			 struct sbuf *buf, int indent)
{
	struct isis_item *i;

	for (i = items; i; i = i->next)
		format_item(context, type, i, buf, indent);
}

static void format_tlvs(struct isis_tlvs *tlvs, struct sbuf *buf, int indent)
{
	format_items(ISIS_CONTEXT_LSP, ISIS_TLV_EXTENDED_REACH,
		     (struct isis_item*)tlvs->extended_reach,
		     buf, indent);
	format_items(ISIS_CONTEXT_LSP, ISIS_TLV_EXTENDED_IP_REACH,
		     (struct isis_item*)tlvs->extended_ip_reach,
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

static struct isis_item *copy_item_extended_reach(struct isis_item *i)
{
	struct isis_extended_reach *r = (struct isis_extended_reach*)i;
	struct isis_extended_reach *rv = XCALLOC(MTYPE_ISIS_TLV, sizeof(*rv));

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
	struct isis_extended_ip_reach *rv = XCALLOC(MTYPE_ISIS_TLV,
						    sizeof(*rv));

	rv->metric = r->metric;
	rv->down = r->down;
	rv->prefix = r->prefix;
#if 0
	rv->subtlvs = isis_copy_tlvs(r->subtlvs);
#endif

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

static struct isis_item *copy_items(enum isis_tlv_context context,
				    enum isis_tlv_type type,
				    struct isis_item *items)
{
	struct isis_item *item;
	struct isis_item **target;
	struct isis_item *rv = NULL;

	target = &rv;

	for (item = items; item; item = item->next) {
		*target = copy_item(context, type, item);
		target = &(*target)->next;
	}

	return (struct isis_item*)rv;
}

struct isis_tlvs *isis_copy_tlvs(struct isis_tlvs *tlvs)
{
	struct isis_tlvs *rv = XCALLOC(MTYPE_ISIS_TLV, sizeof(*rv));

	rv->extended_reach = (struct isis_extended_reach*)copy_items(
					ISIS_CONTEXT_LSP, ISIS_TLV_EXTENDED_REACH,
					(struct isis_item*)tlvs->extended_reach);
	rv->extended_ip_reach = (struct isis_extended_ip_reach*)copy_items(
					ISIS_CONTEXT_LSP, ISIS_TLV_EXTENDED_IP_REACH,
					(struct isis_item*)tlvs->extended_ip_reach);

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

ITEM_TLV_OPS(extended_reach, "TLV 22 Extended Reachability");
ITEM_TLV_OPS(extended_ip_reach, "TLV 135 Extended IP Reachability");

static const struct tlv_ops *tlv_table[ISIS_CONTEXT_MAX][ISIS_TLV_MAX] = {
	[ISIS_CONTEXT_LSP] = {
		[ISIS_TLV_EXTENDED_REACH] = &tlv_extended_reach_ops,
		[ISIS_TLV_EXTENDED_IP_REACH] = &tlv_extended_ip_reach_ops,
	},
	[ISIS_CONTEXT_SUBTLV_NE_REACH] = {
	},
	[ISIS_CONTEXT_SUBTLV_IP_REACH] = {
	},
};
