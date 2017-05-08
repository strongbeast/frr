#include <zebra.h>

#include "memory.h"
#include "stream.h"

#include "isis_protocol2.h"
#include "isis_tlvs2.h"

struct isis_pdu {
	struct stream *s;

	uint8_t pdu_type;

	uint16_t lifetime;
	uint32_t seq;
	uint8_t lsp_id[8];

	ssize_t pdu_len_at;
	ssize_t lifetime_at;
	ssize_t checksum_at;
	ssize_t auth_data_at;

	struct isis_tlvs *tlvs;
};

enum isis_pdu_type {
	ISIS_PDU_L1_IIH = 15,
	ISIS_PDU_L2_IIH = 16,
	ISIS_PDU_PTP_IIH = 17,
	ISIS_PDU_L1_LSP = 18,
	ISIS_PDU_L2_LSP = 20,
	ISIS_PDU_L1_CSNP = 24,
	ISIS_PDU_L2_CSNP = 25,
	ISIS_PDU_L1_PSNP = 26,
	ISIS_PDU_L2_PSNP = 27,
	ISIS_PDU_MAX
};

typedef int(*pack_pdu_func)(struct isis_pdu *pdu);

struct pdu_ops {
	const char *name;
	uint8_t hdr_len;

	pack_pdu_func pack;
};

static const struct pdu_ops *pdu_table[ISIS_PDU_MAX];

struct isis_pdu *isis_alloc_pdu(uint8_t pdu_type, size_t size)
{
	struct isis_pdu *rv;

	rv = XCALLOC(MTYPE_ISIS_PDU, sizeof(*rv));
	rv->s = stream_new(size);
	rv->pdu_type = pdu_type;

	return rv;
}

struct isis_pdu *isis_get_pdu_tlvs(struct isis_pdu *pdu)
{
	return pdu->tlvs;
}

void isis_set_pdu_tlvs(struct isis_pdu *pdu, struct isis_tlvs *tlvs)
{
	pdu->tlvs = tlvs;
}

static void isis_mark_pdu_len(struct isis_pdu *pdu)
{
	pdu->pdu_len_at = stream_get_endp(pdu->s);
}

static void isis_mark_pdu_lifetime(struct isis_pdu *pdu)
{
	pdu->lifetime_at = stream_get_endp(pdu->s);
}

static void isis_mark_pdu_checksum(struct isis_pdu *pdu)
{
	pdu->checksum_at = stream_get_endp(pdu->s);
}

static void isis_mark_pdu_auth_data(struct isis_pdu *pdu)
{
	pdu->auth_data_at = stream_get_endp(pdu->s);
}

static void isis_calculate_pdu_auth(struct isis_pdu *pdu, uint8_t *dest)
{
	uint32_t lifetime = -1;
	uint32_t checksum = -1;

	if (pdu->lifetime_at >= 0) {
		lifetime = stream_getw_from(pdu->s, pdu->lifetime_at);
		stream_putw_at(pdu->s, pdu->lifetime_at, 0);
	}

	if (pdu->checksum_at >= 0) {
		checksum = stream_getw_from(pdu->s, pdu->checksum_at);
		stream_putw_at(pdu->s, pdu->checksum_at, 0);
	}

#ifdef TODO_CALCULATE_AUTH
	isis_calculate_pdu_md5(pdu, dest);
#endif

	if (checksum != (uint32_t)-1)
		stream_putw_at(pdu->s, pdu->checksum_at, checksum);

	if (lifetime != (uint32_t)-1)
		stream_putw_at(pdu->s, pdu->lifetime_at, lifetime);
}

static void isis_add_pdu_auth(struct isis_pdu *pdu)
{
	uint8_t auth_data[16]; /* TODO: Magic */

	isis_calculate_pdu_auth(pdu, auth_data);
	stream_put_at(pdu->s, pdu->auth_data_at, auth_data, sizeof(auth_data));
}

static int isis_pack_lsp(struct isis_pdu *pdu, struct isis_auth_setting *auth)
{
	int rv;

	if (STREAM_WRITEABLE(s) < 19)
		return 1;

	isis_mark_pdu_len(pdu);
	stream_putw(pdu->s, 0x00);          /* Fill pdu len with zeroes */
	isis_mark_pdu_lifetime();
	stream_putw(pdu->s, pdu->lifetime); /* Lifetime */
	stream_put(pdu->s, pdu->lsp_id, sizeof(pdu->lsp_id));
	stream_putl(pdu->s, pdu->seq);     /* Sequence number */
	isis_mark_pdu_checksum(pdu);
	stream_putw(pdu->s, 0x00); /* Fill checksum with zeros */
	stream_putc(pdu->s, 0x01); /* Type-1 IS, No Overload */

	isis_put_auth_tlv(pdu, pdu->s, auth)

	rv = isis_pack_tlvs(pdu->tlvs, pdu->s);
	if (rv)
		return rv;

	return 0;
}

static int isis_pack_pdu(struct isis_pdu *pdu)
{
	int rv;
	struct pdu_ops *ops;

	if (pdu->pdu_type >= ISIS_PDU_MAX)
		return 1;

	ops = pdu_table[pdu->pdu_type];
	if (!ops)
		return 1;

	stream_reset(pdu->s);
	pdu->pdu_len_at = pdu->lifetime_at = -1;
	pdu->checksum_at = pdu->auth_data_at = -1;

	if (STREAM_WRITEABLE(pdu->s) < 8)
		return 1;

	stream_putc(pdu->s, 0x83); /* ISIS protocol discriminator */
	stream_putc(pdu->s, ops->hdr_len);
	stream_putc(pdu->s, 1); /* Version/Protocol ID Extension */
	stream_putc(pdu->s, 0); /* Use 6 octet ID field len */
	stream_putc(pdu->s, pdu->pdu_type);
	stream_putc(pdu->s, 1); /* PDU Version */
	stream_putc(pdu->s, 0); /* Reserved */
	stream_putc(pdu->s, 0); /* Maximum Area Addresses */

	rv = ops->pack(pdu);
	if (rv)
		return rv;

	if (pdu->pdu_len_at >= 0) {
		stream_putw_at(pdu->s, pdu->pdu_len_at,
		               stream_get_endp(pdu->s));
	}

	if (pdu->auth_data_at >= 0)
		isis_add_pdu_auth(pdu);

	if (pdu->checksum_at >= 0)
		isis_add_pdu_checksum(pdu);

	return 0;
}

#define ISIS_PDU_OPS(_name_,_desc_,_hdr_len_) \
	static const struct pdu_ops pdu_##_name_##_ops = { \
		.name = (_desc_), \
		.hdr_len = (_hdr_len_), \
		.pack = pack_pdu_##_name_ \
	}

ISIS_PDU_OPS(l1_lsp, "Level 1 LSP", 27);
ISIS_PDU_OPS(l2_lsp, "Level 2 LSP", 27);

static const struct pdu_ops *pdu_table[ISIS_PDU_MAX] = {
	[ISIS_PDU_L1_LSP] = &pdu_l1_lsp_ops,
	[ISIS_PDU_L2_LSP] = &pdu_l2_lsp_ops,
};
