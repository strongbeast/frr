#include <zebra.h>

#include "memory.h"
#include "stream.h"

#include "isis_protocol2.h"
#include "isis_tlvs2.h"



struct isis_lsp *isis_alloc_lsp(uint8_t *id)
{
	struct isis_lsp *rv;

	rv = XCALLOC(MTYPE_ISIS_LSP, sizeof(*rv));
	memcpy(rv->id, id, sizeof(rv->id));
	rv->seq = 1;
	rv->tlvs = isis_alloc_tlvs();

	return rv;
}

int isis_pack_lsp(struct isis_lsp *lsp)
{
	struct stream *s = stream_new(1500); /* TODO: MAGIC */
	int rv;

//	rv = isis_put_pdu_header(ISIS_PDU_LSP, TODO, s);
//	if (rv)
//		goto out;

	if (STREAM_WRITEABLE(s) < 19) {
		rv = 1;
		goto out;
	}

	return 0;
out:
	stream_free(s);
	return rv;
}
