#ifndef ISIS_PROTOCOL2_H
#define ISIS_PROTOCOL2_H

#include "prefix.h"

struct isis_tlvs;

struct isis_lsp {
	uint8_t id[8];
	uint32_t seq;

	unsigned int own:1;

	struct isis_tlvs *tlvs;
};

struct isis_lsp *isis_alloc_lsp(uint8_t *id);

void pack_lsp(struct isis_lsp *lsp, struct stream *stream);
/* struct isis_lsp *unpack_lsp(struct stream *stream); */

#endif
