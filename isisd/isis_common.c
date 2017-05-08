#include <zebra.h>

#include "isis_common.h"

#define FORMAT_ID_SIZE sizeof("0000.0000.0000.00-00")
const char *isis_format_id(uint8_t *id, size_t len)
{
	#define FORMAT_BUF_COUNT 4
	static char buf_ring[FORMAT_BUF_COUNT][FORMAT_ID_SIZE];
	static size_t cur_buf = 0;

	char *rv;

	cur_buf++;
	if (cur_buf >= FORMAT_BUF_COUNT)
		cur_buf = 0;

	rv = buf_ring[cur_buf];

	if (len < 6) {
		snprintf(rv, FORMAT_ID_SIZE, "Short ID");
		return rv;
	}

	snprintf(rv, FORMAT_ID_SIZE, "%02x%02x.%02x%02x.%02x%02x",
		 id[0], id[1], id[2], id[3], id[4], id[5]);

	if (len > 6)
		snprintf(rv + 14, FORMAT_ID_SIZE - 14, ".%02x", id[6]);
	if (len > 7)
		snprintf(rv + 17, FORMAT_ID_SIZE - 17, "-%02x", id[7]);

	return rv;
}
