#include <zebra.h>

#include "sbuf.h"
#include "memory.h"

void sbuf_init(struct sbuf *dest, char *buf, size_t size)
{
	dest->fixed = (size > 0);
	if (dest->fixed) {
		dest->buf = buf;
		dest->size = size;
	} else {
		dest->buf = XMALLOC(MTYPE_TMP, 4096);
		dest->size = 4096;
	}

	dest->pos = 0;
	dest->buf[0] = '\0';
}

void sbuf_reset(struct sbuf *dest)
{
	dest->pos = 0;
	dest->buf[0] = '\0';
}

const char *sbuf_buf(struct sbuf *buf)
{
	return buf->buf;
}

void sbuf_push(struct sbuf *buf, int indent, const char *format, ...)
{
	va_list args;
	int written;

	if (!buf->fixed) {
		char dummy;
		int written1, written2;
		size_t new_size;

		written1 = snprintf(&dummy, 0, "%*s", indent, "");
		va_start(args, format);
		written2 = vsnprintf(&dummy, 0, format, args);
		va_end(args);

		new_size = buf->size;
		if (written1 >= 0 && written2 >= 0) {
			while (buf->pos + written1 + written2 >= new_size)
				new_size *= 2;
			if (new_size > buf->size) {
				buf->buf = XREALLOC(MTYPE_TMP, buf->buf, new_size);
				buf->size = new_size;
			}
		}
	}

	written = snprintf(buf->buf + buf->pos,
			   buf->size - buf->pos,
			   "%*s", indent, "");

	if (written >= 0)
		buf->pos += written;
	if (buf->pos > buf->size)
		buf->pos = buf->size;

	va_start(args, format);
	written = vsnprintf(buf->buf + buf->pos,
			    buf->size - buf->pos,
			    format, args);
	va_end(args);

	if (written >= 0)
		buf->pos += written;
	if (buf->pos > buf->size)
		buf->pos = buf->size;

	if (buf->pos == buf->size)
		assert(!"Buffer filled up!");
}
