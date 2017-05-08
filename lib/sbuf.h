#ifndef SBUF_H
#define SBUF_H

struct sbuf {
	bool fixed;
	char *buf;
	size_t size;
	size_t pos;
	int indent;
};

void sbuf_init(struct sbuf *dest, char *buf, size_t size);
void sbuf_reset(struct sbuf *buf);
const char *sbuf_buf(struct sbuf *buf);
void sbuf_push(struct sbuf *buf, int indent, const char *format, ...);

#endif
