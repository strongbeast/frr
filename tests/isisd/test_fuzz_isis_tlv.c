#include "test_fuzz_isis_tlv_tests.h"

#include <zebra.h>

#include "memory.h"
#include "stream.h"

#include "isisd/isis_tlvs2.h"

#define TEST_STREAM_SIZE 1500

static int test(FILE *input, FILE *output)
{
	struct stream *s = stream_new(TEST_STREAM_SIZE);
	char buf[TEST_STREAM_SIZE];
	size_t bytes_read = 0;

	while (STREAM_WRITEABLE(s) && !feof(input)) {
		bytes_read = fread(buf, 1, STREAM_WRITEABLE(s), input);
		if (bytes_read == 0)
			 break;
		stream_put(s, buf, bytes_read);
	}

	if (bytes_read && !feof(input)) {
		fprintf(output, "Too much input data.\n");
		stream_free(s);
		return 1;
	}

	stream_set_getp(s, 0);
	struct isis_tlvs *tlvs;
	const char *log;
	int rv = isis_unpack_tlvs(STREAM_READABLE(s), s, &tlvs, &log);

	if (rv) {
		fprintf(output, "Could not unpack TLVs:\n%s\n", log);
		isis_free_tlvs(tlvs);
		stream_free(s);
		return 2;
	}

	fprintf(output, "Unpack log:\n%s", log);
	const char *s_tlvs = isis_format_tlvs(tlvs);
	fprintf(output, "Unpacked TLVs:\n%s", s_tlvs);

	struct isis_tlvs *tlv_copy = isis_copy_tlvs(tlvs);
	isis_free_tlvs(tlvs);

	struct stream *s2 = stream_new(TEST_STREAM_SIZE);

	if (isis_pack_tlvs(tlv_copy, s2)) {
		fprintf(output, "Could not pack TLVs.\n");
		stream_free(s);
		stream_free(s2);
		isis_free_tlvs(tlv_copy);
		return 3;
	}

	stream_set_getp(s2, 0);
	rv = isis_unpack_tlvs(STREAM_READABLE(s2), s2, &tlvs, &log);
	if (rv) {
		fprintf(output, "Could not unpack own TLVs:\n%s\n", log);
		isis_free_tlvs(tlvs);
		isis_free_tlvs(tlv_copy);
		stream_free(s);
		stream_free(s2);
		return 4;
	}

	char *orig_tlvs = XSTRDUP(MTYPE_TMP, s_tlvs);
	s_tlvs = isis_format_tlvs(tlvs);

	if (strcmp(orig_tlvs, s_tlvs)) {
		fprintf(output, "Deserialized and Serialized LSP seem to differ.\n");
		XFREE(MTYPE_TMP, orig_tlvs);
		isis_free_tlvs(tlvs);
		isis_free_tlvs(tlv_copy);
		stream_free(s);
		stream_free(s2);
		return 5;
	}

	XFREE(MTYPE_TMP, orig_tlvs);
	isis_free_tlvs(tlvs);
	isis_free_tlvs(tlv_copy);
	stream_free(s);
	stream_free(s2);

	return 0;
}
