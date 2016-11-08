#include <zebra.h>

#undef assert

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <pthread.h>

#include "atomlist.h"
#include "seqlock.h"

static struct seqlock sqlo;

ATOMLIST_MAKEITEM(alist)
struct item {
	uint64_t val1;
	struct alist_item chain;
	uint64_t val2;
};
ATOMLIST_MAKEFUNCS(alist, struct item, chain)

#define NITEM 10000
struct item itm[NITEM];

#define NTHREADS 4
static pthread_t thr[NTHREADS];

static struct alist_head ahead;

static void dump(const char *lbl)
{
	struct item *item, *safe;
	size_t ctr = 0;
	printf("dump:\n");
	atomlist_for_each_safe(alist, item, safe, &ahead) {
		printf("%s %3zu %p %3lu %3lu\n", lbl, ctr++,
				(void *)item, item->val1, item->val2);
	}
}

static void *thr1func(void *arg)
{
	pthread_t *p = arg;
	int offset = p - &thr[0];
	size_t i;

	printf("thread #%d\n", offset);

	seqlock_ticket_wait(&sqlo, 2);

	for (i = offset; i < NITEM; i += NTHREADS) {
		alist_add_head(&ahead, &itm[i]);
	}

	seqlock_ticket_wait(&sqlo, 4);

#if 0
	for (i = offset; i < NITEM; i += NTHREADS) {
		alist_del(&ahead, &itm[i]);
	}
#endif
	for (i = 0; i < NITEM / NTHREADS; i++) {
		struct item *dr = alist_pop(&ahead);
		if (!dr)
			printf("delete failed\n");
	}

	return NULL;
}

int main()
{
	size_t i;

	seqlock_init(&sqlo);

	memset(itm, 0, sizeof(itm));
	for (i = 0; i < NITEM; i++)
		itm[i].val1 = itm[i].val2 = i;
	memset(&ahead, 0, sizeof(ahead));

	assert(alist_first(&ahead) == NULL);
	dump("");
	alist_add_head(&ahead, &itm[0]);
	dump("");
	alist_add_head(&ahead, &itm[1]);
	dump("");
	alist_add_tail(&ahead, &itm[2]);
	dump("");
	alist_add_tail(&ahead, &itm[3]);
	dump("");
	alist_del(&ahead, &itm[1]);
	dump("");
	printf("POP: %p\n", alist_pop(&ahead));
	dump("");
	printf("POP: %p\n", alist_pop(&ahead));
	dump("");

	memset(itm, 0, sizeof(itm));
	for (i = 0; i < NITEM; i++)
		itm[i].val1 = itm[i].val2 = i;
	memset(&ahead, 0, sizeof(ahead));

	for (i = 0; i < NTHREADS; i++)
		pthread_create(&thr[i], NULL, thr1func, &thr[i]);

	usleep(10000);
	seqlock_work_set(&sqlo, 3);

	usleep(10000);
	seqlock_work_set(&sqlo, 5);

	for (i = 0; i < NTHREADS; i++)
		pthread_join(thr[i], NULL);

	dump("B");
	return 0;
}

