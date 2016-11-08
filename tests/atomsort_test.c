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

ATOMSORT_MAKEITEM(asort)
struct item {
	uint64_t val1;
	struct asort_item chain;
	uint64_t val2;
};

static int icmp(const struct item *a, const struct item *b);
ATOMSORT_MAKEFUNCS(asort, struct item, chain, icmp)

static int icmp(const struct item *a, const struct item *b)
{
	if (a->val1 > b->val1)
		return 1;
	if (a->val1 < b->val1)
		return -1;
	return 0;
}

#define NITEM 10000
struct item itm[NITEM];

#define NTHREADS 4
static pthread_t thr[NTHREADS];

static struct asort_head ahead;

static void dump(const char *lbl)
{
	struct item *item, *safe;
	size_t ctr = 0;
	uint64_t prev = ~0ULL;

	printf("dump:\n");
	atomsort_for_each_safe(asort, item, safe, &ahead) {
		printf("%s %3zu %p %3lu %3lu\n", lbl, ctr++,
				(void *)item, item->val1, item->val2);
		if (prev != ~0ULL && item->val1 < prev) {
			printf("^^^^^\n");
			exit(1);
		}
		prev = item->val1;
	}
}

static void *thr1func(void *arg)
{
	pthread_t *p = arg;
	int offset = p - &thr[0];
	size_t i, j;

	printf("thread #%d\n", offset);

	seqlock_ticket_wait(&sqlo, 2);

	for (i = 0; i < NITEM / NTHREADS; i++) {
		j = (offset * 739 + (i * 3677)) % (NITEM / NTHREADS);
		j = j * NTHREADS + offset;

		assert(!itm[j].chain.ai.next);

		printf("[%d] %zd\n", offset, j);
		asort_add(&ahead, &itm[j]);
	}

	return NULL;
}

int main()
{
	size_t i;

	seqlock_init(&sqlo);

	memset(itm, 0, sizeof(itm));
	for (i = 0; i < NITEM; i++) {
		itm[i].val1 = itm[i].val2 = i;
		itm[i].chain.ai.next = ATOMPTR_NULL;
	}
	memset(&ahead, 0, sizeof(ahead));

	assert(asort_first(&ahead) == NULL);

	for (i = 0; i < NTHREADS; i++)
		pthread_create(&thr[i], NULL, thr1func, &thr[i]);

	usleep(10000);
	seqlock_work_set(&sqlo, 3);

	for (i = 0; i < NTHREADS; i++)
		pthread_join(thr[i], NULL);

	dump("");
	return 0;
}

