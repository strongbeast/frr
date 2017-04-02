#include <string.h>
#include <unistd.h>

#include "frrcu.h"
#include "seqlock.h"
#include "atomlist.h"

DEFINE_MTYPE_STATIC(LIB, RCU_THREAD,    "RCU thread")
DEFINE_MTYPE_STATIC(LIB, RCU_FREE_ITEM, "RCU free queue item")

ATOMLIST_MAKEFUNCS(rcu_heads, struct rcu_head, head)

ATOMLIST_MAKEITEM(rcu_threads)
struct rcu_thread {
	struct rcu_threads_item head;

	struct seqlock rcu;
	bool bump_on_release;

	void *thread_arg;
	void *(*thread_fn)(void *);
};
ATOMLIST_MAKEFUNCS(rcu_threads, struct rcu_thread, head)

static struct seqlock rcu_counter;
static _Atomic unsigned rcu_num_threads = 1;
static struct rcu_threads_head rcu_threads;
static struct rcu_heads_head rcu_heads;
static pthread_t rcu_thread;

static _Thread_local struct rcu_thread *rcu_this = NULL;

static void rcu_start(void);
static inline bool rcu_active(void)
{
	return atomic_load_explicit(&rcu_num_threads, memory_order_relaxed) > 1;
}

/*
 * preinitialization for main thread
 */
static struct rcu_thread rcu_this_main;
static void rcu_preinit(void) __attribute__((constructor));
static void rcu_preinit(void)
{
	struct rcu_thread *rt;

	seqlock_init(&rcu_counter);
	seqlock_acquire_val(&rcu_counter, 1);

	rcu_this = rt = &rcu_this_main;
	seqlock_init(&rt->rcu);
	seqlock_acquire_val(&rt->rcu, 1);
	rcu_threads_add_tail(&rcu_threads, rt);
}

void rcu_init(void)
{
	/* nothing currently */
}

/*
 * thread management (for the non-main thread)
 */
static struct rcu_thread *rcu_thread_setup(void)
{
	unsigned prevc;
	struct rcu_thread *rt = XCALLOC(MTYPE_RCU_THREAD, sizeof(*rt));
	seqlock_init(&rt->rcu);

	rcu_threads_add_tail(&rcu_threads, rt);
	prevc = atomic_fetch_add_explicit(&rcu_num_threads, 1, memory_order_relaxed);
	if (prevc == 1)
		rcu_start();
	return rt;
}

static void rcu_thread_end(void *arg)
{
	rcu_threads_del(&rcu_threads, rcu_this);
	rcu_free(MTYPE_RCU_THREAD, rcu_this);
	if (0)
		/* TODO: let the RCU cleaner run & exit */
		atomic_fetch_sub_explicit(&rcu_num_threads, 1, memory_order_relaxed);
}

static void *rcu_thread_start(void *arg)
{
	struct rcu_thread *rt = arg;
	void *rv;

	rcu_this = rt;
	pthread_cleanup_push(rcu_thread_end, NULL);
	rv = rt->thread_fn(rt->thread_arg);
	pthread_cleanup_pop(1);
	return rv;
}

int rcu_thread_create(pthread_t *thread, const pthread_attr_t *attr,
		void *(*thread_fn)(void *arg), void *arg)
{
	int rv;
	struct rcu_thread *rt = rcu_thread_setup();

	seqlock_acquire(&rt->rcu, &rcu_this->rcu);
	rt->thread_arg = arg;
	rt->thread_fn = thread_fn;

	rv = pthread_create(thread, attr, rcu_thread_start, rt);
	return rv;
}

/*
 * main RCU control aspects
 */

void rcu_hold(void)
{
	assert(rcu_this);
	seqlock_acquire(&rcu_this->rcu, &rcu_counter);
}

void rcu_release(void)
{
	assert(rcu_this);
	if (rcu_this->bump_on_release) {
		rcu_bump();
		rcu_this->bump_on_release = 0;
	}
	seqlock_release(&rcu_this->rcu);
}

void rcu_bump(void)
{
	seqlock_bump(&rcu_counter);
}

/*
 * RCU resource-release thread
 */

static void *rcu_main(void *arg);

static void rcu_start(void)
{
	assert(!pthread_create(&rcu_thread, NULL, rcu_main, NULL));
}

enum rcu_item_types {
	RCU_INVALID = 0,
	RCU_FREE,
	RCU_FREE_HEAD,
	RCU_CLOSE,
};

static void *rcu_main(void *arg)
{
	struct rcu_thread *rt;
	struct rcu_head *rh = NULL;

	seqlock_val_t rcuval = 1;
	while (1) {
		seqlock_wait(&rcu_counter, rcuval);
		atomlist_for_each(rcu_threads, rt, &rcu_threads)
			seqlock_wait(&rt->rcu, rcuval);

		while (rh || (rh = rcu_heads_pop(&rcu_heads))) {
			if (rh->rcu_seq > rcuval)
				break;

			switch (rh->type) {
			case RCU_FREE:
			case RCU_FREE_HEAD:
				if (rh->mem.mt)
					qfree(rh->mem.mt, rh->mem.ptr);
				else
					free(rh->mem.ptr);
				break;
			case RCU_CLOSE:
				close(rh->fd);
				break;
			}
			/* RCU_FREE_HEAD = we used an embedded rcu_head */
			if (rh->type != RCU_FREE_HEAD)
				qfree(MTYPE_RCU_FREE_ITEM, rh);
		}
		rcuval += 2;
	}
	return NULL;
}

/*
 * RCU'd free functions
 */

void rcu_free(struct memtype *mt, void *ptr)
{
	if (!rcu_active()) {
		qfree(mt, ptr);
		return;
	}

	struct rcu_head *rh = XCALLOC(MTYPE_RCU_FREE_ITEM, sizeof(*rh));
	rh->rcu_seq = seqlock_cur(&rcu_counter);
	rh->type = RCU_FREE;
	rh->mem.mt = mt;
	rh->mem.ptr = ptr;
	rcu_heads_add_tail(&rcu_heads, rh);
	rcu_this->bump_on_release = 1;
}

void rcu_free_head(struct memtype *mt, void *ptr, struct rcu_head *rh)
{
	if (!rcu_active()) {
		qfree(mt, ptr);
		return;
	}

	rh->rcu_seq = seqlock_cur(&rcu_counter);
	rh->type = RCU_FREE_HEAD;
	rh->mem.mt = mt;
	rh->mem.ptr = ptr;
	rcu_heads_add_tail(&rcu_heads, rh);
	rcu_this->bump_on_release = 1;
}

void rcu_free_sys(void *ptr)
{
	if (!rcu_active()) {
		free(ptr);
		return;
	}

	rcu_free(NULL, ptr);
}

void rcu_close(int fd)
{
	if (!rcu_active()) {
		close(fd);
		return;
	}

	struct rcu_head *rh = XCALLOC(MTYPE_RCU_FREE_ITEM, sizeof(*rh));
	rh->rcu_seq = seqlock_cur(&rcu_counter);
	rh->type = RCU_CLOSE;
	rh->fd = fd;
	rcu_heads_add_tail(&rcu_heads, rh);
	rcu_this->bump_on_release = 1;
}
