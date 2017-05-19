
#ifndef _FRRCU_H
#define _FRRCU_H

#include "memory.h"
#include "atomlist.h"

extern void rcu_init(void);

/* rcu_thread_create is neccessary to use if "arg" itself is something under
 * RCU protection;  it will hold the reference across creation of the new
 * thread */
extern int rcu_thread_create(pthread_t *thread, const pthread_attr_t *attr,
		const char *name,
		void *(*thread_fn)(void *arg), void *arg);

extern void rcu_hold(void);
extern void rcu_release(void);
extern void rcu_bump(void);

ATOMLIST_MAKEITEM(rcu_heads)
struct rcu_head {
	struct rcu_heads_item head;

	unsigned rcu_seq;
	unsigned type;

	union {
		int fd;
		struct {
			struct memtype *mt;
			void *ptr;
		} mem;
	};
};

extern void rcu_free(struct memtype *mt, void *ptr);
extern void rcu_free_head(struct memtype *mt, void *ptr, struct rcu_head *rh);
extern void rcu_free_sys(void *ptr);

extern void rcu_close(int fd);

#endif /* _FRRCU_H */
