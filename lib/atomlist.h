/*
 * Copyright (c) 2016-2017  David Lamparter, for NetDEF, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#ifndef _FRR_ATOMLIST_H
#define _FRR_ATOMLIST_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include "frratomic.h"

/* pointer with lock/deleted/invalid bit in lowest bit 
 *
 * for atomlist/atomsort, "locked" means "this pointer can't be updated, the
 * item is being deleted".  it is permissible to assume the item will indeed
 * be deleted (as there are no replace/etc. ops in this).
 *
 * in general, lowest 2/3 bits on 32/64bit architectures are available for
 * uses like this; the only thing that will really break this is putting an
 * atomlist_item in a struct with "packed" attribute.  (it'll break
 * immediately and consistently.) -- don't do that.
 */
typedef uintptr_t atomptr_t;
#define ATOMPTR_MASK (UINTPTR_MAX - 1)
#define ATOMPTR_LOCK (1)
#define ATOMPTR_NULL (0)

static inline atomptr_t atomptr_i(void *val)
{
	atomptr_t atomval = (atomptr_t)val;
	assert(!(atomval & ATOMPTR_LOCK));
	return atomval;
}
static inline void *atomptr_p(atomptr_t val)
{
	return (void *)(val & ATOMPTR_MASK);
}
static inline bool atomptr_l(atomptr_t val)
{
	return (bool)(val & ATOMPTR_LOCK);
}



/* single-linked list, unsorted/arbitrary.
 * can be used as queue with add_tail / pop
 *
 * all operations are lock-free, but not neccessarily wait-free.  this means
 * that there is no state where the system as a whole stops making process,
 * but it *is* possible that a *particular* thread is delayed by some time.
 *
 * the only way for this to happen is for other threads to continuously make
 * updates.  an inactive / blocked / deadlocked other thread cannot cause such
 * delays, and to cause such delays a thread must be heavily hitting the list -
 * it's a rather theoretical concern.
 */

/* don't use these structs directly */
struct atomlist_item {
	_Atomic atomptr_t next;
};
#define atomlist_itemp(val) ((struct atomlist_item *)atomptr_p(val))

struct atomlist_head {
	_Atomic atomptr_t first, last;
	_Atomic size_t count;
};

/* use as:
 *
 * ATOMLIST_MAKEITEM(namelist)
 * struct name {
 *   struct namelist_item nlitem;
 * }
 * ATOMLIST_MAKEFUNCS(namelist, struct name, nlitem)
 */
#define ATOMLIST_MAKEITEM(prefix) \
struct prefix ## _item { struct atomlist_item ai; };

#define ATOMLIST_MAKEFUNCS(prefix, type, field) \
struct prefix ## _head { struct atomlist_head ah; }; \
static inline void prefix ## _add_head(struct prefix##_head *h, type *item) \
	{ atomlist_add_head(&h->ah, &item->field.ai); } \
static inline void prefix ## _add_tail(struct prefix##_head *h, type *item) \
	{ atomlist_add_tail(&h->ah, &item->field.ai); } \
static inline void prefix ## _del_hint(struct prefix##_head *h, type *item, \
		_Atomic atomptr_t *hint ) \
	{ atomlist_del_hint(&h->ah, &item->field.ai, hint); } \
static inline void prefix ## _del(struct prefix##_head *h, type *item) \
	{ atomlist_del_hint(&h->ah, &item->field.ai, NULL); } \
static inline type *prefix ## _pop(struct prefix##_head *h) \
	{ char *p = (char *)atomlist_pop(&h->ah); \
	  return p ? (type *)(p - offsetof(type, field)) : NULL; } \
static inline type *prefix ## _first(struct prefix##_head *h) \
	{ char *p = atomptr_p(atomic_load_explicit(&h->ah.first, \
				memory_order_relaxed)); \
	  return p ? (type *)(p - offsetof(type, field)) : NULL; } \
static inline type *prefix ## _next(type *item) \
	{ char *p = atomptr_p(atomic_load_explicit(&item->field.ai.next, \
				memory_order_relaxed)); \
	  return p ? (type *)(p - offsetof(type, field)) : NULL; } \
static inline type *prefix ## _next_safe(type *item) \
	{ return item ? prefix##_next(item) : NULL; } \
static inline size_t prefix ## _count(struct prefix##_head *h) \
	{ return atomic_load_explicit (&h->ah.count, memory_order_relaxed); } \
/* ... */

#define atomlist_for_each(prefix, item, head) \
	for (item = prefix##_first(head); item; item = prefix##_next(item))
#define atomlist_for_each_safe(prefix, item, safe, head) \
	for (item = prefix##_first(head), \
		safe = prefix##_next_safe(item); \
		item; \
		item = safe, safe = prefix##_next_safe(safe))

/* add_head:
 * - contention on ->first pointer
 * - return implies completion
 */
void atomlist_add_head(struct atomlist_head *h, struct atomlist_item *item);

/* add_tail:
 * - concurrent add_tail can cause wait but has progress guarantee
 * - return does NOT imply completion.  completion is only guaranteed after
 *   all other add_tail operations that started before this add_tail have
 *   completed as well.
 */
void atomlist_add_tail(struct atomlist_head *h, struct atomlist_item *item);

/* del/del_hint:
 *
 * OWNER MUST HOLD REFERENCE ON ITEM TO BE DELETED, ENSURING NO OTHER THREAD
 * WILL TRY TO DELETE THE SAME ITEM.  DELETING INCLUDES pop().
 *
 * as with all deletions, threads that started reading earlier may still hold
 * pointers to the deleted item.  completion is however guaranteed for all
 * reads starting later.
 */
void atomlist_del_hint(struct atomlist_head *h, struct atomlist_item *item,
		_Atomic atomptr_t *hint);

/* pop:
 *
 * as with all deletions, threads that started reading earlier may still hold
 * pointers to the deleted item.  completion is however guaranteed for all
 * reads starting later.
 */
struct atomlist_item *atomlist_pop(struct atomlist_head *h);



struct atomsort_item {
	_Atomic atomptr_t next;
};
#define atomsort_itemp(val) ((struct atomsort_item *)atomptr_p(val))

struct atomsort_head {
	_Atomic atomptr_t first;
	_Atomic size_t count;
};

#define ATOMSORT_MAKEITEM(prefix) \
struct prefix ## _item { struct atomsort_item ai; };

#define ATOMSORT_MAKEFUNCS(prefix, type, field, cmpfn) \
struct prefix ## _head { struct atomsort_head ah; }; \
static inline int prefix ## _cmp(const struct atomsort_item *a, \
		const struct atomsort_item *b) \
	{ return cmpfn( (const type *)((char *)a - offsetof(type, field)), \
			(const type *)((char *)b - offsetof(type, field))); } \
static inline void prefix ## _add(struct prefix##_head *h, type *item) \
	{ atomsort_add(&h->ah, &item->field.ai, prefix ## _cmp); } \
static inline type *prefix ## _first(struct prefix##_head *h) \
	{ char *p = atomptr_p(atomic_load_explicit(&h->ah.first, \
				memory_order_relaxed)); \
	  return p ? (type *)(p - offsetof(type, field)) : NULL; } \
static inline type *prefix ## _next(type *item) \
	{ char *p = atomptr_p(atomic_load_explicit(&item->field.ai.next, \
				memory_order_relaxed)); \
	  return p ? (type *)(p - offsetof(type, field)) : NULL; } \
static inline type *prefix ## _next_safe(type *item) \
	{ return item ? prefix##_next(item) : NULL; } \
static inline void prefix ## _del_hint(struct prefix##_head *h, type *item, \
		_Atomic atomptr_t *hint ) \
	{ atomsort_del_hint(&h->ah, &item->field.ai, hint); } \
static inline void prefix ## _del(struct prefix##_head *h, type *item) \
	{ atomsort_del_hint(&h->ah, &item->field.ai, NULL); } \
static inline size_t prefix ## _count(struct prefix##_head *h) \
	{ return atomic_load_explicit (&h->ah.count, memory_order_relaxed); } \
/* ... */

#define atomsort_for_each	atomlist_for_each
#define atomsort_for_each_safe	atomlist_for_each_safe

void atomsort_add(struct atomsort_head *h,
		struct atomsort_item *item, int (*cmpfn)(
			const struct atomsort_item *,
			const struct atomsort_item *));

void atomsort_del_hint(struct atomsort_head *h,
		struct atomsort_item *item, _Atomic atomptr_t *hint);

#endif /* _FRR_ATOMLIST_H */
