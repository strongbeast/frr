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

#include "atomlist.h"

void atomlist_add_head(struct atomlist_head *h, struct atomlist_item *item)
{
	atomptr_t prevval;
	atomptr_t i = atomptr_i(item);

	atomic_fetch_add_explicit(&h->count, 1, memory_order_relaxed);

	/* updating ->last is possible here, but makes the code considerably
	 * more complicated... let's not. */

	prevval = item->next = ATOMPTR_NULL;
	/* head-insert atomically
	 * release barrier: item + item->next writes must be completed */
	while (!atomic_compare_exchange_weak_explicit(&h->first, &prevval, i,
				memory_order_release, memory_order_relaxed))
		atomic_store_explicit (&item->next, prevval,
				memory_order_relaxed);
}

void atomlist_add_tail(struct atomlist_head *h, struct atomlist_item *item)
{
	atomptr_t prevval = item->next = ATOMPTR_NULL;
	atomptr_t i = atomptr_i(item);
	atomptr_t hint;
	struct atomlist_item *prevptr;
	_Atomic atomptr_t *prev;

	atomic_fetch_add_explicit(&h->count, 1, memory_order_relaxed);

	/* place new item into ->last
	 * release: item writes completed;  acquire: DD barrier on hint */
	hint = atomic_exchange_explicit(&h->last, i, memory_order_acq_rel);

	while (1) {
		if (atomptr_p(hint) == NULL)
			prev = &h->first;
		else
			prev = &atomlist_itemp(hint)->next;

		do {
			prevval = atomic_load_explicit(prev,
					memory_order_consume);
			prevptr = atomlist_itemp(prevval);
			if (prevptr == NULL)
				break;

			prev = &prevptr->next;
		} while (prevptr);

		/* last item is being deleted - start over */
		if (atomptr_l(prevval)) {
			hint = ATOMPTR_NULL;
			continue;
		}

		/* no barrier - item->next is NULL and was so in xchg above */
		if (!atomic_compare_exchange_strong_explicit(prev, &prevval, i,
					memory_order_relaxed,
					memory_order_relaxed))
		{
			hint = prevval;
			continue;
		}
		break;
	}
}

void atomlist_del_hint(struct atomlist_head *h, struct atomlist_item *item,
		_Atomic atomptr_t *hint)
{
	_Atomic atomptr_t *prev = hint ? hint : &h->first, *upd;
	atomptr_t prevval, updval, next;
	struct atomlist_item *prevptr;

	/* drop us off "last" if needed.  no r/w to barrier. */
	prevval = atomptr_i(item);
	atomic_compare_exchange_strong_explicit(&h->last, &prevval,
			ATOMPTR_NULL,
			memory_order_relaxed, memory_order_relaxed);

	/* mark ourselves in-delete - full barrier */
	next = atomic_fetch_or_explicit(&item->next, ATOMPTR_LOCK,
				memory_order_seq_cst);
	assert(!atomptr_l(next));	/* delete race on same item */

	atomic_fetch_sub_explicit(&h->count, 1, memory_order_relaxed);

	while (1) {
		upd = NULL;
		updval = ATOMPTR_LOCK;

		do {
			prevval = atomic_load_explicit(prev,
					memory_order_consume);

			/* track the beginning of a chain of deleted items
			 * this is neccessary to make this lock-free; we can
			 * complete deletions started by other threads. */
			if (!atomptr_l(prevval)) {
				updval = prevval;
				upd = prev;
			}

			prevptr = atomlist_itemp(prevval);
			if (prevptr == item)
				break;

			prev = &prevptr->next;
		} while (prevptr);

		if (prevptr != item)
			/* another thread completed our deletion */
			return;

		if (!upd || atomptr_l(updval)) {
			/* failed to find non-deleted predecessor...
			 * have to try again */
			prev = &h->first;
			continue;
		}

		if (!atomic_compare_exchange_strong_explicit(upd, &updval,
					next, memory_order_relaxed,
					memory_order_relaxed))
		{
			/* prev doesn't point to item anymore, something
			 * was inserted.  continue at same position forward. */
			continue;
		}
		break;
	}
}

struct atomlist_item *atomlist_pop(struct atomlist_head *h)
{
	atomptr_t prevval, next;
	struct atomlist_item *prevptr;

	while (1) {
		prevval = atomic_load_explicit(&h->first, memory_order_acquire);
		prevptr = atomlist_itemp(prevval);

		if (!prevptr)
			return NULL;

		/* try to mark deletion */
		next = atomic_fetch_or_explicit(&prevptr->next, ATOMPTR_LOCK,
					memory_order_acq_rel);
		if (atomptr_l(next))
			continue;	/* delete race on same item */

		if (atomic_compare_exchange_strong_explicit(&h->first, &prevval,
				next, memory_order_acquire, memory_order_relaxed))
			break;
	}

	/* drop us off "last" if needed
	 *
	 * consistency is guaranteed by setting the lock bit before popping
	 * the item;  if this is indeed the last item, the next pointer was
	 * not updated in the meantime. */
	prevval = atomptr_i(prevptr);
	atomic_compare_exchange_strong_explicit(&h->last, &prevval,
			ATOMPTR_NULL,
			memory_order_relaxed, memory_order_relaxed);

	atomic_fetch_sub_explicit(&h->count, 1, memory_order_relaxed);
	return prevptr;
}

void atomsort_add(struct atomsort_head *h,
		struct atomsort_item *item, int (*cmpfn)(
			const struct atomsort_item *,
			const struct atomsort_item *))
{
	_Atomic atomptr_t *prev;
	atomptr_t prevval;
	atomptr_t i = atomptr_i(item);
	struct atomsort_item *previtem;

	atomic_fetch_add_explicit(&h->count, 1, memory_order_relaxed);

	do {
		prev = &h->first;

		do {
			prevval = atomic_load_explicit(prev, memory_order_acquire);
			previtem = atomptr_p(prevval);

			if (!previtem || cmpfn(previtem, item) >= 0)
				break;
			prev = &previtem->next;
		} while (1);

		if (atomptr_l(prevval))
			continue;

		item->next = prevval;
		if (atomic_compare_exchange_strong_explicit(prev, &prevval, i,
				memory_order_release, memory_order_relaxed))
			break;
	} while (1);
}

void atomsort_del_hint(struct atomsort_head *h,
		struct atomsort_item *item, _Atomic atomptr_t *hint)
{
	_Atomic atomptr_t *prev = hint ? hint : &h->first, *upd;
	atomptr_t prevval, updval, next;
	struct atomsort_item *prevptr;

	/* mark ourselves in-delete - full barrier */
	next = atomic_fetch_or_explicit(&item->next, ATOMPTR_LOCK,
				memory_order_seq_cst);
	assert(!atomptr_l(next));	/* delete race on same item */

	atomic_fetch_sub_explicit(&h->count, 1, memory_order_relaxed);

	while (1) {
		upd = NULL;
		updval = ATOMPTR_LOCK;

		do {
			prevval = atomic_load_explicit(prev,
					memory_order_consume);

			/* track the beginning of a chain of deleted items
			 * this is neccessary to make this lock-free; we can
			 * complete deletions started by other threads. */
			if (!atomptr_l(prevval)) {
				updval = prevval;
				upd = prev;
			}

			prevptr = atomsort_itemp(prevval);
			if (prevptr == item)
				break;

			prev = &prevptr->next;
		} while (prevptr);

		if (prevptr != item)
			/* another thread completed our deletion */
			return;

		if (!upd || atomptr_l(updval)) {
			/* failed to find non-deleted predecessor...
			 * have to try again */
			prev = &h->first;
			continue;
		}

		if (!atomic_compare_exchange_strong_explicit(upd, &updval,
					next, memory_order_relaxed,
					memory_order_relaxed))
		{
			/* prev doesn't point to item anymore, something
			 * was inserted.  continue at same position forward. */
			continue;
		}
		break;
	}
}
