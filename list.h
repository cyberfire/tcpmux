#ifndef LIST_H
#define LIST_H

/* copied from Linux Kernel code */

#define LIST_HEAD_INIT(name) { &(name), &(name) }

#define LIST_HEAD(name) \
	struct list name = LIST_HEAD_INIT(name)

struct list {
	struct list *next, *prev;
};

static inline void list_init(struct list *list)
{
	list->next = list;
	list->prev = list;
}

static inline int list_empty(struct list *list)
{
	return list->next == list;
}

static inline void list_insert(struct list *new, struct list *base)
{
	new->next = base->next;
	new->prev = base;

	base->next->prev = new;
	base->next = new;
}

static inline void list_prepend(struct list *new, struct list *base)
{
	list_insert(new, base->prev);
}

static inline void list_remove(struct list *link)
{
	link->prev->next = link->next;
	link->next->prev = link->prev;
}

#define list_entry(link, type, member) \
	((type *)((char *)(link)-(unsigned long)(&((type *)0)->member)))

#define list_head(list, type, member)		\
	list_entry((list)->next, type, member)

#define list_tail(list, type, member)		\
	list_entry((list)->prev, type, member)

#define list_next(elm, member)					\
	list_entry((elm)->member.next, typeof(*elm), member)

#define list_for_each(pos, head) \
	for (pos = (head)->next; pos != (head); pos = pos->next)

#define list_for_each_entry(pos, list, member)			\
	for (pos = list_head(list, typeof(*pos), member);	\
	     &pos->member != (list);				\
	     pos = list_next(pos, member))

#define list_for_each_entry_safe(pos, n, list, member)			\
	for (pos = list_head(list, typeof(*pos), member),	\
		n = list_next(pos, member);			\
	     &pos->member != (list); 					\
	     pos = n, n = list_next(n, member))

#endif
