#ifndef __LIBWDTOE_ATOMIC_H__
#define __LIBWDTOE_ATOMIC_H__

typedef struct {
	volatile int counter;
} atomic_t;

#define atomic_read(v) ((v)->counter)

#define atomic_set(v, i) (((v)->counter) = (i))

static inline void atomic_add(int i, atomic_t *v)
{
	(void)__sync_add_and_fetch(&v->counter, i);
}

static inline void atomic_sub(int i, atomic_t *v)
{
	(void)__sync_sub_and_fetch(&v->counter, i);
}

static inline void atomic_incr(atomic_t *v)
{
	(void)__sync_add_and_fetch(&v->counter, 1);
}

static inline void atomic_decr(atomic_t *v)
{
	(void)__sync_sub_and_fetch(&v->counter, 1);
}
#endif
