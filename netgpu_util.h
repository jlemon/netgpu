#pragma once

#define stop_here(...) do {                                             \
        fprintf(stderr, "%s:%d:%s ",					\
                __FILE__, __LINE__, __func__);			        \
        fprintf(stderr, __VA_ARGS__);                                   \
        fprintf(stderr, "\n");                                          \
        exit(1);                                                        \
} while (0)

#define err_with(e, ...) do {                                           \
        fprintf(stderr, "%s:%d:%s %s(%d) ",                             \
                __FILE__, __LINE__, __func__, strerror(e), e);          \
        fprintf(stderr, __VA_ARGS__);                                   \
        fprintf(stderr, "\n");                                          \
        exit(1);                                                        \
} while (0)

#define err_exit(...) err_with(errno, __VA_ARGS__)

#define ERR(fcn) do {							\
	int err = fcn;							\
	if (err)							\
		errx(1, "%s:%d error %d", __FILE__, __LINE__, err);	\
} while (0)

#define SANITY(...) do {						\
	if (! (__VA_ARGS__))						\
		stop_here(#__VA_ARGS__);				\
} while (0)

#define array_size(x)   (sizeof(x) / sizeof((x)[0]))

/* kernel shims */
#define ____cacheline_aligned_in_smp

#define READ_ONCE(var) 		(*((volatile __typeof(var) *)(&(var))))
#define WRITE_ONCE(var, val) 	(*((volatile __typeof(val) *)(&(var))) = (val))

#define smp_mb()	libbpf_smp_rwmb()
#define smp_rmb()	libbpf_smp_rmb()
#define smp_wmb()	libbpf_smp_wmb()
