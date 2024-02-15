#include "types.h"
#include "fcntl.h"
#include "user.h"

#include "threadfunc.h"

thread thread_create(thread *thread, int (*fn) (void *), void *arg)
{
	int tid;
	char *stack = malloc(4096);
	tid = clone(fn, stack + 4096, 0, arg);
	if (tid == -1)
		return 0;
	*thread = tid;
	printf(0,"thread id = %d\n", *thread);
	return tid;
}

int thread_join(thread *thread)
{
	printf(0,"pid = %d\n", join(thread->tid));
}
