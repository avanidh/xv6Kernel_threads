#define CLONE_FILES  2
#define CLONE_VM     8
#define NEW       0
#define RUNNING   1
#define KILLED    2

typedef struct thread{
	int tid;
	int state;
	char*stack;
}thread;
int thread_create(thread *thread, int (*fn) (void *), void *arg);
int thread_join(thread *thread);

