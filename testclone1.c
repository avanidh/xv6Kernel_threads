#include "types.h"
#include "user.h"
#define STACK_SIZE 2048
int func(void* args) {
    int *arg = (int*)args;
    printf(0,"arg value = %d\n", *arg);
    *arg = *arg + 100;
    exit();
}
int main() {
    int val = 1000;
    printf(0,"Initial Value = %d\n",val);
    char* stack = sbrk(STACK_SIZE);
    stack += STACK_SIZE;
    int thread_pid = clone(func,(void *)stack,10,&val);
    printf(0,"Thread pid =  %d\n",thread_pid); //child pid
    printf(0,"Current values = %d\n",val);
    exit();
}
