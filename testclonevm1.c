#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sched.h>
#include <proc.h>


#define STACK_SIZE 65536

int shared_variable = 0;

int child_function(void *arg) {
    // Increment shared_variable by 1
    shared_variable++;

    // Print the value of shared_variable
    printf("Child process: shared_variable = %d\n", shared_variable);

    return 0;
}

int main() {
    char *stack;
    pid_t pid;

    // Allocate memory forchild stack
    stack = malloc(STACK_SIZE);

    if (stack == NULL) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    // Call clone() with CLONE_VM flag
    pid = clone(child_function, stack + STACK_SIZE, CLONE_VM, NULL); //child process

    if (pid == -1) {
        perror("clone");
        exit(EXIT_FAILURE);
    }

    // Wait for the child process to exit
    waitpid(pid, NULL, 0);

    // Print the final value of shared_variable
    printf("Parent process: shared_variable = %d\n", shared_variable);

    // Free the memory used for the child stack
    free(stack);

    return 0;
}
