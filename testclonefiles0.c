#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sched.h>
#include <fcntl.h>
#include<string.h>

#define STACK_SIZE 65536

int child_function(void *arg) {
    // Open a file in the child process
    int fd = open("test.txt", O_WRONLY | O_CREAT | O_TRUNC, 0666);

    if (fd == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    // Write some data to the file
    const char *data = "Hello, world!\n";
    write(fd, data, strlen(data));

    // Close the file
    close(fd);

    return 0;
}

int main() {
    char *stack;
    pid_t pid;

    // Allocate memory for the child stack
    stack = malloc(STACK_SIZE);

    if (stack == NULL) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    // Call clone() with CLONE_FILES flag to create a new process
    pid = clone(child_function, stack + STACK_SIZE, 0, NULL);

    if (pid == -1) {
        perror("clone");
        exit(EXIT_FAILURE);
    }

    // Wait for the child process to exit
    waitpid(pid, NULL, 0);

    // Open the file in the parent process
    int fd = open("test.txt", O_RDONLY);

    if (fd == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    // Read the data from the file
    char buffer[256];
    ssize_t num_read = read(fd, buffer, sizeof(buffer));

    if (num_read == -1) {
        perror("read");
        exit(EXIT_FAILURE);
    }

    // Print the data
    printf("Parent process: data read from file = %.*s", (int) num_read, buffer);

    // Close the file
    close(fd);

    // Free the memory used for the child stack
    free(stack);

    return 0;
}
