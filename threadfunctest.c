#include "types.h"
#include "fcntl.h"
#include "user.h"
#include "threadfunc.h"
#include "threadfunc.c"
#define STACK_SIZE 4096

int Creation_Function() {
  for(int i =0; i<10; i++);
  exit();
}
int main() {
  thread t1;
  int ret = thread_create(&t1,Creation_Function,0);
  thread_join(&t1);
  if(ret) {
    printf(1,"Creation Failed\n");
  }
  else{
    printf(1,"Creation Success\n");
  }
  return 0;
}
