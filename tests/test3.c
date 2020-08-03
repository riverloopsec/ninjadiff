#include <stdio.h>

void function1(int num) {
  for(int i = 0; i < num; ++i) {
    if(i % 2 == 0) {
      printf("%d", i);
    }
    printf("hello world!\n");
  }
}

void function2()  {
  int i = 0;
  while(i < 50) {
    ++i;
    if (i > 40) {
      printf("%p", &i);
    }
  }
}

void * function3(void * val) {
  return val;
}

int main() {
  function1(10);
  function2();
  function3(&function1);
}