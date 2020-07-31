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
  int i = 50;
  while(i > 0) {
    --i;
    if (i > 40) {
      printf("%p", &i);
    }
  }
}

int main() {
  function1(10);
  function2();
}