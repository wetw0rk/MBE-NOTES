#include <stdio.h>

int main() {
  int eax = 0xbffff2e0; /* current value of EAX */
  int edx = 1;

  while (1)
  {
    /* where we want to read from here */
    if ((eax+edx*4+0x8) == 0xbffff29c) {
      printf("COOKIE FOUND AT INDEX: %d\n", edx);
      break;
    }
    edx++;
  }
}
