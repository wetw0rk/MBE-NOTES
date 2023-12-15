/*

This POC program will try to calculate of the jump will be taken
based on the store_number. I did not check for 0xb7 as this is a
number that is written rather than an indexable location.

gcc -o checkAddr checkAddr.c 

*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
  uint32_t comp;
  uint32_t index;
  uint32_t index_addr = 0xbffff33c; // data[1];

  if (argc == 1)
  {
    printf("usage: %s <index_start>\n", argv[0]);
    return -1;
  }
  index = (uint32_t) atoi(argv[1]);

  if (index > 1)
  {
    comp = (index-1) * 0x04;
    index_addr += comp;
  }
  if (index == 0)
  {
    index = 1;
  }

  int i = 0;
  for (index; index < 0x1fffffffe; index++) {
    if (index % 3 == 0)
      index_addr += 0x04;
    else {
      printf("*data[%d]=0x%08x, JUMP TAKEN: N, NUM STORED: Y\n", index, index_addr);
      index_addr += 0x04;
    }

    i++;
    if (i == 10) {
      return -1;
    }
  }
}
