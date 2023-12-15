/*

This POC C program will try to calculate the index that can access
the destination address. Once found pass it to checkAddr, it will
then verify we can write to it. NOTE if the output is way off try
a negative offset

gcc -o calcPOC calcPOC.c 

*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
  uint32_t index_one = 0xbffff54c; // data[1];
  uint32_t wanna_go2;

  if (argc == 1)
  {
    printf("usage: %s <write_addr>\n", argv[0]);
    return -1;
  }
  wanna_go2 = strtol(argv[1], NULL, 16);

  printf("index: %d\n", ((index_one - wanna_go2)/4));
}
