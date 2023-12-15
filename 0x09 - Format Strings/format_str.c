#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
  char *format = "%s";
  char *arg1 = "Hello World!\n";
  printf(format, arg1);
  return EXIT_SUCCESS;
}
