/* wyn2: whats your name program v2 */

#include <stdio.h>
#include <unistd.h>

int main(int argc, char * argv[])
{
  char buffer[10] = {0};           /* create a 10 byte buffer */
  printf("What's your name?\n");
  read(STDIN_FILENO, buffer, 100); /* read 10 bytes from STDIN(0) into our buffer array */
  printf("Hello %s\n", buffer);    /* print the buffer */

  return 0;
}
