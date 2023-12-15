#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
  int local_18;
  char *param_1;
  unsigned int local_14;

  if (argc != 2) {
    printf("%s <lastname>\n", argv[0]);
    exit(-1);
  }

  param_1 = argv[1];

  /* recreated algorithm from Ghidra */
  local_14 = (param_1[3] ^ 0x1337U) + 0x5eeded;
  local_18 = 0;

  while (local_18 < strlen(param_1))
  {
    if (param_1[local_18] < ' ')
      return 1;

    local_14 = local_14 + (param_1[local_18] ^ local_14) % 0x539;
    local_18 = local_18 + 1;
  }
  printf("%d\n", local_14);

  return 0;
}
