#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define EAX 0x12

int main()
{
  int c;
  char str[]= "Q}|u`sfg~sf{}|a3";

  for (int i = 0; i < 0x10; i++) {
    c = str[i];
    printf("XOR %c,0x%x = %c\n",
      c,
      EAX,     // EAX after SUB EDX,EAX; MOV EAX, EDX
      (c^EAX)  // XOR CHAR BYTE, EAX 
    );
  }
}
