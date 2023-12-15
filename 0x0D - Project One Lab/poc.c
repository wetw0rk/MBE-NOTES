/*

This PoC program will calculate the secretpass used by Tw33tChainz;
the password is calculated using the generated password from stdout.
In order for this to work the user must be wetw0rk and salt 123.

gcc poc.c -o poc

Functions:

  toLendian: places 4 bytes into little endian format
  convert: convert the byte array into the proper format

Equation:

  xor byte   = (user byte ^ ?)
  secretpass = (xor byte - salt byte)

*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define checkXor(u, c, g) ((u ^ c) == g) ? 0: -1

int username[] = { /* "wetw0rk" */
  0x77, 0x65, 0x74, 0x77, 0x30, 0x72, 0x6b, 0x0a,
  0x00, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc
};

int salt[] = { /* "123" */
  0x31, 0x32, 0x33, 0x0a, 0x00, 0xba, 0xba, 0xba,
  0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba
};

void
toLendian(int arr[])
{
  int i, j;
  int tmp[4];

  for (i = 0; i < 4; i++)
    tmp[i] = arr[i];

  j = 3;
  for (i = 0; i < 4; i++)
    arr[i] = tmp[j-i];
}

void
convert(int arr[])
{
  for (int i = 0; i < 16; i++) {
    toLendian(&arr[i]);
    i += 3;
  }
}

int
main(int argc, char *argv[]) {

  int i, j;
  int secretpass[16];
  int xor_bytes[16];
  int generated_password[16];

  char byte[3] = {0};

  if (argc < 2)
  {
    printf("usage: %s <generated password>\n", argv[0]);
    return -1;
  }
  
  if (strlen(argv[1]) != 32)
  {
    printf("generated password can only be 32 bytes\n");
    return -1;
  }

  /* convert the string into integers for the byte array */
  for (i = 0, j = 0; i < 32; i++)
  {
    strncpy(byte, (argv[1] + (i++)), 2);
    generated_password[j++] = strtoul(byte, NULL, 16);
  }

  convert(generated_password);

  for (i = 0; i < 16; i++)
    for (j = 0; j < 0xff; j++)
      if ((checkXor(username[i], j, generated_password[i])) == 0)
        secretpass[i] = ((unsigned int)(j-salt[i]) % 0xFF);
  
  printf("set $eax=\"");
  for (i = 0; i < 16; i++)
    printf("\\x%02x", secretpass[i]);
  printf("\"\n");

  printf("set $ecx=\"");
  for (i = 0; i < 16; i++)
    printf("\\x%02x", secretpass[i]);
  printf("\"\n");

  return 0;
}
