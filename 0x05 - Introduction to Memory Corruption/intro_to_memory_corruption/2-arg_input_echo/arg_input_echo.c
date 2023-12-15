#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[])
{
	if(argc != 2)
	{
		printf("You gave %d arguments, which is not 1\n", argc-1);
		return 1;
	}
	printf("Your input as a string: \'%s\'\n", argv[1]);
	printf("The first 4 bytes of your input as characters: \'%c%c%c%c\'\n", argv[1][0], argv[1][1], argv[1][2], argv[1][3]);
	printf("The first 4 bytes of your input as hex bytes: 0x%02x%02x%02x%02x\n", (unsigned char)argv[1][0], (unsigned char)argv[1][1], (unsigned char)argv[1][2], (unsigned char)argv[1][3]);
	int* i = (int*)(argv[1]);
	printf("The first 4 bytes of your input interpreted as an integer: %d\n", *i);
	unsigned int* j = (unsigned int*)(argv[1]);
	printf("The first 4 bytes of your input interpreted as an unsigned integer: %u\n", *j);

	return 0;
}
