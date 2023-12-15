#include <stdio.h>

int main()
{
  int n;

  printf("%03d.%03d.%03d.%03d\n", 127, 0, 0, 1);
  printf("%.2f\n", 5.6732);
  printf("%#010x\n", 3735928559);
  printf("%s%n\n", "01234", &n);
  printf("%3$d\n", 1,2,3);
  printf("%3$d%2$d%1$d\n", 1,2,3);
}
