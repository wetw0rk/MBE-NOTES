int foo(int a, int b, int c)
{
  int x;
  int y;
  int z;

  x=y=z=0;
  z=x+y+a+b+c;
  return z;
}

int main(int argc, char **argv)
{
  foo(1,2,3);
}
