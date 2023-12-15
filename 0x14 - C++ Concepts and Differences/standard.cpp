#include <iostream>

int main()
{
  char buffer[50];

  // C: printf("Hello world!");
  std::cout << "Hello world!" << std::endl;

  // C: scanf("%s", buffer);
  std::cin >> buffer;

  std::cout << buffer << std::endl;
}
