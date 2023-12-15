void function(char *str) {
  char buffer[16];
  strcpy(buffer,str);
}

void main() {
  char large_string[256];
  fgets(large_string, strlen(large_string), stdin);
  function(large_string);
}
