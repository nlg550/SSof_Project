#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

int main() {
  int control;
  char buf[64];

  control = 1;
  fgets(buf, 64, stdin);

}