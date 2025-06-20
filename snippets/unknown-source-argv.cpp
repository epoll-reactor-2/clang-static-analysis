#include <stdlib.h>
#include <stdio.h>

void f(char *m)
{
  for (int i = 0; i < 100000; ++i)
    m[i] = (char) i;
}

int main(int argc, char **argv)
{
  if (argc <= 1)
    return 1;

  printf("Size: %d", atoi(argv[1]));

  /* Generalized: Unknown source of allocation function size argument. */
  char *m = (char *) malloc(atoi(argv[1]));
  if (!m)
    return 2;

  f(m);
  /* Generalized: No relation between allocation size and indices. */
  int r = m[0] + m[100];
  free(m);
  return r;
}
