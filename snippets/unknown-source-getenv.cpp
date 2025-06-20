#include <stdio.h>
#include <stdlib.h>

int main()
{
  char *env = getenv("VAR");
  if (!env)
    return 1;
  /* Unknown source. */
  int siz = atoi(env);
  printf("Size: %d", siz);
  /* Allocate unknown size. */
  char *s = (char *) malloc(siz);
  if (!s)
    return 2;
  /* Access at index with no assumptions about size. */
  s[10000] = siz;
  int res = s[10000];
  free(s);
  return res;
}
