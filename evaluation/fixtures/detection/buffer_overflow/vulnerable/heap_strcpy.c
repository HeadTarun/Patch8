#include <stdlib.h>
#include <string.h>
void copy(const char *src) { char *dst = malloc(8); if (dst) strcpy(dst, src); free(dst); }
/* CWE-122 candidate: unbounded copy into heap allocation. */
