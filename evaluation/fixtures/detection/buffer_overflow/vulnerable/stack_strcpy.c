#include <string.h>
void copy(const char *src) { char dst[8]; strcpy(dst, src); }
/* CWE-121 candidate: unbounded copy into stack array. */
