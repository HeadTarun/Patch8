#include <stdio.h>
void format(const char *src) { char dst[8]; sprintf(dst, "%s", src); }
/* CWE-121 candidate: unbounded formatting into stack array. */
