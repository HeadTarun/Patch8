#include <stdio.h>
void format(char *dst, const char *src) { sprintf(dst, "%s", src); }
/* CWE-120 candidate: unbounded formatting into caller-provided buffer. */
