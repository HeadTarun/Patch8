#include <string.h>
void append(const char *src) { char dst[8] = "x"; strcat(dst, src); }
/* CWE-121 candidate: unbounded append into stack array. */
