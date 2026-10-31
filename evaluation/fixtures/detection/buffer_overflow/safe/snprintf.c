#include <stdio.h>
void format(const char *src) { char dst[8]; snprintf(dst, sizeof dst, "%s", src); }
/* Safe bounded formatting. */
