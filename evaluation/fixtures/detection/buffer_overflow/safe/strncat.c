#include <string.h>
void append(const char *src) { char dst[8] = "x"; size_t used = strlen(dst); strncat(dst, src, sizeof dst - used - 1); }
/* Append bounded by remaining destination capacity. */
