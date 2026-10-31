#include <string.h>
void copy(const char *src) { char dst[8]; size_t n = strlen(src); if (n < sizeof dst) memcpy(dst, src, n + 1); }
/* Safe copy after checking source length against destination capacity. */
