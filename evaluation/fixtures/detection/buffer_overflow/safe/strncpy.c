#include <string.h>
void copy(const char *src) { char dst[8]; strncpy(dst, src, sizeof dst - 1); dst[sizeof dst - 1] = 0; }
/* Bounded copy with explicit termination. */
