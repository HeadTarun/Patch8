#include <string.h>
void copy(void) { char dst[8]; memcpy(dst, "ok", sizeof "ok"); }
/* Copy length is bounded by the known source object size. */
