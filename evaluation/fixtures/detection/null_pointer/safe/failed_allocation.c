#include <stdlib.h>
int make_value(void) { int *p = malloc(sizeof *p); if (!p) return -1; *p = 1; int value = *p; free(p); return value; }
/* Safe allocation check before use. */
