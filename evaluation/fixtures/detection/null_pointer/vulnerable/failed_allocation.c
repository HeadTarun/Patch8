#include <stdlib.h>
int make_value(void) { int *p = malloc(sizeof *p); *p = 1; int value = *p; free(p); return value; }
/* CWE-476: allocation result is used without checking for null. */
