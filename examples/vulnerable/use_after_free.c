#include <stdlib.h>

int read_released_value(void) {
    int *sample = malloc(sizeof(*sample));
    if (!sample) return -1;
    *sample = 7;
    free(sample);
    return *sample; /* CWE-416: use after free. */
}
