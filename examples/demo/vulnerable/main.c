#include <stddef.h>

static int read_value(const int *value) {
    return *value;
}

int main(int argc, char **argv) {
    (void)argv;
    int value = 7;
    if (argc > 1) {
        return read_value(NULL);
    }
    return read_value(&value) == 7 ? 0 : 1;
}
