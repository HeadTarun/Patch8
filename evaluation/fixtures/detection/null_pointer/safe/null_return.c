int *lookup(int ok, int *value) { return ok ? value : 0; }
int read_value(int ok, int *value) { int *p = lookup(ok, value); return p ? *p : 0; }
/* Safe null check before dereference. */
