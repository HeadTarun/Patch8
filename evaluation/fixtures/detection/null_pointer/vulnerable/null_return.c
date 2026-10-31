int *lookup(void) { return 0; }
int read_value(void) { int *p = lookup(); return *p; }
/* CWE-476: a nullable function result is dereferenced without a check. */
