struct Config { int mode; };
int read_mode(const struct Config *config) { return config->mode; }
/* CWE-476: optional configuration pointer is dereferenced without validation. */
