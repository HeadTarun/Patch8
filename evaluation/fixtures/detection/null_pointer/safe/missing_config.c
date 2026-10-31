struct Config { int mode; };
int read_mode(const struct Config *config) { if (!config) return -1; return config->mode; }
/* Safe optional configuration check. */
