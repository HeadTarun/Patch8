int *initialize_sensor(int ok, int *sensor) { return ok ? sensor : 0; }
int read_sensor(int ok, int *sensor) { int *p = initialize_sensor(ok, sensor); if (!p) return -1; return *p; }
/* Safe handling of failed sensor initialization. */
