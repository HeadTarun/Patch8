int *initialize_sensor(int ok) { return ok ? (int *)1 : 0; }
int read_sensor(int ok) { int *sensor = initialize_sensor(ok); return *sensor; }
/* CWE-476: failed sensor initialization returns null and caller dereferences it. */
