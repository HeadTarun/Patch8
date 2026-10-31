int get_sensor_value(void) {
    int *sensor = 0;
    return *sensor; /* CWE-476: null pointer dereference. */
}
