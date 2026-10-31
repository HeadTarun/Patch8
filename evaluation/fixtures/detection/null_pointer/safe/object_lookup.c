struct Device { int state; };
struct Device *find_device(int id) { (void)id; return 0; }
int state_of(int id) { struct Device *d = find_device(id); return d ? d->state : -1; }
/* Safe failed object lookup handling. */
