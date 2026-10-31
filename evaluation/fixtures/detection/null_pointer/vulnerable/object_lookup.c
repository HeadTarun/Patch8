struct Device { int state; };
struct Device *find_device(int id) { (void)id; return 0; }
int state_of(int id) { return find_device(id)->state; }
/* CWE-476: failed object lookup can return null before member access. */
