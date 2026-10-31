#include <stddef.h>

int write_packet_byte(size_t index, unsigned char value) {
    unsigned char packet[8] = {0};
    packet[index] = value; /* CWE-787: index is not bounded by the packet size. */
    return packet[0];
}
