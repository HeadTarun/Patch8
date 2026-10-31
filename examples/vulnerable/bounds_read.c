#include <stddef.h>

int read_packet_byte(size_t index) {
    const unsigned char packet[8] = {0};
    return packet[index]; /* CWE-125: index is not bounded by the packet size. */
}
