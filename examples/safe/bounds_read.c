#include <stddef.h>

int read_packet_byte(size_t index) {
    const unsigned char packet[8] = {0};
    if (index >= sizeof(packet)) return -1;
    return packet[index];
}
