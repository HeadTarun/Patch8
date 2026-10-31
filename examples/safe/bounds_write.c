#include <stddef.h>

int write_packet_byte(size_t index, unsigned char value) {
    unsigned char packet[8] = {0};
    if (index >= sizeof(packet)) return -1;
    packet[index] = value;
    return packet[0];
}
