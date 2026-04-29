#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

void process_data(const unsigned char *data, size_t data_len) {
    if (data_len < 4) {
        return;
    }

    size_t payload_size = data[0];
    size_t copy_len = data[1];
    size_t table_idx = data[2];
    printf("Payload size: %zu, copy len: %zu, idx: %zu\n", payload_size, copy_len, table_idx);

    if (payload_size > data_len - 1) {
        printf("Invalid payload size!\n");
        return;
    }

    if (copy_len > data_len) {
        return;
    }

    uint8_t narrow = (uint8_t)data_len;
    if (narrow == 0) {
        return;
    }

    char lut[8] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'};
    char selected = lut[table_idx];

    char *buffer = malloc(payload_size + 1);
    memcpy(buffer, data + 1, copy_len);
    buffer[payload_size] = '\0';
    printf("Selected: %c Data: %s\n", selected, buffer);
    free(buffer);
}

int main(int argc, char **argv) {
    unsigned char test[] = {5, 9, 4, 'H', 'e', 'l', 'l', 'o'};
    process_data(test, sizeof(test));
    return 0;
}
