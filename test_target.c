#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

void test_length_field_bof(const unsigned char *data, size_t len) {
    if (len < 5) {
        return;
    }
    size_t copy_size = data[0];
    char buf[10];
    memcpy(buf, data + 1, copy_size);
}

void test_boundary_check_bypass(const unsigned char *data, size_t len) {
    if (len < 4) {
        return;
    }
    uint16_t idx = data[0] | (data[1] << 8);
    int lut[256] = {0};
    if (idx < 256) {
        volatile int val = lut[idx];
        (void)val;
    }
}

void test_array_overflow(const unsigned char *data, size_t len) {
    if (len < 2) {
        return;
    }
    const char *table[] = {"A", "B", "C"};
    uint8_t idx = data[0];
    printf("%s\n", table[idx]);
}

void test_alloc_underflow(const unsigned char *data, size_t len) {
    if (len < 2) {
        return;
    }
    size_t sz = data[0];
    void *p = malloc(sz);
    if (sz == 0) {
        fprintf(stderr, "zero alloc edge\n");
    }
    free(p);
}

int main(void) {
    unsigned char test[] = {5, 9, 4, 'H', 'e', 'l', 'l', 'o'};
    test_length_field_bof(test, sizeof(test));
    test_boundary_check_bypass(test, sizeof(test));
    test_array_overflow(test, sizeof(test));
    test_alloc_underflow(test, sizeof(test));
    return 0;
}
