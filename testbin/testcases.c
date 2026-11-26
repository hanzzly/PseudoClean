/* PseudoClean test corpus — covers every construct the analyzer claims to
 * understand.  Deliberately written so each category is isolated in its own
 * function, which makes the expected analyzer output checkable by hand.
 *
 * Build:
 *   gcc -O0 -o testcases_O0.bin testcases.c
 *   gcc -O2 -o testcases_O2.bin testcases.c
 *   strip -o testcases_stripped.bin testcases_O0.bin
 *
 * Categories:
 *   arithmetic      add/sub/mul/div/mod
 *   nested_if       nested if/else, early returns
 *   loops           for/while/do-while, break/continue, loop counters
 *   arrays          arrays, pointers, pointer walking
 *   strings         strlen/strcpy/strcat/strcmp/strchr, char buffers
 *   xor_crypto      XOR decode with key, buffer transform
 *   bitwise         masks, shifts, rotations, byte swap
 *   switch_stmt     small switch + jump-table sized switch
 *   calls           wrappers around libc, allocation, validation
 *   hash            CRC32-style loop with polynomial constant
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ------------------------------------------------------------------ */
/* arithmetic                                                          */
/* ------------------------------------------------------------------ */
int arithmetic_mix(int a, int b)
{
    int sum = a + b;
    int diff = a - b;
    int prod = a * b;
    int quot = b != 0 ? a / b : 0;
    int rem = b != 0 ? a % b : 0;
    return sum + diff + prod + quot + rem;
}

/* ------------------------------------------------------------------ */
/* nested if / early returns                                           */
/* ------------------------------------------------------------------ */
int classify_score(int score, int bonus, int penalty)
{
    int total = score + bonus - penalty;
    if (total > 90) {
        if (bonus > 10) {
            if (penalty == 0)
                return 4;
            else
                return 3;
        } else {
            return 2;
        }
    } else if (total > 50) {
        if (bonus > 5)
            return 1;
        return 0;
    }
    return -1;
}

int early_return_guard(const char *name, int flags)
{
    if (name == NULL)
        return -1;
    if (name[0] == '\0')
        return -2;
    if (flags & 0x01)
        return 1;
    if (flags & 0x02)
        return 2;
    return 0;
}

/* ------------------------------------------------------------------ */
/* loops                                                               */
/* ------------------------------------------------------------------ */
int sum_until(int bound)
{
    int acc = 0;
    for (int i = 0; i < bound; i++) {
        if (i == 7)
            continue;
        if (i > 40)
            break;
        acc += i;
    }
    return acc;
}

int count_while(const char *s)
{
    int n = 0;
    while (s[n] != '\0')
        n++;
    return n;
}

int do_while_digits(unsigned int v)
{
    int digits = 0;
    do {
        digits++;
        v /= 10;
    } while (v != 0);
    return digits;
}

/* ------------------------------------------------------------------ */
/* arrays and pointers                                                 */
/* ------------------------------------------------------------------ */
void reverse_array(int *data, int count)
{
    int lo = 0;
    int hi = count - 1;
    while (lo < hi) {
        int tmp = data[lo];
        data[lo] = data[hi];
        data[hi] = tmp;
        lo++;
        hi--;
    }
}

int sum_pointer_walk(const int *begin, const int *end)
{
    int total = 0;
    for (const int *p = begin; p < end; p++)
        total += *p;
    return total;
}

/* ------------------------------------------------------------------ */
/* strings                                                             */
/* ------------------------------------------------------------------ */
int build_greeting(char *out, size_t out_len, const char *name)
{
    if (out == NULL || name == NULL)
        return -1;
    strncpy(out, "hello ", out_len - 1);
    out[out_len - 1] = '\0';
    strncat(out, name, out_len - strlen(out) - 1);
    return (int)strlen(out);
}

int is_prefix(const char *text, const char *prefix)
{
    size_t n = strlen(prefix);
    if (strlen(text) < n)
        return 0;
    return strncmp(text, prefix, n) == 0;
}

void print_report(const char *label, int value)
{
    printf("%s=%d\n", label, value);
}

/* ------------------------------------------------------------------ */
/* XOR crypto                                                          */
/* ------------------------------------------------------------------ */
void xor_decode_buffer(unsigned char *buf, int len, const char *key)
{
    int klen = (int)strlen(key);
    for (int i = 0; i < len; i++)
        buf[i] ^= key[i % klen];
}

int xor_encrypt_inplace(unsigned char *data, size_t size, unsigned char key)
{
    for (size_t i = 0; i < size; i++)
        data[i] = data[i] ^ key;
    return (int)size;
}

/* ------------------------------------------------------------------ */
/* bitwise                                                             */
/* ------------------------------------------------------------------ */
uint32_t bitfield_pack(uint32_t a, uint32_t b, uint32_t c)
{
    uint32_t out = 0;
    out |= (a & 0xFF);
    out |= (b & 0xFF) << 8;
    out |= (c & 0xFFFF) << 16;
    return out;
}

uint32_t rotl32(uint32_t v, unsigned int n)
{
    n &= 31;
    if (n == 0)
        return v;
    return (v << n) | (v >> (32 - n));
}

uint32_t byteswap32(uint32_t v)
{
    return ((v & 0x000000FFu) << 24) |
           ((v & 0x0000FF00u) << 8) |
           ((v & 0x00FF0000u) >> 8) |
           ((v & 0xFF000000u) >> 24);
}

int count_set_bits(uint32_t v)
{
    int n = 0;
    while (v) {
        v &= (v - 1);
        n++;
    }
    return n;
}

/* ------------------------------------------------------------------ */
/* switch                                                              */
/* ------------------------------------------------------------------ */
int small_switch(int op)
{
    switch (op) {
    case 0: return 10;
    case 1: return 20;
    case 2: return 30;
    default: return -1;
    }
}

/* large enough that a compiler may emit a jump table */
int dispatcher(int op, int a, int b)
{
    switch (op) {
    case 0:  return a + b;
    case 1:  return a - b;
    case 2:  return a * b;
    case 3:  return b ? a / b : 0;
    case 4:  return a & b;
    case 5:  return a | b;
    case 6:  return a ^ b;
    case 7:  return a << 1;
    case 8:  return a >> 1;
    case 9:  return -a;
    case 10: return ~a;
    case 11: return (a > b) ? a : b;
    case 12: return (a < b) ? a : b;
    case 13: return a % (b ? b : 1);
    case 14: return (a * 3) + b;
    case 15: return (a * 5) - b;
    case 16: return (a * 7) ^ b;
    default: return 0;
    }
}

/* ------------------------------------------------------------------ */
/* calls / wrappers / allocation                                       */
/* ------------------------------------------------------------------ */
void *copy_block(void *dst, const void *src, size_t n)
{
    return memcpy(dst, src, n);
}

char *make_buffer(int n)
{
    char *p = (char *)malloc((size_t)n + 1);
    if (p == NULL)
        return NULL;
    memset(p, 0, (size_t)n + 1);
    return p;
}

void destroy_buffer(char *p)
{
    free(p);
}

int validate_range(int value, int lo, int hi)
{
    if (value < lo)
        return 0;
    if (value > hi)
        return 0;
    return 1;
}

/* ------------------------------------------------------------------ */
/* hash (CRC32 style)                                                  */
/* ------------------------------------------------------------------ */
uint32_t crc32_compute(const unsigned char *data, size_t len)
{
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int bit = 0; bit < 8; bit++) {
            if (crc & 1u)
                crc = (crc >> 1) ^ 0xEDB88320u;
            else
                crc >>= 1;
        }
    }
    return ~crc;
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */
int main(int argc, char **argv)
{
    char name[64];
    char greeting[160];
    unsigned char payload[128];
    int numbers[16];

    if (argc > 1) {
        strncpy(name, argv[1], sizeof(name) - 1);
        name[sizeof(name) - 1] = '\0';
    } else {
        snprintf(name, sizeof(name), "world");
    }

    if (build_greeting(greeting, sizeof(greeting), name) < 0)
        return 1;
    print_report("greeting", (int)strlen(greeting));

    memcpy(payload, greeting, strlen(greeting) + 1);
    xor_decode_buffer(payload, (int)strlen(greeting), "s3cr3t");
    print_report("decoded", payload[0]);

    for (int i = 0; i < 16; i++)
        numbers[i] = i * i;
    reverse_array(numbers, 16);
    print_report("sum", sum_pointer_walk(numbers, numbers + 16));

    print_report("arith", arithmetic_mix(argc, 3));
    print_report("class", classify_score(60, 12, 1));
    print_report("early", early_return_guard(name, 0x03));
    print_report("loops", sum_until(50) + count_while(name) +
                          do_while_digits(12345u));
    print_report("prefix", is_prefix(name, "wo"));
    print_report("bits", (int)(bitfield_pack(1, 2, 3) ^ rotl32(0x12345678u, 8) ^
                               byteswap32(0xAABBCCDDu) ^
                               (uint32_t)count_set_bits(0xF0F0u)));
    print_report("sw", small_switch(argc & 3) + dispatcher(argc & 15, 7, 3));
    print_report("crc", (int)crc32_compute((const unsigned char *)name,
                                           strlen(name)));
    print_report("xor", xor_encrypt_inplace(payload, 4, 0x5A));

    char *tmp = make_buffer(32);
    if (tmp) {
        copy_block(tmp, greeting, 8);
        destroy_buffer(tmp);
    }
    print_report("valid", validate_range(argc, 0, 10));
    return 0;
}
