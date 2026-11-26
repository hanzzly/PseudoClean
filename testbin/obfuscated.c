/* PseudoClean obfuscated test corpus.
 *
 * Hand-written equivalents of common commercial protector transforms.  Each
 * function is intended to be recognisable by the analyzer's *structural*
 * detectors (never by a single constant):
 *
 *   obf_flatten    control-flow flattening via a dispatcher switch loop
 *   obf_mba_add    mixed boolean-arithmetic rewrite of a + b
 *   obf_mba_xor    mixed boolean-arithmetic rewrite of a ^ b
 *   obf_opaque     opaque predicate guarding the real body
 *   obf_strcmp     XOR-encrypted literal comparison
 *   obf_deadcode   unreachable fake-crypto decoy branch
 *   obf_indirect   indirect call through a function pointer
 *   obf_nested     deeply nested loops with early exits
 *
 * Build:
 *   gcc -O0 -o obfuscated_O0.bin obfuscated.c
 *   strip -o obfuscated_stripped.bin obfuscated_O0.bin
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ------------------------------------------------------------------ */
/* control-flow flattening                                             */
/* ------------------------------------------------------------------ */
int obf_flatten(int x)
{
    int state = 0;
    int acc = 0;
    for (;;) {
        switch (state) {
        case 0:
            acc = x + 1;
            state = (x & 1) ? 1 : 2;
            break;
        case 1:
            acc = acc * 3;
            state = 3;
            break;
        case 2:
            acc = acc - 5;
            state = (acc > 0) ? 1 : 3;
            break;
        case 3:
            acc ^= 0x55;
            state = 4;
            break;
        case 4:
            return acc;
        default:
            return -1;
        }
    }
}

/* ------------------------------------------------------------------ */
/* mixed boolean-arithmetic                                            */
/* ------------------------------------------------------------------ */
int obf_mba_add(int a, int b)
{
    /* a + b == (a ^ b) + 2 * (a & b) */
    return (a ^ b) + 2 * (a & b);
}

int obf_mba_xor(int a, int b)
{
    /* a ^ b == (a | b) - (a & b) */
    return (a | b) - (a & b);
}

int obf_mba_sub(int a, int b)
{
    /* a - b == (a ^ -1) + b + 1 */
    return (~a) + b + 1;
}

/* ------------------------------------------------------------------ */
/* opaque predicate                                                    */
/* ------------------------------------------------------------------ */
int obf_opaque(int x)
{
    /* (x*x) & 1 is always equal to (x & 1) * (x & 1): always true */
    if ((((x * x) & 1) == ((x & 1) * (x & 1)))) {
        if (x > 1000)
            return x / 2;
        if (x > 100)
            return x / 3;
        return x + 7;
    }
    /* dead code: never reached */
    {
        unsigned char junk[8];
        memset(junk, 0, sizeof(junk));
        for (int i = 0; i < 8; i++)
            junk[i] ^= (unsigned char)(x >> i);
        return (int)junk[0];
    }
}

/* ------------------------------------------------------------------ */
/* XOR-encrypted literal comparison                                    */
/* ------------------------------------------------------------------ */
static void obf_decrypt(char *dst, const unsigned char *src, size_t n,
                        unsigned char key)
{
    for (size_t i = 0; i < n; i++)
        dst[i] = (char)(src[i] ^ key);
}

int obf_strcmp(const char *user)
{
    /* "secret" ^ 0x5A */
    static const unsigned char enc[] = { 0x29, 0x3F, 0x39, 0x28, 0x3F, 0x36,
                                        0x00 };
    char plain[8];
    obf_decrypt(plain, enc, sizeof(plain) - 1, 0x5A);
    plain[sizeof(plain) - 1] = '\0';
    if (user == NULL)
        return 0;
    return strcmp(user, plain) == 0;
}

/* ------------------------------------------------------------------ */
/* dead-code decoy                                                     */
/* ------------------------------------------------------------------ */
int obf_deadcode(int x)
{
    if (x == x + 1) {                 /* statically false */
        unsigned int crc = 0xFFFFFFFFu;
        const unsigned char *data = (const unsigned char *)&x;
        for (int i = 0; i < 4; i++) {
            crc ^= data[i];
            for (int b = 0; b < 8; b++)
                crc = (crc & 1) ? ((crc >> 1) ^ 0xEDB88320u) : (crc >> 1);
        }
        return (int)~crc;
    }
    return x * 2;
}

/* ------------------------------------------------------------------ */
/* indirect call                                                       */
/* ------------------------------------------------------------------ */
typedef int (*binop_fn)(int, int);

static int add_impl(int a, int b) { return a + b; }
static int mul_impl(int a, int b) { return a * b; }

int obf_indirect(int which, int a, int b)
{
    binop_fn fn = (which & 1) ? mul_impl : add_impl;
    return fn(a, b);
}

/* ------------------------------------------------------------------ */
/* nested loops with early exits                                       */
/* ------------------------------------------------------------------ */
int obf_nested(int bound)
{
    int found = -1;
    for (int i = 0; i < bound; i++) {
        for (int j = 0; j < bound; j++) {
            if ((i ^ j) == 0x2A) {
                found = i;
                goto done;
            }
            if (i * j > 4096)
                break;
        }
        if (i > 100)
            continue;
    }
done:
    return found;
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */
int main(int argc, char **argv)
{
    const char *input = (argc > 1) ? argv[1] : "secret";
    printf("flatten=%d\n", obf_flatten(argc));
    printf("mba=%d\n", obf_mba_add(argc, 7) + obf_mba_xor(argc, 3) +
                          obf_mba_sub(argc, 1));
    printf("opaque=%d\n", obf_opaque(argc * 3));
    printf("strcmp=%d\n", obf_strcmp(input));
    printf("dead=%d\n", obf_deadcode(argc));
    printf("indirect=%d\n", obf_indirect(argc, 4, 5));
    printf("nested=%d\n", obf_nested(64));
    return 0;
}
