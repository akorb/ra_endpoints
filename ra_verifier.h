#ifndef RA_VERIFIER_H
#define RA_VERIFIER_H

#define ARRAY_LEN(array) (sizeof(array) / sizeof(array[0]))

typedef struct {
    const char name[8];
    const char certFilename[10];
    const unsigned char *expectedTci;
} chain_t;

#define CHAIN_ENTRY(bl) \
    { \
        .name = #bl, \
        .certFilename=#bl".crt", \
        .expectedTci = tci_ ## bl, \
    }

#define CHAIN_ENTRY_WITHOUT_TCI(bl) \
    { \
        .name = #bl, \
        .certFilename=#bl".crt", \
        .expectedTci = NULL, \
    }

#define PEM_BEGIN_CRT           "-----BEGIN CERTIFICATE-----\n"
#define PEM_END_CRT             "-----END CERTIFICATE-----\n"

#define SHA256_LEN (256 / 8)

#endif /* RA_VERIFIER_H */
