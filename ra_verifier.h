#ifndef RA_VERIFIER_H
#define RA_VERIFIER_H

#define ARRAY_LEN(array) (sizeof(array) / sizeof(array[0]))

/**
 * `name` is only used for debugging purposes.
 * `certFilename` is used to store the received certificate from the SW onto the hard disk.
 * `expectedTci` is the TCI we consider as trustworty.
 */
typedef struct {
    const char name[8];
    const char certFilename[10];
    const unsigned char *expectedTci;
} chain_t;

#define CHAIN_ENTRY(bl, tci) \
    { \
        .name = #bl, \
        .certFilename=#bl".crt", \
        .expectedTci = tci, \
    }

#define PEM_BEGIN_CRT           "-----BEGIN CERTIFICATE-----\n"
#define PEM_END_CRT             "-----END CERTIFICATE-----\n"

#define SHA256_LEN (256 / 8)

#endif /* RA_VERIFIER_H */
