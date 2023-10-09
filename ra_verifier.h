#ifndef RA_VERIFIER_H
#define RA_VERIFIER_H

#define ARRAY_LEN(array) (sizeof((array)) / sizeof((array)[0]))

/**
 * `name` is only used for debugging purposes.
 * `certFilename` is used to store the received certificates onto the hard disk.
 */
typedef struct
{
    const char name[8];
    const char certFilename[10];
} chain_t;

#define CHAIN_ENTRY(bl_name, crt_name) \
    {                                  \
        .name = bl_name,               \
        .certFilename = crt_name,      \
    }

#define PEM_BEGIN_CRT "-----BEGIN CERTIFICATE-----\n"
#define PEM_END_CRT "-----END CERTIFICATE-----\n"

#define SHA256_LEN (256 / 8)

#define flush_stdin() while (getchar() != '\n')

#endif /* RA_VERIFIER_H */
