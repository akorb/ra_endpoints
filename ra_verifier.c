#include <assert.h>
#include <err.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <ra_verifier.h>

#include <tee_client_api.h>
#include <fTPM.h>

#include <mbedtls/x509_crt.h>
#include <mbedtls/oid.h>
#include <mbedtls/md.h>
#include <mbedtls/error.h>
#include <mbedtls/pem.h>

static const char out_filenames[][10] = {
    "bl1.crt",
    "bl2.crt",
    "bl31.crt",
    "bl32.crt",
    "ekcert.crt"};

static const TEEC_UUID ftpmTEEApp = TA_FTPM_UUID;

static TEEC_Result invoke_ftpm_ta(uint8_t *buffer_crts, size_t buffer_crts_len,
                                  uint16_t *buffer_offsets, size_t buffer_offsets_len)
{
    /* Allocate TEE Client structures on the stack. */
    TEEC_Context context;
    TEEC_Session session;
    TEEC_Operation operation;
    TEEC_Result result;
    uint32_t err_origin;

    /* ========================================================================
    [1] Connect to TEE
    ======================================================================== */
    result = TEEC_InitializeContext(
        NULL,
        &context);
    if (result != TEEC_SUCCESS)
    {
        goto cleanup1;
    }
    /* ========================================================================
    [2] Open session with TEE application
    ======================================================================== */
    /* Open a Session with the TEE application. */
    result = TEEC_OpenSession(
        &context,
        &session,
        &ftpmTEEApp,
        TEEC_LOGIN_PUBLIC,
        NULL, /* No connection data needed for TEEC_LOGIN_PUBLIC. */
        NULL, /* No payload, and do not want cancellation. */
        &err_origin);
    if (result != TEEC_SUCCESS)
    {
        goto cleanup2;
    }

    /* Clear the TEEC_Operation struct */
    memset(&operation, 0, sizeof(operation));

    /*
     * Prepare the arguments.
     */

    // TODO: Maybe third output parameter, where we return the count of certificates
    // I.e., split the count parameter from the 'sizes' parameter
    // But don't do it know, since maybe we need more Input parameters,
    // e.g., Nonce, or configuration parameters
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_MEMREF_TEMP_OUTPUT,
                                            TEEC_NONE, TEEC_NONE);
    operation.params[0].tmpref.buffer = buffer_crts;
    operation.params[0].tmpref.size = buffer_crts_len;

    operation.params[1].tmpref.buffer = buffer_offsets;
    operation.params[1].tmpref.size = buffer_offsets_len;

    printf("Invoking fTPM TA to attest itself... \n");
    result = TEEC_InvokeCommand(&session, TA_FTPM_ATTEST,
                                &operation, &err_origin);
    if (result != TEEC_SUCCESS)
    {
        printf("TEEC_InvokeCommand failed with code 0x%x origin 0x%x\n",
               result, err_origin);
        goto cleanup3;
    }

    /*
     * We're done with the TA, close the session and
     * destroy the context.
     */

cleanup3:
    TEEC_CloseSession(&session);
cleanup2:
    TEEC_FinalizeContext(&context);
cleanup1:
    return result;
}

static int parse_buffers(const uint8_t *buffer_crts, const size_t buffer_crts_len,
                         const uint16_t *buffer_sizes, const size_t buffer_sizes_len,
                         mbedtls_x509_crt *crt_ctx)
{
    int res;
    char buf[256];
    int certificate_count = buffer_sizes[0];

    const uint16_t *sizes = &buffer_sizes[1];
    const uint8_t *cur_crt = buffer_crts;

    for (int i = 0; i < certificate_count; i++)
    {
        assert(&sizes[i] + sizeof(sizes[0]) < &buffer_sizes[buffer_sizes_len]);
        assert(cur_crt + sizes[i] < &buffer_crts[buffer_crts_len]);

        res = mbedtls_x509_crt_parse(crt_ctx, cur_crt, sizes[i]);
        if (res != 0)
        {
            mbedtls_strerror(res, buf, 256);
            printf(" parsing crt_bl1 failed\n  !  mbedtls_x509_crt_parse returned -0x%x - %s\n",
                   (unsigned int)-res, buf);
            return 1;
        }

        cur_crt += sizes[i];
    }

    return 0;
}

static int write_certificates(mbedtls_x509_crt *crt_ctx)
{
    uint8_t file_buffer[2048];
    size_t olen;

    const int count_available_names = sizeof(out_filenames) / sizeof(out_filenames[0]);

    for (int i = 0; crt_ctx != NULL; crt_ctx = crt_ctx->next, i++)
    {
        if (!(i < count_available_names))
            errx(EXIT_FAILURE, "We try to write more certificates than we have filenames available\ni=%d, Available names count=%d", i, count_available_names);

        mbedtls_pem_write_buffer(PEM_BEGIN_CRT, PEM_END_CRT,
                                 crt_ctx->raw.p, crt_ctx->raw.len,
                                 file_buffer, sizeof(file_buffer),
                                 &olen);

        FILE *pem_file = fopen(out_filenames[i], "wb");
        // - 1 to trim the null terminator
        // This ensures the exact same content as the certificate is embedded in the attestation PTA,
        // and how it is written here.
        fwrite(file_buffer, 1, olen - 1, pem_file);
        fclose(pem_file);
    }

    return 0;
}

static int print_subjects_of_certificates(mbedtls_x509_crt *crt_ctx)
{
    char subject[50];
    for (int i = 0; crt_ctx != NULL; crt_ctx = crt_ctx->next, i++)
    {
        mbedtls_x509_dn_gets(subject, sizeof(subject), &crt_ctx->subject);
        printf("Cert [%d]: %s\n", i, subject);
    }

    return 0;
}

static int verify(mbedtls_x509_crt *chain)
{
    // From https://stackoverflow.com/a/72722115/2050020

    uint32_t flags = 0;

    int res;
    char buf[256];

    mbedtls_x509_crt ca;
    mbedtls_x509_crt_init(&ca);
    res = mbedtls_x509_crt_parse(&ca, crt_manufacturer, sizeof(crt_manufacturer));
    if (res != 0)
    {
        mbedtls_strerror(res, buf, 256);
        printf(" parsing crt_manufacturer failed\n  !  mbedtls_x509_crt_parse returned -0x%x - %s\n",
               (unsigned int)-res, buf);
    }

    if ((res = mbedtls_x509_crt_verify(chain, &ca, NULL, NULL, &flags,
                                     NULL, NULL)) != 0)
    {
        char vrfy_buf[512];
        printf("Verification failed\n");
        mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);
        printf("%s\n", vrfy_buf);
        printf("Error: 0x%04x; flag: %u\n", res, flags);
    }
    else
        printf("Verification OK\n");
    
    mbedtls_x509_crt_free(&ca);
    return res;
}

int main(void)
{
    // The certificates are stored here in DER format
    // For our certificates, they are always a bit smaller than 1000 bytes.
    // We expect a certificate chain of length 5.
    // So, give a 5 * 1000 bytes buffer
    uint8_t buffer_crts[5000];

    // first element is length of chain
    // Array size must be at least length of chain + 1
    uint16_t buffer_offsets[8];

    mbedtls_x509_crt crt_ctx;
    mbedtls_x509_crt_init(&crt_ctx);

    invoke_ftpm_ta(buffer_crts, sizeof(buffer_crts),
                   buffer_offsets, sizeof(buffer_offsets));

    parse_buffers(buffer_crts, sizeof(buffer_crts),
                  buffer_offsets, sizeof(buffer_offsets), &crt_ctx);

    print_subjects_of_certificates(&crt_ctx);
    write_certificates(&crt_ctx);
    verify(&crt_ctx);
    mbedtls_x509_crt_free(&crt_ctx);

    printf("Certificate chain length: %d\n", buffer_offsets[0]);

    return 0;
}
