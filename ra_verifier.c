#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <tee_client_api.h>
#include <fTPM.h>

#include <mbedtls/x509_crt.h>
#include <mbedtls/x509_csr.h>
#include <mbedtls/oid.h>
#include <mbedtls/md.h>
#include <mbedtls/error.h>

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
     * Prepare the argument. Pass a value in the first parameter,
     * receive a value in the second parameter.
     */
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
        printf("TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
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
    // TODO: Maybe third output parameter, where we return the count of certificates
    // I.e., split the count parameter from the 'sizes' parameter
    // But don't do it know, since maybe we need more Input parameters,
    // e.g., Nonce, or configuration parameters
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

    char name_bl1[50];
    mbedtls_x509_crt crt_ctx;
    mbedtls_x509_crt_init(&crt_ctx);

    invoke_ftpm_ta(buffer_crts, sizeof(buffer_crts),
                   buffer_offsets, sizeof(buffer_offsets));

    parse_buffers(buffer_crts, sizeof(buffer_crts),
                  buffer_offsets, sizeof(buffer_offsets), &crt_ctx);

    mbedtls_x509_dn_gets(name_bl1, sizeof(name_bl1), &crt_ctx.issuer);
    mbedtls_x509_crt_free(&crt_ctx);

    printf("Issuer of BL1: %s\n", name_bl1);
    printf("Certificate chain length: %d\n", buffer_offsets[0]);

    return 0;
}
