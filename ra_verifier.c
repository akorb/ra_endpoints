#include <stdio.h>
#include <string.h>

#include <tee_client_api.h>
#include <fTPM.h>

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

int main(void)
{
    // The certificates are stored here in DER format
    // For our certificates, they are always a bit smaller than 1000 bytes.
    // We expect a certificate chain of length 5.
    // Go give a 5 * 1000 bytes buffer
    uint8_t buffer_crts[5000];

    // first element is length of chain
    // Array size must be at least length of chain + 1
    uint16_t buffer_offsets[8];

    invoke_ftpm_ta(buffer_crts, sizeof(buffer_crts),
                   buffer_offsets, sizeof(buffer_offsets));

    printf("Certificate chain length: %d\n", buffer_offsets[0]);

    return 0;
}
