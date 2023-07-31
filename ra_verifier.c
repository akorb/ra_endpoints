#include <stdio.h>
#include <string.h>

#include <tee_client_api.h>
#include <fTPM.h>

static const TEEC_UUID ftpmTEEApp = TA_FTPM_UUID;

int main(void)
{
    /* Allocate TEE Client structures on the stack. */
    TEEC_Context context;
    TEEC_Session session;
    TEEC_Operation operation;
    TEEC_Result result;
    uint32_t err_origin;
    uint8_t out_str[50];
    uint8_t in_str[] = "to the TEE";

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
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE, TEEC_NONE);
    operation.params[0].tmpref.buffer = in_str;
    operation.params[0].tmpref.size = sizeof(in_str);

    operation.params[1].tmpref.buffer = out_str;
    operation.params[1].tmpref.size = sizeof(out_str);

    printf("Invoking TA to generate Hello World string... \n");
    result = TEEC_InvokeCommand(&session, TA_FTPM_HELLO_WORLD,
                                &operation, &err_origin);
    if (result != TEEC_SUCCESS)
    {
        printf("TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
             result, err_origin);
        goto cleanup3;
    }

    printf("%s\n", out_str);

    /*
     * We're done with the TA, close the session and
     * destroy the context.
     *
     * The TA will print "Goodbye!" in the log when the
     * session is closed.
     */

cleanup3:
    TEEC_CloseSession(&session);
cleanup2:
    TEEC_FinalizeContext(&context);
cleanup1:
    return result;
}
