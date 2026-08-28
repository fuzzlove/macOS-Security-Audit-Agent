#ifndef MSAA_AR_IPC_PEER_AUTH_H
#define MSAA_AR_IPC_PEER_AUTH_H

#include <mach/message.h>
#include <stdbool.h>

typedef enum {
    MSAA_AR_PEER_AUTH_OK = 0,
    MSAA_AR_PEER_AUTH_INVALID_ARGUMENT = 1,
    MSAA_AR_PEER_AUTH_CODE_LOOKUP_FAILED = 2,
    MSAA_AR_PEER_AUTH_SIGNATURE_INVALID = 3,
    MSAA_AR_PEER_AUTH_REQUIREMENT_INVALID = 4,
    MSAA_AR_PEER_AUTH_TEAM_MISMATCH = 5,
    MSAA_AR_PEER_AUTH_IDENTIFIER_MISMATCH = 6,
    MSAA_AR_PEER_AUTH_AD_HOC_REJECTED = 7
} msaa_ar_peer_auth_result_t;

msaa_ar_peer_auth_result_t msaa_ar_authenticate_audit_token(
    audit_token_t token,
    const char *expected_team_id,
    const char *expected_signing_id,
    const char *designated_requirement,
    bool production_mode
);

#endif
