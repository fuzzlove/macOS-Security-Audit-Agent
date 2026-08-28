#ifndef MSAA_AR_CONTAINMENT_BOUNDARY_H
#define MSAA_AR_CONTAINMENT_BOUNDARY_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#define MSAA_AR_PATH_MAX 4096
#define MSAA_AR_SHA256_HEX 65

typedef enum {
    MSAA_AR_ACTION_PAUSE = 1,
    MSAA_AR_ACTION_RESUME = 2,
    MSAA_AR_ACTION_TERMINATE = 3
} msaa_ar_native_action_t;

typedef enum {
    MSAA_AR_CONTAINMENT_OK = 0,
    MSAA_AR_CONTAINMENT_INVALID = 1,
    MSAA_AR_CONTAINMENT_NOT_FOUND = 2,
    MSAA_AR_CONTAINMENT_IDENTITY_MISMATCH = 3,
    MSAA_AR_CONTAINMENT_CRITICAL = 4,
    MSAA_AR_CONTAINMENT_SIGNAL_FAILED = 5,
    MSAA_AR_CONTAINMENT_VERIFY_FAILED = 6
} msaa_ar_containment_result_t;

typedef struct {
    pid_t pid;
    int pid_version;
    uid_t effective_uid;
    uint64_t start_seconds;
    uint64_t start_microseconds;
    uint64_t device;
    uint64_t inode;
    char executable_path[MSAA_AR_PATH_MAX];
    char executable_sha256[MSAA_AR_SHA256_HEX];
} msaa_ar_process_identity_t;

bool msaa_ar_capture_process_identity(pid_t pid, int trusted_pid_version, msaa_ar_process_identity_t *identity);
bool msaa_ar_revalidate_process_identity(const msaa_ar_process_identity_t *expected);
msaa_ar_containment_result_t msaa_ar_apply_exact_action(const msaa_ar_process_identity_t *expected, msaa_ar_native_action_t action);

#endif
