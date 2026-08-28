#include "containment_boundary.h"

#include <CommonCrypto/CommonDigest.h>
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/proc_info.h>
#include <sys/proc.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static bool sha256_file(const char *path, char output[MSAA_AR_SHA256_HEX]) {
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    CC_SHA256_CTX context;
    CC_SHA256_Init(&context);
    unsigned char buffer[16384];
    ssize_t length;
    while ((length = read(fd, buffer, sizeof(buffer))) > 0) {
        CC_SHA256_Update(&context, buffer, (CC_LONG)length);
    }
    int saved = errno;
    close(fd);
    if (length < 0) { errno = saved; return false; }
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_Final(digest, &context);
    for (size_t index = 0; index < sizeof(digest); index++) {
        snprintf(output + index * 2, 3, "%02x", digest[index]);
    }
    output[64] = '\0';
    return true;
}

static bool critical_identity(const msaa_ar_process_identity_t *identity) {
    if (identity->pid <= 1 || identity->pid == getpid()) return true;
    const char *path = identity->executable_path;
    return strcmp(path, "/sbin/launchd") == 0 || strcmp(path, "/usr/libexec/logind") == 0 ||
           strstr(path, "MacAuditAgent") != NULL || strstr(path, "VoiceOver") != NULL;
}

static bool wait_for_state(pid_t pid, uint32_t desired, bool invert) {
    const struct timespec delay = {.tv_sec = 0, .tv_nsec = 2000000};
    for (unsigned attempt = 0; attempt < 100; attempt++) {
        struct proc_bsdinfo info;
        int size = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info));
        if (size != sizeof(info)) return desired == SZOMB;
        bool matches = info.pbi_status == desired;
        if (invert ? !matches : matches) return true;
        nanosleep(&delay, NULL);
    }
    return false;
}

bool msaa_ar_capture_process_identity(pid_t pid, int trusted_pid_version, msaa_ar_process_identity_t *identity) {
    if (pid <= 1 || trusted_pid_version < 0 || identity == NULL) return false;
    memset(identity, 0, sizeof(*identity));
    struct proc_bsdinfo info;
    if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info)) != sizeof(info)) return false;
    int path_length = proc_pidpath(pid, identity->executable_path, sizeof(identity->executable_path));
    if (path_length <= 0 || (size_t)path_length >= sizeof(identity->executable_path)) return false;
    struct stat status;
    if (lstat(identity->executable_path, &status) != 0 || !S_ISREG(status.st_mode)) return false;
    if (!sha256_file(identity->executable_path, identity->executable_sha256)) return false;
    identity->pid = pid;
    identity->pid_version = trusted_pid_version;
    identity->effective_uid = info.pbi_uid;
    identity->start_seconds = info.pbi_start_tvsec;
    identity->start_microseconds = info.pbi_start_tvusec;
    identity->device = (uint64_t)status.st_dev;
    identity->inode = (uint64_t)status.st_ino;
    return true;
}

bool msaa_ar_revalidate_process_identity(const msaa_ar_process_identity_t *expected) {
    if (expected == NULL || expected->pid_version < 0 || expected->executable_sha256[0] == '\0') return false;
    msaa_ar_process_identity_t live;
    if (!msaa_ar_capture_process_identity(expected->pid, expected->pid_version, &live)) return false;
    return live.pid == expected->pid && live.pid_version == expected->pid_version &&
           live.effective_uid == expected->effective_uid && live.start_seconds == expected->start_seconds &&
           live.start_microseconds == expected->start_microseconds && live.device == expected->device &&
           live.inode == expected->inode && strcmp(live.executable_path, expected->executable_path) == 0 &&
           strcmp(live.executable_sha256, expected->executable_sha256) == 0;
}

msaa_ar_containment_result_t msaa_ar_apply_exact_action(const msaa_ar_process_identity_t *expected, msaa_ar_native_action_t action) {
    if (expected == NULL || (action != MSAA_AR_ACTION_PAUSE && action != MSAA_AR_ACTION_RESUME && action != MSAA_AR_ACTION_TERMINATE)) return MSAA_AR_CONTAINMENT_INVALID;
    if (critical_identity(expected)) return MSAA_AR_CONTAINMENT_CRITICAL;
    if (!msaa_ar_revalidate_process_identity(expected)) return kill(expected->pid, 0) == 0 ? MSAA_AR_CONTAINMENT_IDENTITY_MISMATCH : MSAA_AR_CONTAINMENT_NOT_FOUND;
    int signal_number = action == MSAA_AR_ACTION_PAUSE ? SIGSTOP : action == MSAA_AR_ACTION_RESUME ? SIGCONT : SIGTERM;
    if (kill(expected->pid, signal_number) != 0) return MSAA_AR_CONTAINMENT_SIGNAL_FAILED;
    bool state_verified = action == MSAA_AR_ACTION_PAUSE ? wait_for_state(expected->pid, SSTOP, false) :
                          action == MSAA_AR_ACTION_RESUME ? wait_for_state(expected->pid, SSTOP, true) :
                          wait_for_state(expected->pid, SZOMB, false);
    if (!state_verified) return MSAA_AR_CONTAINMENT_VERIFY_FAILED;
    if (action == MSAA_AR_ACTION_TERMINATE) return MSAA_AR_CONTAINMENT_OK;
    /* Revalidate after state verification so a reused PID cannot be treated as success. */
    return msaa_ar_revalidate_process_identity(expected) ? MSAA_AR_CONTAINMENT_OK : MSAA_AR_CONTAINMENT_VERIFY_FAILED;
}
