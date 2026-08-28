#include "../containment_boundary.h"

#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static void fixture_child(void) {
    for (;;) pause();
}

int main(void) {
    msaa_ar_process_identity_t self;
    assert(msaa_ar_capture_process_identity(getpid(), 1, &self));
    assert(msaa_ar_apply_exact_action(&self, MSAA_AR_ACTION_PAUSE) == MSAA_AR_CONTAINMENT_CRITICAL);

    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) fixture_child();
    usleep(50000);
    msaa_ar_process_identity_t expected;
    assert(msaa_ar_capture_process_identity(child, 7, &expected));
    assert(msaa_ar_revalidate_process_identity(&expected));
    msaa_ar_process_identity_t changed = expected;
    changed.start_microseconds += 1;
    assert(!msaa_ar_revalidate_process_identity(&changed));
    assert(msaa_ar_apply_exact_action(&expected, MSAA_AR_ACTION_PAUSE) == MSAA_AR_CONTAINMENT_OK);
    int status = 0;
    assert(waitpid(child, &status, WUNTRACED) == child && WIFSTOPPED(status));
    assert(msaa_ar_apply_exact_action(&expected, MSAA_AR_ACTION_RESUME) == MSAA_AR_CONTAINMENT_OK);
    assert(msaa_ar_apply_exact_action(&expected, MSAA_AR_ACTION_TERMINATE) == MSAA_AR_CONTAINMENT_OK);
    assert(waitpid(child, &status, 0) == child && WIFSIGNALED(status));
    assert(!msaa_ar_revalidate_process_identity(&expected));
    puts("containment_boundary: identity, pause, resume, terminate, critical refusal passed");
    return 0;
}
