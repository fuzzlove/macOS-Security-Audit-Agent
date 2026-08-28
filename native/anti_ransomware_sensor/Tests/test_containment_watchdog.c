#include "../containment_watchdog.h"

#include <assert.h>
#include <stdio.h>

static unsigned resumes = 0;
static msaa_ar_containment_result_t resume_ok(const msaa_ar_process_identity_t *identity, msaa_ar_native_action_t action) {
    assert(identity->pid == 42 && action == MSAA_AR_ACTION_RESUME); resumes += 1; return MSAA_AR_CONTAINMENT_OK;
}

int main(void) {
    msaa_ar_watchdog_t watchdog; msaa_ar_watchdog_init(&watchdog);
    msaa_ar_process_identity_t identity = {.pid = 42, .pid_version = 3};
    assert(msaa_ar_watchdog_add(&watchdog, "lease-1", &identity, 100));
    msaa_ar_watchdog_tick(&watchdog, 99, resume_ok);
    assert(resumes == 0 && watchdog.active == 1);
    msaa_ar_watchdog_tick(&watchdog, 100, resume_ok);
    assert(resumes == 1 && watchdog.active == 0 && watchdog.rollbacks == 1 && watchdog.failures == 0);
    msaa_ar_watchdog_tick(&watchdog, 200, resume_ok);
    assert(resumes == 1);
    puts("containment_watchdog: bounded expiry rollback passed");
    return 0;
}
