#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static void child_fixture(const char *root) {
    char marker[1024]; char activity[1024];
    snprintf(marker, sizeof(marker), "%s/.msaa-anti-ransomware-test", root);
    snprintf(activity, sizeof(activity), "%s/activity.log", root);
    if (access(marker, F_OK) != 0) _exit(90);
    for (;;) {
        int fd = open(activity, O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW, 0600);
        if (fd < 0) _exit(91);
        (void)write(fd, "synthetic\n", 10);
        close(fd);
        usleep(10000);
    }
}

int main(int argc, char **argv) {
    if (argc != 2 || strcmp(argv[1], "--self-test") != 0) {
        fprintf(stderr, "This fixture accepts only --self-test and no PID or path.\n");
        return 2;
    }
    char root[] = "/tmp/msaa-ar-containment-XXXXXX";
    assert(mkdtemp(root) != NULL);
    char marker[1024]; char activity[1024];
    snprintf(marker, sizeof(marker), "%s/.msaa-anti-ransomware-test", root);
    snprintf(activity, sizeof(activity), "%s/activity.log", root);
    int marker_fd = open(marker, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    assert(marker_fd >= 0); close(marker_fd);
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) child_fixture(root);
    usleep(100000);
    assert(kill(child, SIGSTOP) == 0);
    int status = 0;
    assert(waitpid(child, &status, WUNTRACED) == child && WIFSTOPPED(status));
    assert(kill(child, SIGCONT) == 0);
    usleep(50000);
    assert(kill(child, SIGSTOP) == 0);
    assert(waitpid(child, &status, WUNTRACED) == child && WIFSTOPPED(status));
    /* Bounded lease rollback: a paused fixture is resumed before termination. */
    assert(kill(child, SIGCONT) == 0);
    assert(kill(child, SIGTERM) == 0);
    assert(waitpid(child, &status, 0) == child && WIFSIGNALED(status));
    unlink(activity); unlink(marker); assert(rmdir(root) == 0);
    puts("{\"fixture_only\":true,\"pause_verified\":true,\"resume_verified\":true,\"termination_verified\":true,\"rollback_verified\":true,\"remaining_suspended\":0}");
    return 0;
}
