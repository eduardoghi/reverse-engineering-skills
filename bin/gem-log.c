// gcc -shared -fPIC -O1 -o gemlog.so gemlog.c -ldl
// GEMLOG=gem.txt LD_PRELOAD=./gemlog.so ./program
#define _GNU_SOURCE
#include <dlfcn.h>
#include <drm/i915_drm.h>
#include <execinfo.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <time.h>
#include <unistd.h>

static int (*real)(int, unsigned long, ...);
static int out = -1;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

int ioctl(int fd, unsigned long req, ...) {
    va_list ap;
    va_start(ap, req);
    void *arg = va_arg(ap, void *);
    va_end(ap);
    if (!real) real = dlsym(RTLD_NEXT, "ioctl");
    int ret = real(fd, req, arg);
    if (req == DRM_IOCTL_I915_GEM_CREATE_EXT && ret == 0) {
        struct drm_i915_gem_create_ext *c = arg;
        void *frames[32];
        int n = backtrace(frames, 32);
        char head[128], name[32] = "";
        struct timespec t;
        clock_gettime(CLOCK_MONOTONIC, &t);
        prctl(PR_GET_NAME, name);
        int len = snprintf(head, sizeof head, "#GEM %ld %llu %s\n", (long)t.tv_sec,
                           (unsigned long long)c->size, name);
        pthread_mutex_lock(&lock);
        if (out < 0) out = open(getenv("GEMLOG"), O_WRONLY | O_CREAT | O_TRUNC, 0600);
        write(out, head, len);
        backtrace_symbols_fd(frames, n, out);
        pthread_mutex_unlock(&lock);
    }
    return ret;
}
