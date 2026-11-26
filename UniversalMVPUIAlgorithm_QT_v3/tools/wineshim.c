/*
 * wineshim.c — rootless Wine için LD_PRELOAD yol-yönlendirme shim'i
 *
 * Debian wine64/wineserver64 ikilileri /usr/share/wine ve /usr/lib/wine
 * mutlak yollarını gömülü olarak arar. Root yoksa bu yollar oluşamaz.
 * Bu shim, open/openat/stat/access/execve/fopen çağrılarında bu ön ekleri
 * kullanıcı alanındaki wine_root ağacına yönlendirir.
 *
 * Derleme: gcc -shared -fPIC -O2 -o wineshim.so wineshim.c -ldl
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>

#define WINE_ROOT "/home/z/my-project/vmprotect/wine_root"

static const char *rewrite(const char *path, char *buf, size_t bufsz)
{
    if (!path) return path;
    if (strncmp(path, "/usr/share/wine", 15) == 0) {
        snprintf(buf, bufsz, "%s%s", WINE_ROOT "/usr/share/wine", path + 15);
        return buf;
    }
    if (strncmp(path, "/usr/lib/wine", 13) == 0) {
        snprintf(buf, bufsz, "%s%s", WINE_ROOT "/usr/lib/wine", path + 13);
        return buf;
    }
    if (strncmp(path, "/usr/lib/x86_64-linux-gnu/wine", 30) == 0) {
        snprintf(buf, bufsz, "%s%s", WINE_ROOT "/usr/lib/x86_64-linux-gnu/wine", path + 30);
        return buf;
    }
    return path;
}

/* --- open --- */
int open(const char *path, int flags, ...)
{
    static int (*real_open)(const char *, int, ...);
    if (!real_open) real_open = dlsym(RTLD_NEXT, "open");
    char buf[4096];
    const char *p = rewrite(path, buf, sizeof(buf));
    mode_t mode = 0;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list ap; va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    return real_open(p, flags, mode);
}

/* --- openat --- */
int openat(int dirfd, const char *path, int flags, ...)
{
    static int (*real_openat)(int, const char *, int, ...);
    if (!real_openat) real_openat = dlsym(RTLD_NEXT, "openat");
    char buf[4096];
    const char *p = rewrite(path, buf, sizeof(buf));
    mode_t mode = 0;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list ap; va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    return real_openat(dirfd, p, flags, mode);
}

/* --- fopen / fopen64 --- */
FILE *fopen(const char *path, const char *mode)
{
    static FILE *(*real_fopen)(const char *, const char *);
    if (!real_fopen) real_fopen = dlsym(RTLD_NEXT, "fopen");
    char buf[4096];
    const char *p = rewrite(path, buf, sizeof(buf));
    return real_fopen(p, mode);
}

FILE *fopen64(const char *path, const char *mode)
{
    static FILE *(*real_fopen64)(const char *, const char *);
    if (!real_fopen64) real_fopen64 = dlsym(RTLD_NEXT, "fopen64");
    char buf[4096];
    const char *p = rewrite(path, buf, sizeof(buf));
    return real_fopen64(p, mode);
}

/* --- stat ailesi --- */
int stat(const char *path, struct stat *st)
{
    static int (*real_stat)(const char *, struct stat *);
    if (!real_stat) real_stat = dlsym(RTLD_NEXT, "stat");
    char buf[4096];
    const char *p = rewrite(path, buf, sizeof(buf));
    return real_stat(p, st);
}

int stat64(const char *path, struct stat64 *st)
{
    static int (*real_stat64)(const char *, struct stat64 *);
    if (!real_stat64) real_stat64 = dlsym(RTLD_NEXT, "stat64");
    char buf[4096];
    const char *p = rewrite(path, buf, sizeof(buf));
    return real_stat64(p, st);
}

int __xstat(int ver, const char *path, struct stat *st)
{
    static int (*real_xstat)(int, const char *, struct stat *);
    if (!real_xstat) real_xstat = dlsym(RTLD_NEXT, "__xstat");
    char buf[4096];
    const char *p = rewrite(path, buf, sizeof(buf));
    return real_xstat(ver, p, st);
}

int __xstat64(int ver, const char *path, struct stat64 *st)
{
    static int (*real_xstat64)(int, const char *, struct stat64 *);
    if (!real_xstat64) real_xstat64 = dlsym(RTLD_NEXT, "__xstat64");
    char buf[4096];
    const char *p = rewrite(path, buf, sizeof(buf));
    return real_xstat64(ver, p, st);
}

int __lxstat(int ver, const char *path, struct stat *st)
{
    static int (*real_lxstat)(int, const char *, struct stat *);
    if (!real_lxstat) real_lxstat = dlsym(RTLD_NEXT, "__lxstat");
    char buf[4096];
    const char *p = rewrite(path, buf, sizeof(buf));
    return real_lxstat(ver, p, st);
}

int __fxstatat(int ver, int dirfd, const char *path, struct stat *st, int flags)
{
    static int (*real_fxstatat)(int, int, const char *, struct stat *, int);
    if (!real_fxstatat) real_fxstatat = dlsym(RTLD_NEXT, "__fxstatat");
    char buf[4096];
    const char *p = rewrite(path, buf, sizeof(buf));
    return real_fxstatat(ver, dirfd, p, st, flags);
}

/* --- access --- */
int access(const char *path, int mode)
{
    static int (*real_access)(const char *, int);
    if (!real_access) real_access = dlsym(RTLD_NEXT, "access");
    char buf[4096];
    const char *p = rewrite(path, buf, sizeof(buf));
    return real_access(p, mode);
}

/* --- execve (wineserver betiği vb.) --- */
int execve(const char *path, char *const argv[], char *const envp[])
{
    static int (*real_execve)(const char *, char *const [], char *const []);
    if (!real_execve) real_execve = dlsym(RTLD_NEXT, "execve");
    char buf[4096];
    const char *p = rewrite(path, buf, sizeof(buf));
    return real_execve(p, argv, envp);
}
