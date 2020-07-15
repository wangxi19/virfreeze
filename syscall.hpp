#ifndef SYSCALL_HPP
#define SYSCALL_HPP

#include <sys/mman.h>
#include <dlfcn.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>

typedef void*(*mmpOrgPfn)(void *__addr, size_t __len, int __prot, int __flags, int __fd, __off_t __offset);
static mmpOrgPfn mmpOrg;

typedef int (*munmapOrgPfn) (void *__addr, size_t __len);
static munmapOrgPfn munmapOrg;

bool init()
{
    mmpOrg = (mmpOrgPfn)dlsym(RTLD_NEXT, "mmap");
    munmapOrg = (munmapOrgPfn)dlsym(RTLD_NEXT, "munmap");

    return mmpOrg;
}

void* mmap(void *addr,
           size_t length,
           int prot,
           int flags,
           int fd,
           off_t offset)
{
    return mmpOrg(addr, length, prot, flags, fd, offset);
}

int munmap (void *__addr, size_t __len)
{
    return munmapOrg(__addr, __len);
}

void* memset(void *s, int c, size_t n)
{
    char* sc = (char*)s;
    for (size_t i = 0; i < n; i++) {
        sc[i] = c;
    }

    return s;
}
#endif // SYSCALL_HPP
