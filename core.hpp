#ifndef CORES_HPP
#define CORES_HPP
#include "syscall.hpp"
#include "tools.hpp"
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <vector>
#include <fstream>
#include <string>
#include <stdlib.h>
#include <climits>
#include <tuple>
#include <algorithm>
#include <elf.h>
#include <map>

#define LOGERR(fmt, arg...) fprintf(stderr, "%s %s %d: " fmt, __FILE__, __FUNCTION__, __LINE__, ##arg);
#define LOGINFO(fmt, arg...) fprintf(stdout, "%s %s %d: " fmt, __FILE__, __FUNCTION__, __LINE__, ##arg);


// get text segment from process memory
#define GTEXTPROC(ptr,sz,vec) \
    for (size_t i = 0; i < vec.size(); i++) { \
        if (std::get<2>(vec[i]) & (1<<1)) { \
            ptr = std::get<0>(vec[i]); \
            sz = std::get<1>(vec[i]); \
            break; \
        } \
    } \

#define GEHDRPROC(ptr,vec) \
    for (size_t i = 0; i < vec.size(); i++) { \
        if (std::get<3>(vec[i]) == 0 && std::get<1>(vec[i]) >= sizeof(Elf64_Ehdr)) { \
            ptr = (Elf64_Ehdr*)std::get<0>(vec[i]);  \
            break; \
        }   \
    }   \

#define GPHDRPROC(ptr,sz,vec) \
{\
    Elf64_Ehdr* elfhdr = NULL; \
    for (size_t i = 0; i < vec.size(); i++) { \
        if (std::get<3>(vec[i]) == 0 && std::get<1>(vec[i]) >= sizeof(Elf64_Ehdr)) { \
            elfhdr = (Elf64_Ehdr*)std::get<0>(vec[i]);  \
            if (elfhdr->e_phoff + elfhdr->e_phnum * elfhdr->e_phentsize <= std::get<1>(vec[i])) { \
                ptr = (Elf64_Phdr*) (std::get<0>(tp) + elfhdr->e_phoff); \
                sz = elfhdr->e_phnum; \
            } \
            break; \
        }   \
    }   \
}\

// get ELF header from elf file
#define GEHDRFILE(ptr,mem,sz) \
    if (sz >= sizeof(Elf64_Ehdr)) { \
        ptr = (Elf64_Ehdr*)mem; \
    } \

#define GPHDRFILE(ptr,num,mem,sz) \
{\
    Elf64_Ehdr* elfhdr = NULL; \
    GEHDRFILE(elfhdr,mem,sz);\
    if (elfhdr != NULL && elfhdr->e_phoff + elfhdr->e_phnum * elfhdr->e_phentsize <= sz) { \
        ptr = (Elf64_Phdr*) (mem + elfhdr->e_phoff); \
        num = elfhdr->e_phnum; \
    }\
}\
// get text segment from elf file
//#define GTEXTFILE(ptr,datlen,mem,sz) \

/*
 * These below parts need to be loaded
 * 1. process LOAD segment  | process elf header
 * 2. entire elf file | The elf header of elf file
 * 3. /proc/pid/stat
 * 4. /proc/pid/environ
 *
*/

//It is the caller responsibility to munmap(*__mp, *__sz)
int getElfFromFile (const std::string& path,
                 char** __mp,
                 size_t* __sz,
                 std::vector<std::tuple<char*, uint32_t, uint32_t>>& loadSegmentVec)
{
    int fd;
    __off_t sz;
    char* mp;
    Elf64_Ehdr* ehdr;
    Elf64_Phdr* phdr;
    Elf64_Shdr* shdr = NULL;
    fd = open(path.c_str(), O_RDONLY);
    if (fd <= 0) {
        LOGERR("Fail to open %s\n", path.c_str());
        return -1;
    }

    sz = lseek(fd, 0, SEEK_END);
    mp = (char*)mmap(NULL, sz, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
    close(fd);
    if (MAP_FAILED == mp) {
        LOGERR("Fail to mmap %s\n", path.c_str());
        return -1;
    }

    if ((size_t)sz < sizeof(Elf64_Ehdr)) {
        LOGERR("(size_t)sz < sizeof(Elf64_Ehdr)\n");
        munmap(mp, sz);
        return -1;
    }

    ehdr = (Elf64_Ehdr*) mp;
    if ((size_t)sz < ehdr->e_phnum * ehdr->e_phentsize + ehdr->e_phoff) {
        LOGERR("(size_t)sz < ehdr->e_phnum * ehdr->e_phentsize + ehdr->e_phoff\n");
        munmap(mp, sz);
        return -1;
    }

    phdr = (Elf64_Phdr*) (mp + ehdr->e_phoff);

    if (ehdr->e_shoff > 0 && (size_t)sz > ehdr->e_shoff + ehdr->e_shnum * ehdr->e_shentsize) {
        shdr = (Elf64_Shdr*) (mp + ehdr->e_shoff);
    }

    *__mp = mp;
    *__sz = sz;

    for (int i = 0; i < ehdr->e_phnum; i++) {
        if ((phdr + i)->p_type == PT_LOAD) {
            loadSegmentVec.push_back(std::make_tuple(mp + (phdr+i)->p_offset, (phdr+i)->p_filesz, (phdr+i)->p_flags));
        }
    }

    return 0;
}

int getProcElfHeader (pid_t pid,
                      Elf64_Ehdr& elfHeader,
                      std::vector<Elf64_Phdr>& phdrVec,
                      uint64_t saddr,
                      uint64_t eaddr)
{
    std::string path{"/proc/"};
    path = path + std::to_string(pid) + "/mem";
    int fd;
    auto sz = eaddr - saddr;

    if (sz < sizeof(elfHeader)) {
        LOGERR("Memory size is not enough to hold elfHeader\n");
        return -1;
    }

    fd = open(path.c_str(), O_RDONLY);
    if (fd <= 0) {
        LOGERR("Fail to open %s to read\n", path.c_str());
        return errno;
    }

    if ((__off_t)saddr != lseek(fd, saddr, SEEK_SET)) {
        close(fd);
        LOGERR("Fail to seek\n");
        return -1;
    }

    if (sizeof(elfHeader) != read(fd, &elfHeader, sizeof(elfHeader))) {
        close(fd);
        LOGERR("Fail to read elfheader\n");
        return -1;
    }

    if (elfHeader.e_phentsize != sizeof(Elf64_Phdr)) {
        close(fd);
        LOGERR("Is not Elf64_Phdr\n");
        return -1;
    }

    if ((int64_t)(saddr + elfHeader.e_phoff) != (int64_t)lseek(fd, saddr + elfHeader.e_phoff, SEEK_SET)) {
        close(fd);
        LOGERR("Fail to lseek\n");
        return -1;
    }

    phdrVec.resize(elfHeader.e_phnum);
    if ((int64_t)(elfHeader.e_phnum*elfHeader.e_phentsize) != (int64_t)read(fd, phdrVec.data(), elfHeader.e_phnum*elfHeader.e_phentsize)) {
        close(fd);
        LOGERR("read error\n");
        return -1;
    }

    close(fd);
    return 0;
}

int getProcEnviron (pid_t pid,
                    std::vector<std::string>& environVec)
{
    std::string path;
    int fd;
    char* buf;
    ssize_t sz;
    path = path + "/proc/" + std::to_string(pid) + "/environ";

    fd = open(path.c_str(), O_RDONLY);
    if (fd <= 0) {
        LOGERR("Fail to open %s\n", path.c_str());
        return -1;
    }

    buf = (char*)malloc(10240);
    sz = read(fd, buf, 10240);
    close(fd);
    if (sz == 10240) {
        free(buf);
        LOGERR("%s size is too long", path.c_str());
        return -1;
    }

    buf[sz] = 0;
    for (ssize_t i = 0; i < sz; i++) {
        environVec.push_back(std::string(buf+i));
        ssize_t j = i;
        for (; j < sz; j++) {
            if (buf[j] == 0) break;
        }

        if (j == i)
            break;

        i = j;
    }

    free(buf);
    return 0;
}

int getProcCmdline(pid_t pid,
                std::string& progName)
{
    std::string path;
    ssize_t sz;
    int fd;
    char buf[1024];
    path = path + "/proc/" + std::to_string(pid) + "/cmdline";

    fd = open(path.c_str(), O_RDONLY);
    if (fd <= 0) {
        LOGERR("Fail to open file %s\n", path.c_str());
        return -1;
    }

    sz = read(fd, buf, sizeof(buf));

    if (sz <= 0 || sz == sizeof(buf)) {
        close(fd);
        LOGERR("Some error occured\n");
        return -1;
    }

    close(fd);
    progName.assign(buf);

    return 0;
}

int getProcStat(pid_t pid,
                std::vector<std::string>& statVec)
{
    std::string path;
    int fd;
    char* buf;
    ssize_t sz;
    path = path + "/proc/" + std::to_string(pid) + "/stat";

    fd = open(path.c_str(), O_RDONLY);
    if (fd <= 0) {
        LOGERR("Fail to open stat %s\n", path.c_str());
        return -1;
    }

    buf = (char*)malloc(10240);
    sz = read(fd, buf, 10240);
    close(fd);
    if (sz == 10240) {
        free(buf);
        LOGERR("%s size is too long", path.c_str());
        return -1;
    }

    buf[sz] = 0;
    statVec = Split(buf, " ");
    free(buf);
    return 0;
}

//It is the caller responsibility to munmap(mem, size)
int getElfFromProc (pid_t pid,
                    //                      saddr    eaddr    flag   offset
                    std::vector<std::tuple<uint64_t, uint64_t, int, uint32_t>>& progLoadedVec,
                    //                      mem    size    flag   offset
                    std::vector<std::tuple<char*, uint32_t, int, uint32_t>>& oVec)
{
    std::string path = "/proc/";
    Defer defer;
    int fd;
    char* buf;
    uint32_t sz;
    int jk1 = 0;
    path = path + std::to_string(pid) + "/mem";

    fd = open(path.c_str(), O_RDONLY);
    if (fd <= 0) {
        LOGERR("Fail to open %s \n", path.c_str());
        return -1;
    }

    defer.add([fd](){
        close(fd);
    });

    for (auto& tp: progLoadedVec) {
        sz = std::get<1>(tp)-std::get<0>(tp);
        buf = (char*) mmap(NULL, sz, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

        if (buf == MAP_FAILED) {
            jk1 = 1;
            break;
        }

        if (buf) {
            oVec.push_back(std::make_tuple(buf, sz, std::get<2>(tp), std::get<3>(tp)));
        }

        if ((int64_t)std::get<0>(tp) != (int64_t)lseek(fd, std::get<0>(tp), SEEK_SET)) {
            jk1 = 1;
            break;
        }

        if ((int64_t)sz != (int64_t)read(fd, buf, sz)) {
            jk1 = 1;
            break;
        }
    }

    if (jk1 == 1) {
        defer.add([&oVec](){
            for (size_t i = 0; i < oVec.size(); i++) {
                munmap(std::get<0>(oVec[i]), std::get<1>(oVec[i]));
            }

            oVec.clear();
        });

        return -1;
    }

    return 0;
}

/*
 *  return: return 0 when maps is not empty and has been read
*/
int getProcMaps(pid_t pid,
                std::vector<std::tuple<uint64_t, uint64_t, int, uint32_t>>& progLoadedVec,
                std::vector<std::tuple<uint64_t, uint64_t, int>>& progHeapVec,
                std::vector<std::tuple<uint64_t, uint64_t, int>>& progStackVec,
                std::string& progName,
                std::vector<std::string>& soVec)
{
    uint32_t sz = 0;
    std::string line;
    std::ifstream ifp(line + "/proc/" + std::to_string(pid) + "/maps");
    bool reachHeap = false;
    bool progNameSet = false;
    if (!ifp.is_open())
        return -1;

    while (std::getline(ifp, line)) {
        if (line.empty())
            continue;

        sz += line.size();
        std::vector<std::string> retVec = Split(line, " ");
        if (retVec.size() != 6)
            continue;

        if (retVec[5] == "[heap]")  {
            reachHeap = true;
        }

        if (!progNameSet) {
            if (progName.empty()) {
                if (!reachHeap) {
                    progName = retVec[5];
                    progNameSet = true;
                }
            } else if (retVec[5].size() >= progName.size()
                       && retVec[5].substr(retVec[5].size()-progName.size(), progName.size()) == progName) {

                progName = retVec[5];
                progNameSet = true;
            }
        }

        auto addrVec = Split(retVec[0], "-");
        if (addrVec.size() != 2) {
            continue;
        }

        auto saddr = strtoull(addrVec[0].c_str(), NULL, 16);
        if (saddr == ULLONG_MAX) {
            continue;
        }

        auto eaddr = strtoull(addrVec[1].c_str(), NULL, 16);
        if (eaddr == ULLONG_MAX) {
            continue;
        }

        auto ofst = strtoull(retVec[2].c_str(), NULL, 16);
        if (ofst == ULLONG_MAX) {
            continue;
        }

        //rw-p
        if (retVec[1].size() != 4)
            continue;

        int perm = 0;
        if (retVec[1][0] == 'r')
            perm |= 1 << 3;

        if (retVec[1][1] == 'w')
            perm |= 1 << 2;

        if (retVec[1][2] == 'x')
            perm |= 1 << 1;

        if (retVec[1][3] == 'p')
            perm |= 1;

        if (reachHeap && retVec[5] == "[heap]") {
            progHeapVec.push_back(std::make_tuple((uint64_t)saddr, (uint64_t)eaddr, perm));
            continue;
        }

        if (!reachHeap && progNameSet && progName == retVec[5]) {
            progLoadedVec.push_back(std::make_tuple((uint64_t)saddr, (uint64_t)eaddr, perm, ofst));
            continue;
        }

        if (retVec[5].size() > 6 && retVec[5].substr(0, 6) == "[stack") {
            progStackVec.push_back(std::make_tuple((uint64_t)saddr, (uint64_t)eaddr, perm));
            continue;
        }

        if (retVec[5].size() > 3 && retVec[5].substr(retVec[5].size()-3, 3) == ".so") {
            if (std::find(soVec.begin(), soVec.end(), retVec[5]) == soVec.end())
                soVec.push_back(retVec[5]);

            continue;
        }
    }
    return sz > 0 ? 0 : -1;
}



#endif // CORES_HPP
