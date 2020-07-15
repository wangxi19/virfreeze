#include "core.hpp"
#include <iostream>

using namespace std;

int checkNormal(pid_t pid) {

}

int CheckTextSegment(pid_t pid)
{
    std::vector<std::tuple<uint64_t, uint64_t, int, uint32_t>> progLoadedVec;
    std::vector<std::tuple<uint64_t, uint64_t, int>> progHeapVec;
    std::vector<std::tuple<uint64_t, uint64_t, int>> progStackVec;
    std::string progName;
    std::vector<std::string> soVec;

    int gPronmRet = getProcCmdline(pid, progName);
    if (0 == gPronmRet && progName.size() && progName.find("/") != std::string::npos && progName[progName.size()-1] != '/') {
        progName = progName.substr(progName.find_last_of("/")+1);
    }

    int gProMpRet = getProcMaps(pid, progLoadedVec, progHeapVec, progStackVec, progName, soVec);

    if (0 == gPronmRet && progName.empty() && gProMpRet == 0) {
        return 1;
    }

    if (gProMpRet != 0 || access(progName.c_str(), F_OK) != 0 || !progLoadedVec.size()) {
        LOGERR("Fail to getProcMaps\n");
        return 1;
    }

    Elf64_Ehdr elfHeader;
    std::vector<Elf64_Phdr> phdrVec;
    uint64_t saddr = 0, eaddr = 0;

    for (auto& tp: progLoadedVec) {
        if (std::get<3>(tp) == 0) {
            saddr = std::get<0>(tp);
            eaddr = std::get<1>(tp);
        }
    }

    if (saddr == 0) {
        LOGERR("Fail to find out offset 0 segment\n");
        return 1;
    }

    if (0 != getProcElfHeader(pid, elfHeader, phdrVec, saddr, eaddr)) {
        LOGERR("Fail to getProcElfHeader\n");
        return 1;
    }

    char* mp = NULL;
    size_t sz = 0;
    std::vector<std::tuple<char*, uint32_t, uint32_t>> loadSegmentVec;

    if (0 == getElfFromFile(progName, &mp, &sz, loadSegmentVec)) {
        std::string _path;
        _path = _path + "/proc/" + std::to_string(pid) + "/mem";
        int fd = open(_path.c_str(), O_RDONLY);
        int64_t saddr = 0, eaddr = 0;
        char* txtSeg = NULL;
        Elf64_Phdr* phdrPtr = NULL;
        for (auto& ph: phdrVec) {
            if (ph.p_type == PT_LOAD && ph.p_flags & PF_X) {
                phdrPtr = &ph;
                break;
            }
        }

        if (phdrPtr == NULL) {
            LOGERR("Fail to phdrPtr\n");
            return 1;
        }

        txtSeg = (char*) malloc(phdrPtr->p_memsz);
        for (auto& tp: progLoadedVec) {
            if (std::get<2>(tp) & (1<<1)) {
                saddr = std::get<0>(tp);
                eaddr = std::get<1>(tp);
            }
        }

        if (saddr != 0) {
            lseek(fd, saddr, SEEK_SET);
            read(fd, txtSeg, phdrPtr->p_memsz);
        }

        char* txtSegInDisk = NULL;
        for (auto& tp: loadSegmentVec) {
            if (std::get<2>(tp) & PF_X) {
                txtSegInDisk = std::get<0>(tp);
                break;
            }
        }

        return memcmp(txtSeg, txtSegInDisk, phdrPtr->p_memsz);
    }
    return 0;
}

int main (int argc, char** argv)
{
    init();

}
