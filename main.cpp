#include "core.hpp"
#include <iostream>

using namespace std;

class VirusCheck {
    std::vector<std::tuple<uint64_t, uint64_t, int, uint32_t>> mProgLoadVec;
    std::vector<std::tuple<uint64_t, uint64_t, int>> mProgHeapVec;
    std::vector<std::tuple<uint64_t, uint64_t, int>> mProgStackVec;
    std::string mProgName;
    std::vector<std::string> mProgSoVec;
    //                     mem    size      flag   offset
    std::vector<std::tuple<char*, uint32_t, int, uint32_t>> mProgLoadMemVec;
    char* mElfMmap = NULL;
    size_t mElfMmapSz = 0;
    //                      mem    size     flag
    std::vector<std::tuple<char*, uint32_t, uint32_t>> mElfLoadVec;

    Elf64_Ehdr* mProgEHdr = NULL;
    Elf64_Phdr* mProgPHdr = NULL;
    size_t mProgPHdrNum = 0;
    char* mProgTextSeg = NULL;
    size_t mProgTextSz = 0;

    Elf64_Ehdr* mElfEHdr = NULL;
    Elf64_Phdr* mElfPHdr = NULL;
    size_t mElfPHdrNum = 0;
    Elf64_Shdr* mElfSHdr = NULL;
    size_t mElfSHdrNum = 0;
    char* mElfTextSeg = NULL;
    size_t mElfTextSz = 0;
    std::vector<std::string> mEnvironVec;
public:
    explicit VirusCheck () {

    }

    ~VirusCheck () {
        clear();
    }

    void clear() {
        for (size_t i = 0; i < mProgLoadMemVec.size(); i++) {
            munmap(std::get<0>(mProgLoadMemVec[i]), std::get<1>(mProgLoadMemVec[i]));
        }

        if (mElfMmap != NULL) {
            munmap(mElfMmap, mElfMmapSz);
        }

        mProgLoadVec.clear();
        mProgHeapVec.clear();
        mProgStackVec.clear();
        mProgName.clear();
        mProgSoVec.clear();
        mProgLoadMemVec.clear();
        mElfMmap = NULL;
        mElfMmapSz = 0;
        mElfLoadVec.clear();

        mProgEHdr = NULL;
        mProgPHdr = NULL;
        mProgPHdrNum = 0;
        mProgTextSeg = NULL;
        mProgTextSz = 0;

        mElfEHdr = NULL;
        mElfPHdr = NULL;
        mElfPHdrNum = 0;
        mElfSHdr = NULL;
        mElfSHdrNum = 0;
        mElfTextSeg = NULL;
        mElfTextSz = 0;
        mEnvironVec.clear();
    }

    /*
     * return
     *      0: if loading is ok and nothing has been found
     *     -1: if loading is failed
     *     >0: if some trick is found
    */
    int loadProc (pid_t pid) {
        getProcEnviron(pid, mEnvironVec);
        // If the progname is a soft link,thus the soft link will be parsed.
        int gPronmRet = getProcExcName(pid, mProgName);
        if (mProgName.size()) {
            std::string PATH = "/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/usr/sbin/:/usr/local/sbin/";
            for (size_t i = 0; i < mEnvironVec.size(); i++) {
                if (mEnvironVec[i].size() > 5 && mEnvironVec[i].substr(0, 5) == "PATH=") {
                    PATH = mEnvironVec[i].substr(5);
                }
            }

            std::vector<std::string> PATHVec = Split(PATH, ":");
            for (size_t i = 0; i < PATHVec.size(); i++) {
                if (access((PATHVec[i] + "/" + mProgName).c_str(), F_OK) == 0) {
                    mProgName = PATHVec[i] + "/" + mProgName;
                    bool smblk;
                    char* buf = (char*) malloc(2048);
                    if (0 == isSymlink(mProgName.c_str(), smblk) && smblk) {
                        ssize_t sz = readlink(mProgName.c_str(), buf, 2048);
                        if (sz > 0) {
                            mProgName.assign(buf, sz);
                        }
                    }

                    free(buf);
                }
            }
        }

        int gProMpRet = getProcMaps(pid, mProgLoadVec, mProgHeapVec, mProgStackVec, mProgName, mProgSoVec);

        //hasn't maps
        if (gProMpRet != 0) {
            return -1;
        }

        //The responsible elf file of that running process does not existing.
        if (access(mProgName.c_str(), F_OK) != 0) {
            return 2;
        }

        if (gPronmRet == 0 && mProgName.empty() && gProMpRet == 0) {
            return 1;
        }

        if (gProMpRet == 0 && mProgLoadVec.size() == 0) {
            return -1;
        }

        if (0 != getElfFromProc(pid, mProgLoadVec, mProgLoadMemVec)) {
            return -1;
        }

        if (0 != getElfFromFile(mProgName, &mElfMmap, &mElfMmapSz, mElfLoadVec)) {
            return -1;
        }

        GEHDRPROC(mProgEHdr, mProgLoadMemVec);

        if (mProgEHdr == NULL || mProgEHdr->e_ident[4] != ELFCLASS64) {
            return -1;
        }

        GPHDRPROC(mProgPHdr, mProgPHdrNum, mProgLoadMemVec);
        if (mProgPHdr == NULL || mProgPHdrNum == 0) {
            //do nothing
        }

        GTEXTPROC(mProgTextSeg, mProgTextSz, mProgLoadMemVec);
        //Failed to retrieve text segment
        if (mProgTextSeg == NULL || mProgTextSz == 0) {
            return -1;
        }

        GEHDRFILE(mElfEHdr,mElfMmap,mElfMmapSz);
        if (mElfEHdr == NULL || mElfEHdr->e_ident[4] != ELFCLASS64) {
            return -1;
        }

        GPHDRFILE(mElfPHdr,mElfPHdrNum,mElfMmap,mElfMmapSz);
        if (mElfPHdr == NULL || mElfPHdrNum == 0) {
            return -1;
        }

        GTEXTFILE(mElfTextSeg,mElfTextSz,mElfMmap,mElfMmapSz);
        if (mElfTextSeg == NULL || mElfTextSz == 0) {
            return -1;
        }

        GSHDRFILE(mElfSHdr,mElfSHdrNum,mElfMmap,mElfMmapSz);
        if (mElfSHdr == NULL || mElfSHdrNum == 0) {
            //do nothing
        }

        return 0;
    }

    int checkTextSegment() {
        return checkTextSegment(mProgTextSeg, mProgTextSz, mElfTextSeg, mElfTextSz);
    }

    int checkTextSegment(char* t1,
                         size_t t1len,
                         char* t2,
                         size_t t2len)
    {

        return t1len == t2len ? memcmp(t1, t2, t1len) : 1;
    }
};
int main (int argc, char** argv)
{
    init();
    VirusCheck vc;
    for (int i = 0; i < 100000; i++) {
        if (0 == vc.loadProc(i)) {
            cout << i << ": " << vc.checkTextSegment() << endl;
        }

        vc.clear();
    }
}
