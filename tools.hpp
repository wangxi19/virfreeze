#ifndef TOOLS_HPP
#define TOOLS_HPP
#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include <vector>
#include <string>
#include <stdlib.h>
#include <climits>
#include <tuple>
#include <algorithm>
#include <functional>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

class Defer
{
public:
    explicit Defer () {

    }

    explicit Defer (std::function<void(void)> pfn) {
        dctors.push_back(pfn);
    }

    ~Defer() {
        for (size_t i = 0; i < dctors.size(); i++) {
            if (dctors[i])
                dctors[i]();
        }
    }

    Defer& add(std::function<void(void)> pfn) {
        dctors.push_back(pfn);
        return *this;
    }
private:
    std::vector<std::function<void(void)>> dctors;
};

int findStr(const char* src, const char* ptn, int lenSrc = 0, int sPos = 0) {
    int pos = -1;
    lenSrc = lenSrc == (unsigned int) 0 ? strlen(src) : lenSrc;
    int lenPtn = strlen(ptn);
    if (sPos < 0 || lenSrc <=0 || lenPtn <= 0 || lenSrc - sPos < lenPtn) {
        return pos;
    }

    for (int idx = sPos; idx <= lenSrc - lenPtn; idx++) {
        if (0 == memcmp(src + idx, ptn, lenPtn)) {
            pos = idx;
            break;
        }
    }

    return pos;
}

std::vector<std::string> Split(const std::string& s, const std::string& c, bool skipEmptyPart = true, int maxCnt = -1) {
    std::vector<std::string> v;
    std::string::size_type pos1, pos2;
    pos2 = s.find(c);
    pos1 = 0;
    while (std::string::npos != pos2) {
        if (!(pos2 == pos1 && skipEmptyPart))
            v.push_back(s.substr(pos1, pos2 - pos1));

        pos1 = pos2 + c.size();
        pos2 = s.find(c, pos1);

        if ( (int)v.size() == maxCnt - 1) {
            break;
        }
    }

    if (pos1 != s.length()) {
        v.push_back(s.substr(pos1));
    }

    return v;
}


inline void Ltrim(std::string& s) {
    if (s.size() == 0) return;

    int pos = -1;
    for (size_t idx = 0; idx < s.size(); idx++) {
        if (s.at(idx) == ' ') {
            pos = idx;
        }
        else {
            break;
        }
    }
    if (pos != -1) {
        s.erase(0, pos + 1);
    }
}

inline void Rtrim(std::string& s) {
    if (s.size() == 0) return;

    int pos = -1;
    for (int idx = (int)s.size() - 1; idx >= 0; idx--) {
        if (s.at(idx) == ' ') {
            pos = idx;
        }
        else {
            break;
        }
    }

    if (pos != -1) {
        s.erase(pos);
    }
}

inline void Trim(std::string& s) {
    Ltrim(s);
    Rtrim(s);
}

int isSymlink(const char *filename, bool& smblk)
{
    struct stat p_statbuf;

    if (lstat(filename, &p_statbuf) < 0) {
        return 1;
    }

    if (S_ISLNK(p_statbuf.st_mode) == 1) {
        smblk = true;
    } else {
        smblk = false;
    }

    return 0;
}
#endif // TOOLS_HPP
