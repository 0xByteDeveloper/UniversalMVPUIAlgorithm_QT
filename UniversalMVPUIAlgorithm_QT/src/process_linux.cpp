// UMVPQT GOD STATE — Process layer: Linux implementation
// ============================================================================
//  /proc/<pid>/maps + process_vm_readv + /proc/<pid>/comm
// ============================================================================
#include "umvpqt/process.h"
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <sys/uio.h>
#include <sys/types.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>

namespace umvpqt {

static bool g_target64 = true;

class LinuxProcess : public IProcessReader {
public:
    ~LinuxProcess() override { close(); }

    bool open(uint64_t pid) override {
        char path[64];
        snprintf(path, sizeof(path), "/proc/%llu/maps", (unsigned long long)pid);
        FILE* f = fopen(path, "r");
        if (!f) return false;
        fclose(f);
        pid_ = pid;
        // process adi
        snprintf(path, sizeof(path), "/proc/%llu/comm", (unsigned long long)pid);
        f = fopen(path, "r");
        if (f) { char buf[256]{}; if (fgets(buf, sizeof(buf), f)) { char* p = strchr(buf, '\n'); if (p) *p = 0; name_ = buf; } fclose(f); }
        reloadRegions();
        detectArch();
        return true;
    }
    void close() override { pid_ = 0; name_.clear(); regions_.clear(); }
    bool isOpen() const override { return pid_ != 0; }
    uint64_t pid() const override { return pid_; }
    std::string name() const override { return name_; }

    bool read(Addr addr, void* buf, size_t len) override {
        struct iovec local{ buf, len };
        struct iovec remote{ (void*)(uintptr_t)addr, len };
        ssize_t n = process_vm_readv((pid_t)pid_, &local, 1, &remote, 1, 0);
        return n == (ssize_t)len;
    }
    bool readPtrSize(Addr addr, uint64_t& out) override {
        if (ptrSize() == 4) { uint32_t v{}; if (!read(addr, &v, 4)) return false; out = v; return true; }
        return read(addr, &out, 8);
    }
    std::vector<MemRegion> regions() override { return regions_; }

    bool targetIs64() const override { return is64_; }
    int ptrSize() const override { return is64_ ? 8 : 4; }
    Addr ptrMask() const override { return is64_ ? ~(Addr)0 : 0xFFFFFFFFULL; }

private:
    void reloadRegions() {
        regions_.clear();
        char path[64];
        snprintf(path, sizeof(path), "/proc/%llu/maps", (unsigned long long)pid_);
        FILE* f = fopen(path, "r");
        if (!f) return;
        char line[512];
        while (fgets(line, sizeof(line), f)) {
            MemRegion r;
            unsigned long long s, e, off;
            char perms[8] = {};
            char fpath[400] = {};
            int n = sscanf(line, "%llx-%llx %7s %llx", &s, &e, perms, &off);
            if (n < 4) continue;
            // yol kismi: 5 alandan sonra
            const char* p = strchr(line, '/');
            if (p) { size_t i = 0; while (*p && *p != '\n' && i < sizeof(fpath) - 1) fpath[i++] = *p++; }
            else { p = strstr(line, "["); if (p) { size_t i = 0; while (*p && *p != '\n' && i < sizeof(fpath) - 1) fpath[i++] = *p++; } }
            r.start = s; r.end = e; r.fileOffset = off;
            r.read = perms[0] == 'r'; r.write = perms[1] == 'w'; r.exec = perms[2] == 'x';
            r.priv = perms[3] == 'p';
            r.path = fpath;
            regions_.push_back(r);
        }
        fclose(f);
    }
    void detectArch() {
        is64_ = true;
        // ELF basligindan: ilk executable modul dosyasini ac
        for (auto& r : regions_) {
            if (r.path.empty() || r.path[0] != '/' || r.fileOffset != 0) continue;
            FILE* f = fopen(r.path.c_str(), "rb");
            if (!f) continue;
            unsigned char magic[6] = {};
            if (fread(magic, 1, 6, f) == 6 && magic[0] == 0x7f && memcmp(magic + 1, "ELF", 3) == 0) {
                // magic[4] = EI_CLASS (2 = 64-bit) — GECMIS BUG: 5. bayt (EI_DATA) okunuyordu
                is64_ = (magic[4] == 2);
            }
            fclose(f);
            break;
        }
        g_target64 = is64_;
    }

    uint64_t pid_ = 0;
    std::string name_;
    std::vector<MemRegion> regions_;
    bool is64_ = true;
};

std::vector<ProcEntry> listProcesses() {
    std::vector<ProcEntry> out;
    DIR* d = opendir("/proc");
    if (!d) return out;
    struct dirent* de;
    while ((de = readdir(d))) {
        if (de->d_name[0] < '0' || de->d_name[0] > '9') continue;
        ProcEntry e;
        e.pid = strtoull(de->d_name, nullptr, 10);
        char path[64];
        snprintf(path, sizeof(path), "/proc/%llu/comm", (unsigned long long)e.pid);
        FILE* f = fopen(path, "r");
        if (f) { char buf[256]{}; if (fgets(buf, sizeof(buf), f)) { char* p = strchr(buf, '\n'); if (p) *p = 0; e.name = buf; } fclose(f); }
        if (!e.name.empty()) out.push_back(e);
    }
    closedir(d);
    return out;
}

std::unique_ptr<IProcessReader> openProcess(uint64_t pid) {
    auto p = std::make_unique<LinuxProcess>();
    if (p->open(pid)) return p;
    return nullptr;
}

std::unique_ptr<IProcessReader> openProcessByName(const std::string& name) {
    for (auto& e : listProcesses()) {
        if (name == e.name || e.name.find(name) != std::string::npos) {
            auto p = openProcess(e.pid);
            if (p) return p;
        }
    }
    return nullptr;
}

} // namespace umvpqt
