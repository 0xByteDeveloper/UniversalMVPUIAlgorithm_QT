// =============================================================================
// UMVP-QT // src/process_posix.cpp — Linux /proc reader (/proc/pid/mem + maps).
// Lets the Linux CLI analyse REAL Qt processes on this machine (Qt apps use the
// same QObject ABI on Linux; only PE export resolution is Windows-only).
// =============================================================================
#ifndef _WIN32

#include "umvpqt/process.h"

#include <cerrno>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>

#include <fstream>
#include <sstream>

namespace umvpqt {

namespace {

class PosixProcessReader : public IProcessReader {
public:
    ~PosixProcessReader() override {
        if (mem_fd_ >= 0) ::close(mem_fd_);
    }

    bool open(uint32_t pid) {
        pid_ = pid;
        char path[64];
        std::snprintf(path, sizeof path, "/proc/%u/cmdline", pid);
        std::ifstream cmd(path);
        std::string arg0;
        std::getline(cmd, arg0, '\0');
        if (!arg0.empty()) {
            size_t slash = arg0.rfind('/');
            name_ = slash == std::string::npos ? arg0 : arg0.substr(slash + 1);
        } else {
            std::snprintf(path, sizeof path, "/proc/%u/comm", pid);
            std::ifstream comm(path);
            std::getline(comm, name_);
        }
        std::snprintf(path, sizeof path, "/proc/%u/mem", pid);
        mem_fd_ = ::open(path, O_RDONLY);
        refresh();
        return !regions_.empty() || mem_fd_ >= 0;
    }

    void refresh() {
        regions_.clear();
        modules_.clear();
        char pmap[64];
        std::snprintf(pmap, sizeof pmap, "/proc/%u/maps", pid_);
        std::ifstream f(pmap);
        std::string line;
        while (std::getline(f, line)) {
            // 55d3e2c00000-55d3e2c21000 rw-p 00000000 08:02 17355629 /path/libQt6Core.so.6
            MemoryRegion reg;
            unsigned long lo = 0, hi = 0;
            char perms[8] = {0};
            char file[1024] = {0};
            int n = std::sscanf(line.c_str(), "%lx-%lx %4s %*s %*s %*s %1023[^\n]",
                                &lo, &hi, perms, file);
            if (n < 3) continue;
            reg.start = lo;
            reg.end = hi;
            reg.perms = (perms[0] == 'r' ? 1 : 0) | (perms[1] == 'w' ? 2 : 0) |
                        (perms[2] == 'x' ? 4 : 0);
            if (n >= 4 && file[0]) {
                std::string fpath(file);
                size_t slash = fpath.rfind('/');
                reg.name = slash == std::string::npos ? fpath : fpath.substr(slash + 1);
                reg.moduleBase = reg.start;   // first mapping of the file
                ModuleInfo m;
                m.name = reg.name;
                m.base = reg.start;
                m.size = hi - lo;
                std::string low = reg.name;
                for (char& c : low) c = (char)tolower((unsigned char)c);
                if (low.find("qt6core") != std::string::npos) { m.isQtCore = true; m.qtFlavor = "qt6"; }
                if (low.find("qt5core") != std::string::npos ||
                    low.find("libqtcore") != std::string::npos) { m.isQtCore = true; m.qtFlavor = "qt5"; }
                modules_.push_back(m);
            }
            regions_.push_back(reg);
        }
        if (info_.pid == 0) {
            info_.pid = pid_;
            info_.name = name_;
            info_.arch = Arch::X64;
        }
    }

    bool read(Address addr, void* buf, size_t len) override {
        if (mem_fd_ < 0) return false;
        size_t done = 0;
        while (done < len) {
            ssize_t n = ::pread(mem_fd_, (char*)buf + done, len - done, (off_t)(addr + done));
            if (n <= 0) return false;
            done += (size_t)n;
        }
        return true;
    }
    const std::vector<MemoryRegion>& regions() override { return regions_; }
    const std::vector<ModuleInfo>& modules() override { return modules_; }
    ProcessInfo info() const override { return info_; }
    void* native() const override { return (void*)(intptr_t)mem_fd_; }

private:
    uint32_t pid_ = 0;
    std::string name_;
    int mem_fd_ = -1;
    ProcessInfo info_;
    std::vector<MemoryRegion> regions_;
    std::vector<ModuleInfo> modules_;
};

} // namespace

std::vector<ProcessInfo> list_processes() {
    std::vector<ProcessInfo> out;
    DIR* d = opendir("/proc");
    if (!d) return out;
    while (struct dirent* e = readdir(d)) {
        if (!(e->d_name[0] >= '0' && e->d_name[0] <= '9')) continue;
        uint32_t pid = (uint32_t)strtoul(e->d_name, nullptr, 10);
        char path[64];
        std::snprintf(path, sizeof path, "/proc/%u/comm", pid);
        std::ifstream f(path);
        std::string name;
        std::getline(f, name);
        if (!name.empty()) {
            ProcessInfo p;
            p.pid = pid;
            p.name = name;
            p.arch = Arch::X64;
            out.push_back(p);
        }
    }
    closedir(d);
    return out;
}

std::unique_ptr<IProcessReader> open_process_by_pid(uint32_t pid) {
    auto r = std::make_unique<PosixProcessReader>();
    if (!r->open(pid)) return nullptr;
    return r;
}

std::unique_ptr<IProcessReader> open_process_by_name(const std::string& name) {
    for (const ProcessInfo& p : list_processes()) {
        if (p.name == name || p.name.find(name) != std::string::npos)
            if (auto r = open_process_by_pid(p.pid)) return r;
    }
    return nullptr;
}

// PE export stubs (not applicable on Linux)
Address resolve_export(IProcessReader&, const ModuleInfo&, const std::string&) { return 0; }
std::vector<ExportEntry> list_exports(IProcessReader&, const ModuleInfo&) { return {}; }

} // namespace umvpqt

#endif // !_WIN32
