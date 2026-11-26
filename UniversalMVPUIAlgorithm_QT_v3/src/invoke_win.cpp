// UMVPQT GOD STATE — Windows Invoke Engine (CreateRemoteThread + stub)
// ============================================================================
//  Uzak cagri: VirtualAllocEx ile RWX stub sayfasi; stub:
//      mov rcx, <this>; mov rdx, <a1>; mov r8, <a2>; mov r9, <a3>
//      mov rax, <fn>; call rax; mov [rax_slot], rax; ret
//  CreateRemoteThread(stub) — donuste slot'tan 64-bit RAX okunur.
//  (Not: CreateRemoteThread yeni is parcaciginda calisir — Qt thread
//   affinity gerektiren islemler icin once message-modu denenmelidir.)
// ============================================================================
#include "umvpqt/invoke.h"

#ifdef _WIN32

#include <cstdio>
#include <cstring>
#include <vector>
#include <windows.h>

namespace umvpqt {

class WinInvoker : public IInvoker {
public:
    explicit WinInvoker(HANDLE hp, bool target64) : hp_(hp), target64_(target64) {}
    ~WinInvoker() override {
        for (Addr p : pages_) if (p) VirtualFreeEx(hp_, (LPVOID)(uintptr_t)p, 0, MEM_RELEASE);
    }

    std::string platform() const override { return "win-remotethread"; }
    bool hasPendingCall() const override { return false; }

    // ------------------------------------------------------------ callFn --
    RemoteCallResult callFn(Addr fn, Addr thisPtr, uint64_t a1, uint64_t a2,
                            uint64_t a3, int timeoutMs) override {
        RemoteCallResult res;
        if (!target64_) {
            res.error = "Windows invoke stub'u 64-bit hedef icin yazildi "
                        "(32-bit: stub 32-bit versiyonu gerekir)";
            return res;
        }
        if (!hp_) { res.error = "surec handle yok"; return res; }

        // stub sayfasi
        Addr stubPage = allocPage(0x1000);
        if (!stubPage) { res.error = "VirtualAllocEx(stub) basarisiz"; return res; }
        // duzen: [0x00..0x7F] kod, [0x80] RAX slot
        unsigned char code[0x80] = {};
        size_t o = 0;
        auto movreg = [&](unsigned char b0, unsigned char b1, uint64_t v) {
            code[o++] = b0; code[o++] = b1;
            memcpy(code + o, &v, 8); o += 8;
        };
        movreg(0x48, 0xB9, thisPtr);   // mov rcx, this
        movreg(0x48, 0xBA, a1);        // mov rdx, a1
        movreg(0x49, 0xB8, a2);        // mov r8,  a2
        movreg(0x49, 0xB9, a3);        // mov r9,  a3
        movreg(0x48, 0xB8, fn);         // mov rax, fn
        code[o++] = 0xFF; code[o++] = 0xD0;        // call rax
        // 48 A3 imm64 : mov [moffs64], rax
        code[o++] = 0x48; code[o++] = 0xA3;
        uint64_t slot = stubPage + 0x80;
        memcpy(code + o, &slot, 8); o += 8;
        code[o++] = 0xC3;                          // ret
        if (!remoteWrite(stubPage, code, sizeof(code))) {
            res.error = "stub yazilamadi"; return res;
        }

        HANDLE th = CreateRemoteThread(hp_, nullptr, 0,
                                       (LPTHREAD_START_ROUTINE)(uintptr_t)stubPage,
                                       nullptr, 0, nullptr);
        if (!th) { res.error = "CreateRemoteThread basarisiz"; return res; }
        DWORD wait = WaitForSingleObject(th, timeoutMs < 0 ? 5000 : timeoutMs);
        if (wait != WAIT_OBJECT_0) {
            TerminateThread(th, 1);
            CloseHandle(th);
            res.pending = true;
            res.error = "uzak thread zaman asimi";
            return res;
        }
        CloseHandle(th);
        uint64_t rax = 0;
        if (!remoteRead(slot, &rax, 8)) { res.error = "sonuc okunamadi"; return res; }
        res.ok = true;
        res.ret = rax;
        return res;
    }

    Addr remoteAlloc(size_t size) override {
        Addr p = allocPage((size + 0xFFF) & ~0xFFFULL);
        if (p) {
            unsigned char z[1] = { 0 };
            remoteWrite(p, z, 1);   // dokunma — sayfayi commit et
        }
        return p;
    }

    bool remoteWrite(Addr addr, const void* data, size_t len) override {
        SIZE_T got = 0;
        return WriteProcessMemory(hp_, (LPVOID)(uintptr_t)addr, data, len, &got) && got == len;
    }
    bool remoteRead(Addr addr, void* buf, size_t len) override {
        SIZE_T got = 0;
        return ReadProcessMemory(hp_, (LPCVOID)(uintptr_t)addr, buf, len, &got) && got == len;
    }

private:
    Addr allocPage(size_t size) {
        Addr p = (Addr)(uintptr_t)VirtualAllocEx(hp_, nullptr, size,
                                                 MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (p) pages_.push_back(p);
        return p;
    }

    HANDLE hp_ = nullptr;
    bool target64_ = true;
    std::vector<Addr> pages_;
};

std::unique_ptr<IInvoker> createInvoker(IProcessReader& proc) {
    // handle'i WindowsProcess'ten almak icin dynamic cast kullanimi yerine
    // yeni ac: openProcess'ten handle girmek yerine tekrar OpenProcess yap.
    // (IProcessReader arayuzune HANDLE eklemedigimiz icin — sade tutuldu.)
    HANDLE hp = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
                            PROCESS_VM_READ | PROCESS_CREATE_THREAD,
                            FALSE, (DWORD)proc.pid());
    if (!hp) hp = OpenProcess(PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, (DWORD)proc.pid());
    if (!hp) return nullptr;
    return std::make_unique<WinInvoker>(hp, proc.targetIs64());
}

} // namespace umvpqt

#endif // _WIN32
