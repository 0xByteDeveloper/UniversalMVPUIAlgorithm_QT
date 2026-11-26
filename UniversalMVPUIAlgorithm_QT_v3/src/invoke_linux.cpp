// UMVPQT GOD STATE — Linux ptrace Invoke Engine
// ============================================================================
//  Mekanik (sandbox'ta dogrulandi — scripts/ptrace_smoke.cpp):
//    PTRACE_SEIZE + PTRACE_INTERRUPT ile GUI thread'i durdur,
//    kayitlari sakla, uzak cagriyi (rip=fn, rdi=this...) ayarla,
//    ozel scratch stack uzerinde "magic" donus adresi birak,
//    PTRACE_CONT — cagri bitince SIGSEGV@stop(magic) doner:
//    retval = rax, kayitlar geri yuklenir, GUI thread kaldigi yerden devam.
//
//  NESTED/MODAL DESTEK: click() handler'i QDialog::exec() acarsa cagri
//  "pending" olur; thread serbest birakilir (GUI calisir); sonraki komutlar
//  PTRACE_INTERRUPT ile yeni cagrilari AYNI thread icinde icice enjekte eder
//  (Qt thread-affinity korunur). pending call'lar tamamlaninca kendi
//  durdurma noktalarindan devam eder (LIFO).
//
//  Durum makinesi:
//    Detached  -> (SEIZE+INTERRUPT)  -> Stopped  (hold_ gecerli)
//    Stopped   -> (SETREGS+CONT)     -> Running  (cagri/GUI calisiyor)
//    Running   -> (INTERRUPT+EVENT)  -> Stopped
//    Running'de pending magic SIGSEGV'leri sonraki beklemede toplanir.
// ============================================================================
#include "umvpqt/invoke.h"

#ifndef _WIN32

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <vector>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <chrono>
#include <sys/types.h>
#include <sys/signal.h>

namespace umvpqt {

// magic donus adresleri: 0x6000_0000_0000 + serial*8 — heap(0x55..) ile
// kutuphaneler(0x7f..) arasindaki bos gap — kesin eslenmemis VA.
static const uint64_t MAGIC_BASE = 0x600000000000ULL;

// V3.2 — syscall-restart duzeltmesi (gdb tarzi):
// Wine surecleri GUI thread'i wineserver PIPE READ icinde bekler.
// PTRACE_INTERRUPT bu syscall'i ortasindan keser: durdurma anindaki
// kayitlarda rax = -ERESTARTSYS(-512)/-513/-514/-516, orig_rax = syscall no.
// Bu kayitlar DOGRUDAN geri konursa (v2 hatasi!) kullanicistedi rax=-512
// gorur → wineserver pipe read'i EBADMSG'ye duser → surec coker
// ("seh invalid frame" tam olarak budur).
// Cozum: rip'i 2 bayt geri cek (0f 05 syscall yeniden islet) + rax=orig_rax.
static void fixSyscallRestart(user_regs_struct& r) {
    if (r.rax == (uint64_t)-512 || r.rax == (uint64_t)-513 ||
        r.rax == (uint64_t)-514 || r.rax == (uint64_t)-516) {
        if ((int64_t)r.orig_rax > 0) {
            r.rip -= 2;                 // syscall komutunu yeniden islet
            r.rax = r.orig_rax;          // dogru syscall numarasi
        }
    }
}

class LinuxInvoker : public IInvoker {
public:
    explicit LinuxInvoker(pid_t pid, IProcessReader* rd) : pid_(pid), rd_(rd) {}
    ~LinuxInvoker() override { tryDetach(true); free(buf_); }

    std::string platform() const override { return "linux-ptrace"; }
    bool hasPendingCall() const override { return !pending_.empty(); }

    // V3.2 — wine PE hedeflerde Microsoft x64 cagri kurali
    void setWin64Convention(bool on) override { win64_ = on; }

    // thread'i GUI'ye geri birak (seized kalir) — komutlar arasi
    void releaseThread() override {
        if (state_ == Stopped) {
            fixSyscallRestart(hold_);            // V3.2: wine pipe-read onarimi
            ptrace(PTRACE_SETREGS, pid_, 0, &hold_);
            ptrace(PTRACE_CONT, pid_, 0, 0);
            state_ = Running;
        }
    }

    // bitmis pending cagrileri topla (bekleme dongulerinde — GUI serbest)
    void pollPending() override {
        if (state_ != Running || pending_.empty()) return;
        for (int i = 0; i < 16; i++) {
            int st;
            pid_t r = waitpid(pid_, &st, WNOHANG | __WALL);
            if (r != pid_) break;
            handleEvent(st);
        }
    }

    // ------------------------------------------------------------ callFn --
    RemoteCallResult callFn(Addr fn, Addr thisPtr, uint64_t a1, uint64_t a2,
                            uint64_t a3, int timeoutMs) override {
        if (timeoutMs < 0) timeoutMs = 5000;
        RemoteCallResult res;
        if (fn < 0x1000) { res.error = "gecersiz fonksiyon adresi"; return res; }
        if (rd_ && rd_->ptrSize() != 8) {
            res.error = "Linux invoke motoru 64-bit hedef gerektirir "
                        "(32-bit hedefler icin Windows tarafini kullanin)";
            return res;
        }
        if (!ensureStopped(&res.error)) return res;
        if (!ensureScratch(&res.error)) return res;

        // ---- cagri baglami ----
        Ctx ctx;
        ctx.magic      = MAGIC_BASE + (++serial_) * 8;
        ctx.regsBefore = hold_;                 // durdurma noktasi — buradan devam
        // V3.2 — çerçeve GERÇEK thread yığınında (wine hedefleri için ŞART):
        // mmap scratch yığında çalışan callee, wine SEH yığın-sınırı kontrolünde
        // "invalid frame not in stack limits" ile ölüyor. hold_.rsp'nin 0x6000
        // altı: gerçek yığın bölgesi içinde; dönüşte orijinal kayıtlar geri
        // yüklendiği için terk edilen bölge kimseyi etkilemez. (Linux ELF
        // hedeflerde de geçerli — YIGIN zaten hedefe ait.)
        ctx.stackTop   = 0;
        // giriş hizalaması: callee girişte rsp%16==8 görmeli (gerçek CALL taklidi)
        ctx.rsp        = ((hold_.rsp - 0x6000) & ~0xFULL) - 8;
        pending_.push_back(ctx);

        user_regs_struct r = hold_;
        r.rip = (unsigned long long)fn;
        if (win64_) {
            // Microsoft x64 (wine PE kodu): rcx=this, rdx=a1, r8=a2, r9=a3.
            // Gölge alanı: callee [rsp+8..rsp+0x28] yazabilir — 64KB'lık
            // stack slot içinde güvenli (scratch mmap bölgesi).
            r.rcx = (unsigned long long)thisPtr;
            r.rdx = (unsigned long long)a1;
            r.r8  = (unsigned long long)a2;
            r.r9  = (unsigned long long)a3;
        } else {
            // SysV (Linux ELF): rdi=this, rsi=a1, rdx=a2, rcx=a3
            r.rdi = (unsigned long long)thisPtr;
            r.rsi = (unsigned long long)a1;
            r.rdx = (unsigned long long)a2;
            r.rcx = (unsigned long long)a3;
        }
        r.rax = 0;
        r.rsp = (unsigned long long)ctx.rsp;
        if (!remoteWrite(ctx.rsp, &ctx.magic, 8)) {
            res.error = "magic donus adresi yazilamadi (stack)";
            dropPending(ctx.magic);
            return res;
        }
        if (ptrace(PTRACE_SETREGS, pid_, 0, &r) != 0) {
            res.error = std::string("PTRACE_SETREGS: ") + strerror(errno);
            dropPending(ctx.magic);
            return res;
        }
        state_ = Running;
        if (ptrace(PTRACE_CONT, pid_, 0, 0) != 0) {
            res.error = std::string("PTRACE_CONT: ") + strerror(errno);
            dropPending(ctx.magic);
            return res;
        }
#ifdef UMVPQT_INVK_DEBUG
        fprintf(stderr, "[ivk-dbg] call inject: fn=0x%llx this=0x%llx rsp=0x%llx magic=0x%llx\n",
                (unsigned long long)fn, (unsigned long long)thisPtr,
                (unsigned long long)ctx.rsp, (unsigned long long)ctx.magic);
#endif
        return waitTarget(ctx, timeoutMs);
    }

    // -------------------------------------------------------- remoteAlloc --
    Addr remoteAlloc(size_t size) override {
        if (!size) return 0;
        std::string err;
        if (!ensureStopped(&err)) { lastErr_ = err; return 0; }
        if (!ensureScratch(&err)) { lastErr_ = err; return 0; }

        Ctx ctx;
        ctx.magic      = MAGIC_BASE + (++serial_) * 8;
        ctx.regsBefore = hold_;
        ctx.stackTop   = stackSlot(serial_);
        ctx.rsp        = ctx.stackTop - 8;
        pending_.push_back(ctx);

        user_regs_struct r = hold_;
        r.rip = (unsigned long long)(Addr)syscallGadget_;
        r.rax = 9;                                    // SYS_mmap
        r.rdi = 0;
        r.rsi = (unsigned long long)((size + 0xFFF) & ~0xFFFULL);
        r.rdx = 3;                                    // PROT_READ|PROT_WRITE
        r.r10 = 0x22;                                 // MAP_PRIVATE|MAP_ANON
        r.r8  = (unsigned long long)-1;
        r.r9  = 0;
        r.rsp = (unsigned long long)ctx.rsp;
        if (!remoteWrite(ctx.rsp, &ctx.magic, 8)) { dropPending(ctx.magic); return 0; }
        if (ptrace(PTRACE_SETREGS, pid_, 0, &r) != 0) { dropPending(ctx.magic); return 0; }
        state_ = Running;
        if (ptrace(PTRACE_CONT, pid_, 0, 0) != 0) { dropPending(ctx.magic); return 0; }

        RemoteCallResult res = waitTarget(ctx, 4000);
        if (!res.ok) { lastErr_ = res.error.empty() ? "uzak mmap donmedi" : res.error; return 0; }
        Addr a = res.ret;
        if (a > 0x1000 && a < 0x800000000000ULL) return a;
        lastErr_ = "mmap gecersiz adres dondurdu";
        return 0;
    }

    // ------------------------------------------------------- read / write --
    bool remoteWrite(Addr addr, const void* data, size_t len) override {
        struct iovec l{ const_cast<void*>(data), len };
        struct iovec r{ (void*)(uintptr_t)addr, len };
        return process_vm_writev(pid_, &l, 1, &r, 1, 0) == (ssize_t)len;
    }
    bool remoteRead(Addr addr, void* buf, size_t len) override {
        struct iovec l{ buf, len };
        struct iovec r{ (void*)(uintptr_t)addr, len };
        return process_vm_readv(pid_, &l, 1, &r, 1, 0) == (ssize_t)len;
    }

private:
    enum State { Detached, Stopped, Running };

    struct Ctx {
        uint64_t         magic = 0;
        user_regs_struct regsBefore{};
        Addr             stackTop = 0;
        Addr             rsp = 0;
    };

    // ---- durum ----
    static constexpr size_t SCRATCH_SZ = 0x800000;   // 8 MB uzak yigin alani
    pid_t            pid_ = 0;
    IProcessReader*  rd_ = nullptr;
    bool             seized_ = false;
    bool             win64_ = false;      // V3.2: wine PE hedef → MS x64 ABI
    State            state_ = Detached;
    user_regs_struct hold_{};
    std::vector<Ctx> pending_;
    unsigned         serial_ = 0;
    Addr             scratch_ = 0;        // RWX 8MB: park stub + cagri yiginlari
    Addr             syscallGadget_ = 0;
    uint64_t         lastRet_ = 0;
    uint8_t*         buf_ = nullptr;     // gadget arama arabellegi (1 MB)

    // cagri yigin adresi: her cagri KENDİ 64KB bolgesini kullanir
    // (ic ice cagrilarda diş cagri yigini bozulmamali!)
    Addr stackSlot(unsigned serial) {
        unsigned k = (serial % 120) + 1;          // 1..120
        return scratch_ + SCRATCH_SZ - 0x10000 * k; // 64KB'lik bolge basi
    }

    // ======================================================================
    //  Durum yonetimi
    // ======================================================================
    bool seize() {
        if (seized_) return true;
        if (ptrace(PTRACE_SEIZE, pid_, 0, 0) != 0) {
            lastErr_ = std::string("PTRACE_SEIZE: ") + strerror(errno) +
                       " (hedef zaten izleniyor veya izin yok)";
            return false;
        }
        seized_ = true;
        state_ = Running;
        return true;
    }

    // hedefi durdurup kontrolu al — hold_ gecerli olur
    bool ensureStopped(std::string* err) {
        if (state_ == Stopped) return true;
        if (!seized_ && !seize()) { if (err) *err = lastErr_; return false; }

        if (ptrace(PTRACE_INTERRUPT, pid_, 0, 0) != 0) {
            if (err) *err = std::string("PTRACE_INTERRUPT: ") + strerror(errno);
            return false;
        }
        // olaylari toplaya toplaya EVENT_STOP'u bekle (~20 sn ust sinir)
        for (int spin = 0; spin < 20000; spin++) {
            int st;
            pid_t r = waitpid(pid_, &st, __WALL);
            if (r != pid_) {
                if (errno == EINTR) continue;
                if (err) *err = std::string("waitpid(interrupt): ") + strerror(errno);
                return false;
            }
            // pending magic tamamlandi mi? (INTERRUPT'tan once dusenler)
            if (WIFSTOPPED(st) && WSTOPSIG(st) == SIGSEGV) {
                user_regs_struct rr;
                if (ptrace(PTRACE_GETREGS, pid_, 0, &rr) == 0) {
                    Ctx* c = findCtx(rr.rip);
                    if (c) { completePending(*c, rr.rax); continue; }
                }
                ptrace(PTRACE_CONT, pid_, 0, SIGSEGV);   // gercek crash — ilet
                continue;
            }
            if (WIFSTOPPED(st) && WSTOPSIG(st) == SIGTRAP &&
                (st >> 16) == PTRACE_EVENT_STOP) {
                if (ptrace(PTRACE_GETREGS, pid_, 0, &hold_) != 0) {
                    if (err) *err = "PTRACE_GETREGS basarisiz";
                    return false;
                }
                state_ = Stopped;
                return true;
            }
            if (WIFSTOPPED(st)) {   // diger sinyaller: ilet
                ptrace(PTRACE_CONT, pid_, 0, WSTOPSIG(st));
                continue;
            }
        }
        if (err) *err = "hedef durdurulamadi (INTERRUPT donmedi)";
        return false;
    }

    // ======================================================================
    //  Bekleme
    // ======================================================================
    RemoteCallResult waitTarget(const Ctx& ctx, int timeoutMs) {
        RemoteCallResult res;
        auto t0 = std::chrono::steady_clock::now();
        int storm = 0;                    // V3.2: hedef SIGSEGV fırtınası sayacı
        while (true) {
            // V3.2 — zaman aşımı HER turda denetlenir (olay fırtınası
            // döngüyü sonsuzca besliyordu → ajan takılıyordu):
            int elapsed = (int)std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - t0).count();
            int st;
            pid_t r = waitpid(pid_, &st, WNOHANG | __WALL);
            if (r == pid_) {
                // V3.2 — hedef SIGSEGV fırtınası: magic olmayan art arda 8+
                // fault = callee zaten patladı (anti-debug / yanlış thread /
                // bozuk kare) — sinyali iletmeye devam etmek kâr etmiyor.
                if (WIFSTOPPED(st) && WSTOPSIG(st) == SIGSEGV) {
                    user_regs_struct rr;
                    if (ptrace(PTRACE_GETREGS, pid_, 0, &rr) == 0 && !findCtx(rr.rip))
                        storm++;
                }
                if (storm > 8) {
                    // kayıtları durdurma noktasına geri yükle, çağrıyı düşür
                    hold_ = ctx.regsBefore;
                    fixSyscallRestart(hold_);
                    ptrace(PTRACE_SETREGS, pid_, 0, &hold_);
                    dropPending(ctx.magic);
                    state_ = Stopped;
                    res.error = "hedef SIGSEGV fırtınası — çağrı yarıda bırakıldı "
                                "(anti-debug veya yanlış iş parçacığı?)";
                    return res;
                }
                handleEvent(st);
                // hedef ctx bitmis mi? (pending listesinden dusmusse)
                bool gone = true;
                for (auto& c : pending_) if (c.magic == ctx.magic) { gone = false; break; }
                if (gone) {
                    res.ok = true;
                    res.ret = lastRet_;
                    lastRet_ = 0;
                    return res;
                }
                // EVENT_STOP yedikse (beklenmedik durma) — hedef hala icli
                // calisiyor olamaz; Stopped'sa devam ettir ki bitsin:
                if (state_ == Stopped) {
                    // (nadir) — thread durdu; devam ettir
                    releaseThread();
                }
            } else if (r == 0) {
                if (elapsed >= timeoutMs) break;
                usleep(1000);
            } else {
                res.error = std::string("waitpid: ") + strerror(errno);
                return res;
            }
        }
        // zaman asimi: cagri hala calisiyor (muhtemelen MODAL) — pending kalir,
        // thread zaten Running durumda (CONT edilmisti) — GUI calisiyor.
        res.pending = true;
        res.error = "zaman asimi — cagri hala calisiyor (modal form?) — GUI serbest birakildi";
        return res;
    }

    // tek olay isle
    void handleEvent(int st) {
        if (WIFSTOPPED(st) && WSTOPSIG(st) == SIGSEGV) {
            user_regs_struct rr;
            siginfo_t si{};
            ptrace(PTRACE_GETSIGINFO, pid_, 0, &si);
            if (ptrace(PTRACE_GETREGS, pid_, 0, &rr) == 0) {
                std::string reg = "?";
                if (rd_) for (auto& r : rd_->regions())
                    if (rr.rip >= r.start && rr.rip < r.end) { reg = r.path.empty() ? "anon" : r.path; break; }
                fprintf(stderr, "[ivk] SIGSEGV stop rip=0x%llx si_addr=0x%llx code=%d bolge=%s\n",
                        (unsigned long long)rr.rip, (unsigned long long)si.si_addr,
                        si.si_code, reg.c_str());
                Ctx* c = findCtx(rr.rip);
                if (c) { completePending(*c, rr.rax); return; }
                fprintf(stderr, "[!] HEDEF SIGSEGV (rip=%llx) — sinyal iletiliyor\n",
                        (unsigned long long)rr.rip);
            }
            ptrace(PTRACE_CONT, pid_, 0, SIGSEGV);
            return;
        }
        if (WIFSTOPPED(st) && WSTOPSIG(st) == SIGTRAP &&
            (st >> 16) == PTRACE_EVENT_STOP) {
            if (ptrace(PTRACE_GETREGS, pid_, 0, &hold_) == 0) state_ = Stopped;
            return;
        }
        if (WIFSTOPPED(st)) ptrace(PTRACE_CONT, pid_, 0, WSTOPSIG(st));
    }

    Ctx* findCtx(uint64_t rip) {
        for (auto& c : pending_) if (c.magic == rip) return &c;
        return nullptr;
    }

    // pending ctx tamamlandi: retval al, durdurma noktasina geri yukle
    void completePending(Ctx& c, uint64_t retval) {
        lastRet_ = retval;
        std::vector<Ctx> keep;
        for (auto& x : pending_) if (x.magic != c.magic) keep.push_back(x);
        pending_.swap(keep);
        hold_ = c.regsBefore;
        fixSyscallRestart(hold_);                // V3.2: wine pipe-read onarimi
        ptrace(PTRACE_SETREGS, pid_, 0, &hold_);
        state_ = Stopped;   // thread durur; releaseThread() ile GUI'ye iade
    }

    void dropPending(uint64_t magic) {
        std::vector<Ctx> keep;
        for (auto& x : pending_) if (x.magic != magic) keep.push_back(x);
        pending_.swap(keep);
    }

    // ======================================================================
    //  Scratch kurulumu
    // ======================================================================
    bool ensureScratch(std::string* err) {
        if (scratch_ && syscallGadget_) return true;
        if (!syscallGadget_ && !findSyscallGadget(err)) return false;
        if (!scratch_) {
            // 8 MB RWX: park stub @ +0, cagri yiginlari yukaridan asagi 64KB'lik
            // bolgeler (ic ice MODAL akislarda diş cagri yigini korunur)
            Addr a = remoteAllocVia(SCRATCH_SZ, 7 /*RWX*/, true);
            if (!a) { if (err) *err = "scratch sayfasi ayirlamadi: " + lastErr_; return false; }
            scratch_ = a;
            // park stub @ scratch+0: mov rax,34; syscall; jmp $-11
            // (SYS_pause dongusu — force-detach'te GUI thread zararsiz park)
            const unsigned char park[] = { 0x48,0xC7,0xC0,0x22,0,0,0,
                                           0x0F,0x05, 0xEB,0xF5 };
            if (!remoteWrite(scratch_, park, sizeof(park))) {
                if (err) *err = "park stub yazilamadi";
                return false;
            }
        }
        return true;
    }

    // exec bolgelerinde {0F 05 C3} (syscall; ret) ara — vdso/libc kesin bulundurur
    bool findSyscallGadget(std::string* err) {
        if (!buf_) buf_ = (uint8_t*)malloc(0x100000);
        if (!rd_) { if (err) *err = "process reader yok"; return false; }
        for (auto& r : rd_->regions()) {
            if (!r.exec) continue;
            if (r.path.find("[vsyscall]") != std::string::npos) continue;
            Addr p = r.start;
            size_t left = (size_t)(r.end - r.start);
            const size_t chunk = 0x100000 - 2;
            while (left > 0) {
                size_t n = left < chunk ? left : chunk;
                if (!rd_->read(p, buf_, n)) break;
                for (size_t i = 0; i + 2 < n; i++) {
                    if (buf_[i] == 0x0F && buf_[i+1] == 0x05 && buf_[i+2] == 0xC3) {
                        syscallGadget_ = p + i;
                        return true;
                    }
                }
                p += n; left -= n;
            }
        }
        if (err) *err = "syscall;ret gadget bulunamadi";
        return false;
    }

    // mmap enjeksiyonu. useTargetStack=true: hedef stack'ini gecici kullan
    // (scratch kurulmadan once — scratch kurulurken scratch stack yok)
    Addr remoteAllocVia(size_t size, int prot, bool useTargetStack) {
        std::string err;
        if (!ensureStopped(&err)) { lastErr_ = err; return 0; }
        if (!syscallGadget_ && !findSyscallGadget(&err)) { lastErr_ = err; return 0; }

        uint64_t magic = MAGIC_BASE + (++serial_) * 8;
        Addr rsp;
        if (useTargetStack) {
            rsp = (Addr)((((uint64_t)hold_.rsp - 0x800) & ~0xFULL) - 8);
        } else {
            Addr top = stackSlot(serial_);
            rsp = top - 8;
        }

        user_regs_struct r = hold_;
        r.rip = (unsigned long long)(Addr)syscallGadget_;
        r.rax = 9;
        r.rdi = 0;
        r.rsi = (unsigned long long)((size + 0xFFF) & ~0xFFFULL);
        r.rdx = (unsigned long long)prot;
        r.r10 = 0x22;
        r.r8  = (unsigned long long)-1;
        r.r9  = 0;
        r.rsp = (unsigned long long)rsp;
        if (!remoteWrite(rsp, &magic, 8)) { lastErr_ = "mmap magic yazilamadi"; return 0; }
        if (ptrace(PTRACE_SETREGS, pid_, 0, &r) != 0) { lastErr_ = "SETREGS(mmap)"; return 0; }
        state_ = Running;
        ptrace(PTRACE_CONT, pid_, 0, 0);

        for (int ms = 0; ms < 5000;) {
            int st;
            pid_t w = waitpid(pid_, &st, WNOHANG | __WALL);
            if (w == pid_) {
                if (WIFSTOPPED(st) && WSTOPSIG(st) == SIGSEGV) {
                    user_regs_struct rr;
                    if (ptrace(PTRACE_GETREGS, pid_, 0, &rr) == 0 && rr.rip == magic) {
                        Addr ret = (Addr)rr.rax;
                        // thread'i durdurma noktasina geri yukle (Stopped)
                        ptrace(PTRACE_SETREGS, pid_, 0, &hold_);
                        state_ = Stopped;
                        return ret;
                    }
                    ptrace(PTRACE_CONT, pid_, 0, SIGSEGV);
                    continue;
                }
                if (WIFSTOPPED(st) && WSTOPSIG(st) == SIGTRAP &&
                    (st >> 16) == PTRACE_EVENT_STOP) {
                    ptrace(PTRACE_GETREGS, pid_, 0, &hold_);
                    state_ = Stopped;
                    releaseThread();
                    continue;
                }
                if (WIFSTOPPED(st)) { ptrace(PTRACE_CONT, pid_, 0, WSTOPSIG(st)); continue; }
            } else if (w == 0) { usleep(1000); ms++; }
            else break;
        }
        lastErr_ = "mmap cagrisi donmedi";
        return 0;
    }

    // ======================================================================
    //  Detach
    // ======================================================================
    bool tryDetach(bool silent) {
        if (!seized_) return true;
        // thread Stopped olmali; Degilse INTERRUPT ile durdur.
        if (state_ != Stopped) {
            if (ptrace(PTRACE_INTERRUPT, pid_, 0, 0) == 0) {
                for (int i = 0; i < 10000; i++) {
                    int st;
                    if (waitpid(pid_, &st, __WALL) != pid_) break;
                    if (WIFSTOPPED(st) && WSTOPSIG(st) == SIGSEGV) {
                        user_regs_struct rr;
                        ptrace(PTRACE_GETREGS, pid_, 0, &rr);
                        Ctx* c = findCtx(rr.rip);
                        if (c) { completePending(*c, rr.rax); continue; }
                        ptrace(PTRACE_CONT, pid_, 0, SIGSEGV);
                        continue;
                    }
                    if (WIFSTOPPED(st) && WSTOPSIG(st) == SIGTRAP &&
                        (st >> 16) == PTRACE_EVENT_STOP) {
                        ptrace(PTRACE_GETREGS, pid_, 0, &hold_);
                        state_ = Stopped;
                        break;
                    }
                    if (WIFSTOPPED(st)) { ptrace(PTRACE_CONT, pid_, 0, WSTOPSIG(st)); continue; }
                }
            }
        }
        // hala pending (derin modal) — park et: magic'i park stub'a yonlendir
        if (!pending_.empty() && scratch_) {
            for (auto& c : pending_) {
                Addr park = scratch_;
                remoteWrite(c.rsp, &park, 8);
            }
            if (!silent)
                fprintf(stderr, "[!] %zu pending cagri park edildi (GUI donar, crash yok)\n",
                        pending_.size());
            pending_.clear();
        } else if (!pending_.empty() && !silent) {
            fprintf(stderr, "[!] %zu pending cagri — park sayfasi yok; SIGSEGV riski\n",
                    pending_.size());
            pending_.clear();
        }
        // durdurma noktasina yukle ve DETACH
        if (state_ == Stopped) {
            fixSyscallRestart(hold_);            // V3.2: wine pipe-read onarimi
            ptrace(PTRACE_SETREGS, pid_, 0, &hold_);
            ptrace(PTRACE_DETACH, pid_, 0, 0);
        } else {
            ptrace(PTRACE_DETACH, pid_, 0, 0);
        }
        seized_ = false;
        state_ = Detached;
        return true;
    }
};

std::unique_ptr<IInvoker> createInvoker(IProcessReader& proc) {
    return std::make_unique<LinuxInvoker>((pid_t)proc.pid(), &proc);
}

} // namespace umvpqt

#endif // !_WIN32
