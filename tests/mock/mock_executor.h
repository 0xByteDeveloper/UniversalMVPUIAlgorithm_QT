// =============================================================================
// UMVP-QT // tests/mock/mock_executor.h — in-process remote-call backend.
// Executes resolved qt_static_metacall / slot-impl functions directly with the
// same 5-argument marshalling the Windows CreateRemoteThread path uses.
// Scratch buffers are local mallocs — the engine cannot tell the difference.
// =============================================================================
#pragma once
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "umvpqt/qt_invoke.h"

namespace umvpqt_mock {

class MockRemoteExecutor : public umvpqt::IRemoteExecutor {
public:
    bool call(const umvpqt::RemoteCall& c, uint64_t* ret) override {
        if (!c.fn) return false;
        void (*fn)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t) =
            (void (*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t))(uintptr_t)c.fn;
        fn(c.args[0], c.args[1], c.args[2], c.args[3], c.args[4]);
        if (ret) *ret = 0;
        return true;
    }
    umvpqt::Address allocScratch(size_t len) override {
        void* p = std::calloc(1, len + 16);
        if (!p) return 0;
        tracked_.push_back(p);
        return (umvpqt::Address)(uintptr_t)p;
    }
    bool readScratch(umvpqt::Address a, void* buf, size_t len) override {
        std::memcpy(buf, (void*)(uintptr_t)a, len);
        return true;
    }
    bool writeScratch(umvpqt::Address a, const void* buf, size_t len) override {
        std::memcpy((void*)(uintptr_t)a, buf, len);
        return true;
    }
    void freeScratch(umvpqt::Address) override {
        // freed in dtor (keep allocations alive across the analysis)
    }
    std::string describe() const override { return "mock in-process executor"; }
    ~MockRemoteExecutor() override {
        for (void* p : tracked_) std::free(p);
    }

private:
    std::vector<void*> tracked_;
};

} // namespace umvpqt_mock
