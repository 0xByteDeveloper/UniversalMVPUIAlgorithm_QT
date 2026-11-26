// UMVPQT GOD STATE — uqt_agent: yapay zeka surucu CLI
// ============================================================================
//  Qt menulu sureci JSON-lines komutlarla "bir uzvi gibi" kontrol eder:
//    uqt_agent --pid 1234
//    uqt_agent --name vmprotect --allow-shell
//    uqt_agent --pid 1234 --script vmprotect_scenario.json
//    uqt_agent --list
// ============================================================================
#include "umvpqt/agent.h"
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>

using namespace umvpqt;

static void usage() {
    printf("UMVPQT GOD AGENT — Qt surec kontrol arayuzu (yapay zeka icin)\n"
           "  --list                surec listesi\n"
           "  --pid N               surece baglan\n"
           "  --name X              isimle baglan (icerir)\n"
           "  --allow-shell         'sh' komutuna izin (dosya islemleri)\n"
           "  --script FILE         JSON komut dizisini tek atista calistir\n"
           "  (stdini JSON-lines olarak okur; her satir = komut, her cikti = JSON)\n"
           "\nOrnek oturum:\n"
           "  {\"cmd\":\"attach\",\"name\":\"vmprotect\"}\n"
           "  {\"cmd\":\"analyze\"}\n"
           "  {\"cmd\":\"forms\"}\n"
           "  {\"cmd\":\"click\",\"text\":\"Add function\"}\n"
           "  {\"cmd\":\"waitform\",\"title\":\"Add\"}\n"
           "  {\"cmd\":\"settext\",\"name\":\"editSearch\",\"value\":\"MovePlayer\"}\n"
           "  {\"cmd\":\"selectrow\",\"name\":\"listDialog\",\"row\":0}\n"
           "  {\"cmd\":\"click\",\"text\":\"OK\"}\n");
}

int main(int argc, char** argv) {
    uint64_t pid = 0;
    std::string name, script;
    bool allowShell = false;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--list")) {
            for (auto& e : listProcesses())
                printf("%6llu  %s\n", (unsigned long long)e.pid, e.name.c_str());
            return 0;
        } else if (!strcmp(argv[i], "--pid") && i + 1 < argc) {
            pid = strtoull(argv[++i], nullptr, 10);
        } else if (!strcmp(argv[i], "--name") && i + 1 < argc) {
            name = argv[++i];
        } else if (!strcmp(argv[i], "--allow-shell")) allowShell = true;
        else if (!strcmp(argv[i], "--script") && i + 1 < argc) {
            script = argv[++i];
        } else { usage(); return 1; }
    }

    Agent agent(allowShell);

    // otomatik baglanti (pid/name verildiyse)
    if (pid || !name.empty()) {
        Json att = Json::mkObj();
        att.set("cmd", "attach");
        if (pid) att.set("pid", (double)pid);
        if (!name.empty()) att.set("name", name);
        Json r = agent.execute(att);
        printf("%s\n", r.dump().c_str());
        fflush(stdout);
        if (!r["ok"].asBool()) return 2;
    }

    if (!script.empty()) {
        std::ofstream devnull;
        return agent.runScriptFile(script, std::cout);
    }

    return agent.runREPL(std::cin, std::cout);
}
