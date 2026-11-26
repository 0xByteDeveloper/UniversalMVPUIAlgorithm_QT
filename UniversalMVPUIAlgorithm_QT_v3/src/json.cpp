// UMVPQT GOD STATE — Minimal JSON uygulamasi
// ============================================================================
#include "umvpqt/json.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cctype>

namespace umvpqt {

static const Json kNullJson;

const Json& Json::operator[](const std::string& key) const {
    for (auto& kv : obj) if (kv.first == key) return kv.second;
    return kNullJson;
}

void Json::set(const std::string& key, Json v) {
    if (type == Type::Null) type = Type::Obj;
    for (auto& kv : obj)
        if (kv.first == key) { kv.second = std::move(v); return; }
    obj.emplace_back(key, std::move(v));
}

std::string Json::asStr(const std::string& def) const {
    if (type == Type::Str) return str;
    if (type == Type::Num) { char b[64]; snprintf(b, sizeof(b), "%g", num); return b; }
    return def;
}
double Json::asNum(double def) const {
    if (type == Type::Num) return num;
    if (type == Type::Bool) return b ? 1 : 0;
    return def;
}
bool Json::asBool(bool def) const {
    if (type == Type::Bool) return b;
    if (type == Type::Num) return num != 0;
    if (type == Type::Str) return str == "true" || str == "1" || str == "yes" || str == "Yes" || str == "YES";
    return def;
}
bool Json::has(const std::string& key) const {
    for (auto& kv : obj) if (kv.first == key) return true;
    return false;
}

// ---------------------------------------------------------------- serilestir
std::string jsonEscape(const std::string& s) {
    std::string out = "\"";
    for (unsigned char c : s) {
        switch (c) {
        case '"':  out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n";  break;
        case '\r': out += "\\r";  break;
        case '\t': out += "\\t";  break;
        default:
            if (c < 0x20) { char b[8]; snprintf(b, sizeof(b), "\\u%04x", c); out += b; }
            else out += (char)c;
        }
    }
    out += '"';
    return out;
}

static void dumpTo(const Json& j, std::string& out) {
    char b[64];
    switch (j.type) {
    case Json::Type::Null: out += "null"; break;
    case Json::Type::Bool: out += j.b ? "true" : "false"; break;
    case Json::Type::Num: {
        if (j.num == (long long)j.num) snprintf(b, sizeof(b), "%lld", (long long)j.num);
        else snprintf(b, sizeof(b), "%g", j.num);
        out += b;
        break;
    }
    case Json::Type::Str: out += jsonEscape(j.str); break;
    case Json::Type::Arr: {
        out += '[';
        bool first = true;
        for (auto& e : j.arr) { if (!first) out += ','; first = false; dumpTo(e, out); }
        out += ']';
        break;
    }
    case Json::Type::Obj: {
        out += '{';
        bool first = true;
        for (auto& kv : j.obj) {
            if (!first) out += ',';
            first = false;
            out += jsonEscape(kv.first);
            out += ':';
            dumpTo(kv.second, out);
        }
        out += '}';
        break;
    }
    }
}

std::string Json::dump() const {
    std::string out;
    dumpTo(*this, out);
    return out;
}

// ------------------------------------------------------------------- parser
namespace {
struct P {
    const char* p;
    const char* end;
    bool ok = true;
    void ws() { while (p < end && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')) p++; }
    bool parseVal(Json& out) {
        ws();
        if (p >= end) return false;
        char c = *p;
        if (c == '{') return parseObj(out);
        if (c == '[') return parseArr(out);
        if (c == '"') { out.type = Json::Type::Str; return parseStr(out.str); }
        if (c == 't' || c == 'f') {
            if (end - p >= 4 && memcmp(p, "true", 4) == 0)  { out.type = Json::Type::Bool; out.b = true;  p += 4; return true; }
            if (end - p >= 5 && memcmp(p, "false", 5) == 0) { out.type = Json::Type::Bool; out.b = false; p += 5; return true; }
            return false;
        }
        if (c == 'n') {
            if (end - p >= 4 && memcmp(p, "null", 4) == 0) { p += 4; return true; }
            return false;
        }
        // sayi
        char* e = nullptr;
        double d = strtod(p, &e);
        if (e == p || e > end) return false;
        out.type = Json::Type::Num;
        out.num = d;
        p = e;
        return true;
    }
    bool parseObj(Json& out) {
        p++; // '{'
        out.type = Json::Type::Obj;
        ws();
        if (p < end && *p == '}') { p++; return true; }
        while (p < end) {
            ws();
            if (*p != '"') return false;
            std::string key;
            if (!parseStr(key)) return false;
            ws();
            if (p >= end || *p != ':') return false;
            p++;
            Json v;
            if (!parseVal(v)) return false;
            out.obj.emplace_back(std::move(key), std::move(v));
            ws();
            if (p < end && *p == ',') { p++; continue; }
            if (p < end && *p == '}') { p++; return true; }
            return false;
        }
        return false;
    }
    bool parseArr(Json& out) {
        p++; // '['
        out.type = Json::Type::Arr;
        ws();
        if (p < end && *p == ']') { p++; return true; }
        while (p < end) {
            Json v;
            if (!parseVal(v)) return false;
            out.arr.push_back(std::move(v));
            ws();
            if (p < end && *p == ',') { p++; continue; }
            if (p < end && *p == ']') { p++; return true; }
            return false;
        }
        return false;
    }
    bool parseStr(std::string& out) {
        if (p >= end || *p != '"') return false;
        p++;
        while (p < end && *p != '"') {
            char c = *p;
            if (c == '\\') {
                p++;
                if (p >= end) return false;
                char e = *p;
                switch (e) {
                case 'n': out += '\n'; break;
                case 't': out += '\t'; break;
                case 'r': out += '\r'; break;
                case 'b': out += '\b'; break;
                case 'f': out += '\f'; break;
                case '/': out += '/';  break;
                case '"': out += '"';  break;
                case '\\': out += '\\'; break;
                case 'u': {
                    if (end - p < 5) return false;
                    unsigned cp = 0;
                    for (int i = 1; i <= 4; i++) {
                        char h = p[i];
                        cp <<= 4;
                        if (h >= '0' && h <= '9') cp |= h - '0';
                        else if (h >= 'a' && h <= 'f') cp |= h - 'a' + 10;
                        else if (h >= 'A' && h <= 'F') cp |= h - 'A' + 10;
                        else return false;
                    }
                    p += 4;
                    // UTF-16 surrogate cifti
                    if (cp >= 0xD800 && cp <= 0xDBFF && end - p >= 7 && p[1] == '\\' && p[2] == 'u') {
                        unsigned lo = 0;
                        for (int i = 3; i <= 6; i++) {
                            char h = p[i];
                            lo <<= 4;
                            if (h >= '0' && h <= '9') lo |= h - '0';
                            else if (h >= 'a' && h <= 'f') lo |= h - 'a' + 10;
                            else if (h >= 'A' && h <= 'F') lo |= h - 'A' + 10;
                        }
                        if (lo >= 0xDC00 && lo <= 0xDFFF) {
                            cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                            p += 6;
                        }
                    }
                    if (cp < 0x80) out += (char)cp;
                    else if (cp < 0x800) {
                        out += (char)(0xC0 | (cp >> 6));
                        out += (char)(0x80 | (cp & 0x3F));
                    } else {
                        out += (char)(0xE0 | (cp >> 12));
                        out += (char)(0x80 | ((cp >> 6) & 0x3F));
                        out += (char)(0x80 | (cp & 0x3F));
                    }
                    break;
                }
                default: out += e; break;
                }
                p++;
            } else {
                out += c;
                p++;
            }
        }
        if (p >= end) return false;
        p++; // kapanis "
        return true;
    }
};
} // namespace

bool JsonParser::parse(const std::string& text, Json& out) {
    P ps{ text.c_str(), text.c_str() + text.size() };
    if (!ps.parseVal(out)) return false;
    return true;
}

// ------------------------------------------------------- 0x adresi parse ----
bool parseAddr(const std::string& s, uint64_t& out) {
    if (s.empty()) return false;
    const char* p = s.c_str();
    int base = 10;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) { base = 16; p += 2; }
    char* e = nullptr;
    out = strtoull(p, &e, base);
    return e && *e == 0 && e != p;
}

} // namespace umvpqt
