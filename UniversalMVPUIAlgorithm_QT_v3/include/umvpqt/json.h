// UMVPQT GOD STATE — Minimal JSON (ajan protokolu icin)
// ============================================================================
//  Agent CLI'nin komut protokolunu JSON-lines uzerinden tasir.
//  Kucuk, bagimsiz, harici kutuphane yok (XPRO tarzi sade SDK).
// ============================================================================
#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <memory>

namespace umvpqt {

// JSON degeri: null | bool | sayi | string | array | object
struct Json {
    enum class Type { Null, Bool, Num, Str, Arr, Obj };
    Type type = Type::Null;
    bool    b = false;
    double  num = 0;
    std::string str;
    std::vector<Json> arr;
    std::vector<std::pair<std::string, Json>> obj;   // anahtar sirali degil — kucuk

    // ---- yardimcilar ----
    bool isNull()  const { return type == Type::Null; }
    bool isStr()   const { return type == Type::Str; }
    bool isNum()   const { return type == Type::Num; }
    bool isArr()   const { return type == Type::Arr; }
    bool isObj()   const { return type == Type::Obj; }
    bool isBool()  const { return type == Type::Bool; }

    // obj["anahtar"] — yoksa Null doner
    const Json& operator[](const std::string& key) const;
    // obj set
    void set(const std::string& key, Json v);
    void set(const std::string& key, const char* s) { set(key, Json::mkStr(s)); }
    void set(const std::string& key, const std::string& s) { set(key, Json::mkStr(s)); }
    void set(const std::string& key, double n) { set(key, Json::mkNum(n)); }
    void set(const std::string& key, bool bv)  { set(key, Json::mkBool(bv)); }
    // array push
    void push(Json v) { if (type == Type::Null) type = Type::Arr; arr.push_back(std::move(v)); }
    void push(const std::string& s) { if (type == Type::Null) type = Type::Arr; arr.push_back(Json::mkStr(s)); }

    // ---- fabrikalar ----
    static Json mkStr(const std::string& s)  { Json j; j.type = Type::Str;  j.str = s; return j; }
    static Json mkNum(double n)              { Json j; j.type = Type::Num;  j.num = n; return j; }
    static Json mkBool(bool b)                { Json j; j.type = Type::Bool; j.b = b;   return j; }
    static Json mkObj()                       { Json j; j.type = Type::Obj;  return j; }
    static Json mkArr()                       { Json j; j.type = Type::Arr;  return j; }

    // ---- tarama yardimcilari ----
    std::string asStr(const std::string& def = "") const;
    double      asNum(double def = 0) const;
    bool        asBool(bool def = false) const;
    bool        has(const std::string& key) const;

    // ---- serilestirme ----
    std::string dump() const;
};

// Kucuk, tolere edici parser (tek satir / butun metin)
//  Basarisizsa {ok:false} doner.
struct JsonParser {
    static bool parse(const std::string& text, Json& out);
};

// ---- yardimci: JSON string escape ----
std::string jsonEscape(const std::string& s);

// ---- yardimci: 0x... / tam sayi adresi parse ----
bool parseAddr(const std::string& s, uint64_t& out);

} // namespace umvpqt
