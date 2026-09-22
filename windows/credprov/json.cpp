// Minimal JSON reader/writer for the contract §2 messages. Objects are
// flattened ("strings.tile_label"); arrays are skipped; numbers, bools and
// null are stored as their literal text. Not a general-purpose parser.
#include "common.h"
#include <cstdlib>

namespace {

struct Reader
{
    const std::string& s;
    size_t i = 0;
    explicit Reader(const std::string& text) : s(text) {}

    void ws() { while (i < s.size() && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n')) ++i; }
    bool eof() const { return i >= s.size(); }
    char peek() const { return eof() ? '\0' : s[i]; }
    bool take(char c) { ws(); if (peek() == c) { ++i; return true; } return false; }

    static void putUtf8(std::string& out, unsigned cp)
    {
        if (cp < 0x80) out += (char)cp;
        else if (cp < 0x800) { out += (char)(0xC0 | (cp >> 6)); out += (char)(0x80 | (cp & 0x3F)); }
        else if (cp < 0x10000) { out += (char)(0xE0 | (cp >> 12)); out += (char)(0x80 | ((cp >> 6) & 0x3F)); out += (char)(0x80 | (cp & 0x3F)); }
        else { out += (char)(0xF0 | (cp >> 18)); out += (char)(0x80 | ((cp >> 12) & 0x3F)); out += (char)(0x80 | ((cp >> 6) & 0x3F)); out += (char)(0x80 | (cp & 0x3F)); }
    }

    bool hex4(unsigned& v)
    {
        if (i + 4 > s.size()) return false;
        v = 0;
        for (int k = 0; k < 4; ++k)
        {
            char c = s[i++];
            v <<= 4;
            if (c >= '0' && c <= '9') v |= (unsigned)(c - '0');
            else if (c >= 'a' && c <= 'f') v |= (unsigned)(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') v |= (unsigned)(c - 'A' + 10);
            else return false;
        }
        return true;
    }

    bool str(std::string& out)
    {
        ws();
        if (peek() != '"') return false;
        ++i;
        out.clear();
        while (!eof())
        {
            char c = s[i++];
            if (c == '"') return true;
            if (c != '\\') { out += c; continue; }
            if (eof()) return false;
            char e = s[i++];
            switch (e)
            {
            case '"': out += '"'; break;
            case '\\': out += '\\'; break;
            case '/': out += '/'; break;
            case 'b': out += '\b'; break;
            case 'f': out += '\f'; break;
            case 'n': out += '\n'; break;
            case 'r': out += '\r'; break;
            case 't': out += '\t'; break;
            case 'u':
            {
                unsigned cp;
                if (!hex4(cp)) return false;
                if (cp >= 0xD800 && cp <= 0xDBFF)
                {
                    // Surrogate pair: expect \uDC00..\uDFFF next.
                    unsigned lo;
                    if (i + 6 <= s.size() && s[i] == '\\' && s[i + 1] == 'u')
                    {
                        i += 2;
                        if (!hex4(lo)) return false;
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                    }
                }
                putUtf8(out, cp);
                break;
            }
            default: return false;
            }
        }
        return false;
    }

    bool skipValue()
    {
        ws();
        char c = peek();
        if (c == '"') { std::string tmp; return str(tmp); }
        if (c == '{')
        {
            ++i;
            if (take('}')) return true;
            for (;;)
            {
                std::string k;
                if (!str(k) || !take(':') || !skipValue()) return false;
                if (take(',')) continue;
                return take('}');
            }
        }
        if (c == '[')
        {
            ++i;
            if (take(']')) return true;
            for (;;)
            {
                if (!skipValue()) return false;
                if (take(',')) continue;
                return take(']');
            }
        }
        while (!eof() && s[i] != ',' && s[i] != '}' && s[i] != ']' && s[i] != ' ' && s[i] != '\n' && s[i] != '\r' && s[i] != '\t') ++i;
        return true;
    }

    bool value(const std::string& key, std::map<std::string, std::string>& out)
    {
        ws();
        char c = peek();
        if (c == '"')
        {
            std::string v;
            if (!str(v)) return false;
            out[key] = v;
            return true;
        }
        if (c == '{') return object(key.empty() ? key : key + ".", out);
        if (c == '[') return skipValue();
        size_t start = i;
        while (!eof() && s[i] != ',' && s[i] != '}' && s[i] != ']' && s[i] != ' ' && s[i] != '\n' && s[i] != '\r' && s[i] != '\t') ++i;
        if (i == start) return false;
        out[key] = s.substr(start, i - start);
        return true;
    }

    bool object(const std::string& prefix, std::map<std::string, std::string>& out)
    {
        if (!take('{')) return false;
        if (take('}')) return true;
        for (;;)
        {
            std::string k;
            if (!str(k) || !take(':')) return false;
            if (!value(prefix + k, out)) return false;
            if (take(',')) continue;
            return take('}');
        }
    }
};

} // namespace

bool JsonParseFlat(const std::string& text, std::map<std::string, std::string>& out)
{
    out.clear();
    Reader r(text);
    if (!r.object("", out)) return false;
    r.ws();
    return true;
}

std::string JsonQuote(const std::wstring& ws)
{
    std::string s = WideToUtf8(ws);
    std::string out = "\"";
    for (unsigned char c : s)
    {
        switch (c)
        {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (c < 0x20)
            {
                char buf[8];
                StringCchPrintfA(buf, ARRAYSIZE(buf), "\\u%04x", c);
                out += buf;
            }
            else out += (char)c;
        }
    }
    out += "\"";
    return out;
}

std::wstring Utf8ToWide(const std::string& s)
{
    if (s.empty()) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    if (n <= 0) return std::wstring();
    std::wstring out((size_t)n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), &out[0], n);
    return out;
}

std::string WideToUtf8(const std::wstring& ws)
{
    if (ws.empty()) return std::string();
    int n = WideCharToMultiByte(CP_UTF8, 0, ws.data(), (int)ws.size(), nullptr, 0, nullptr, nullptr);
    if (n <= 0) return std::string();
    std::string out((size_t)n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, ws.data(), (int)ws.size(), &out[0], n, nullptr, nullptr);
    return out;
}
