// Console self-test for json.cpp. Built and run by test.cmd; not part of the DLL.
#include "common.h"
#include <cstdio>

static int failures = 0;
#define CHECK(cond) do { if (!(cond)) { printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #cond); ++failures; } } while (0)

int main()
{
    std::map<std::string, std::string> m;

    CHECK(JsonParseFlat("{\"ok\": true, \"strings\": {\"tile_label\": \"Rostor\", \"connecting\": \"Contacting Rostor\\u2026\"}}", m));
    CHECK(m["ok"] == "true");
    CHECK(m["strings.tile_label"] == "Rostor");
    CHECK(m["strings.connecting"] == "Contacting Rostor\xE2\x80\xA6");

    CHECK(JsonParseFlat("{\"ok\":false,\"code\":\"auth.failed\",\"message\":\"Sign-in failed.\"}", m));
    CHECK(m["ok"] == "false" && m["code"] == "auth.failed" && m["message"] == "Sign-in failed.");

    CHECK(JsonParseFlat("{\"ok\":true,\"local_user\":\"dan\",\"local_secret\":\"a\\\"b\\\\c\\n\"}", m));
    CHECK(m["local_secret"] == "a\"b\\c\n");

    // Arrays are skipped; numbers/null kept as literals; nested objects flattened.
    CHECK(JsonParseFlat("{\"reason\":[{\"code\":\"x\"},2],\"n\":42,\"z\":null,\"o\":{\"p\":{\"q\":\"deep\"}}}", m));
    CHECK(m.find("reason") == m.end());
    CHECK(m["n"] == "42" && m["z"] == "null" && m["o.p.q"] == "deep");

    // Surrogate pair.
    CHECK(JsonParseFlat("{\"e\":\"\\ud83d\\ude00\"}", m));
    CHECK(m["e"] == "\xF0\x9F\x98\x80");

    // Malformed input is rejected, never partially trusted.
    CHECK(!JsonParseFlat("{\"ok\":true", m));
    CHECK(!JsonParseFlat("[1,2]", m));
    CHECK(!JsonParseFlat("", m));
    CHECK(!JsonParseFlat("{\"a\":\"\\x\"}", m));

    // Quoting round-trips through the parser.
    std::wstring secret = L"p\"a\\s\ns\tw\x2026rd\x01";
    std::string doc = "{\"s\":" + JsonQuote(secret) + "}";
    CHECK(JsonParseFlat(doc, m));
    CHECK(Utf8ToWide(m["s"]) == secret);

    printf(failures ? "json_test: %d failure(s)\n" : "json_test: all passed\n", failures);
    return failures ? 1 : 0;
}
