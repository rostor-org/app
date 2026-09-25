// Client side of contract §2: connect to \\.\pipe\rostor-deputy, write one
// newline-terminated JSON request, read one newline-terminated reply, close.
// The 30 s deadline is the contract's (§2); on expiry the result is deputy.timeout.
#include "common.h"

namespace {

const wchar_t* kPipePath = L"\\\\.\\pipe\\rostor-deputy";
const DWORD kTimeoutMs = 30000;

// Overlapped I/O lets us enforce the deadline without a worker thread.
bool WaitIo(HANDLE h, OVERLAPPED& ov, DWORD& transferred, DWORD deadlineTick)
{
    DWORD now = GetTickCount();
    DWORD remaining = (deadlineTick > now) ? (deadlineTick - now) : 0;
    DWORD w = WaitForSingleObject(ov.hEvent, remaining);
    if (w != WAIT_OBJECT_0)
    {
        CancelIo(h);
        return false;
    }
    return GetOverlappedResult(h, &ov, &transferred, TRUE) != FALSE;
}

} // namespace

bool PipeCall(const std::string& requestJson, std::map<std::string, std::string>& reply, std::string& code)
{
    reply.clear();
    code.clear();
    DWORD deadline = GetTickCount() + kTimeoutMs;

    HANDLE h = INVALID_HANDLE_VALUE;
    for (;;)
    {
        h = CreateFileW(kPipePath, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                        FILE_FLAG_OVERLAPPED, nullptr);
        if (h != INVALID_HANDLE_VALUE) break;
        DWORD err = GetLastError();
        if (err == ERROR_PIPE_BUSY && WaitNamedPipeW(kPipePath, 2000))
            continue;
        LogLine("pipe: connect failed (%lu)", err);
        code = "deputy.unreachable";
        return false;
    }

    OVERLAPPED ov = {};
    ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!ov.hEvent)
    {
        CloseHandle(h);
        code = "deputy.unreachable";
        return false;
    }

    bool ok = false;
    std::string line = requestJson + "\n";
    DWORD transferred = 0;
    if (!WriteFile(h, line.data(), (DWORD)line.size(), nullptr, &ov) && GetLastError() != ERROR_IO_PENDING)
    {
        LogLine("pipe: write failed (%lu)", GetLastError());
        code = "deputy.unreachable";
    }
    else if (!WaitIo(h, ov, transferred, deadline))
    {
        LogLine("pipe: write timed out");
        code = "deputy.timeout";
    }
    else
    {
        std::string buf;
        char chunk[4096];
        for (;;)
        {
            ResetEvent(ov.hEvent);
            if (!ReadFile(h, chunk, sizeof(chunk), nullptr, &ov) && GetLastError() != ERROR_IO_PENDING)
            {
                DWORD err = GetLastError();
                if (err == ERROR_BROKEN_PIPE || err == ERROR_HANDLE_EOF) break;
                LogLine("pipe: read failed (%lu)", err);
                code = "deputy.unreachable";
                break;
            }
            if (!WaitIo(h, ov, transferred, deadline))
            {
                DWORD err = GetLastError();
                if (err == ERROR_BROKEN_PIPE || err == ERROR_HANDLE_EOF) break;
                LogLine("pipe: read timed out");
                code = "deputy.timeout";
                break;
            }
            buf.append(chunk, transferred);
            if (buf.find('\n') != std::string::npos) break;
            if (buf.size() > 64 * 1024) { code = "deputy.unreachable"; break; }
        }
        if (code.empty())
        {
            size_t nl = buf.find('\n');
            std::string one = (nl == std::string::npos) ? buf : buf.substr(0, nl);
            if (one.empty() || !JsonParseFlat(one, reply))
            {
                LogLine("pipe: unparseable reply (%u bytes)", (unsigned)one.size());
                code = "deputy.unreachable";
            }
            else ok = true;
        }
    }
    // Wipe anything that may hold the secret before freeing.
    SecureZeroMemory(&line[0], line.size());
    CloseHandle(ov.hEvent);
    CloseHandle(h);
    return ok;
}

bool PipeFetchUi(UiStrings& out)
{
    std::map<std::string, std::string> reply;
    std::string code;
    if (!PipeCall("{\"op\":\"ui\",\"locale\":\"en-US\"}", reply, code) || reply["ok"] != "true")
    {
        LogLine("ui: no strings from deputy (%s)", code.empty() ? reply["code"].c_str() : code.c_str());
        return false;
    }
    out.tile_label     = Utf8ToWide(reply["strings.tile_label"]);
    out.username_label = Utf8ToWide(reply["strings.username_label"]);
    out.password_label = Utf8ToWide(reply["strings.password_label"]);
    out.submit_label   = Utf8ToWide(reply["strings.submit_label"]);
    out.connecting     = Utf8ToWide(reply["strings.connecting"]);
    out.pin_label      = Utf8ToWide(reply["strings.pin_label"]);
    out.badge_hint     = Utf8ToWide(reply["strings.badge_hint"]);
    // v0.11.0 / v0.13.0 additions; an older deputy leaves them empty and the
    // tile keeps its previous form (plain field, no link, tile_label on top).
    out.default_method     = Utf8ToWide(reply["default_method"]);
    out.default_provider   = Utf8ToWide(reply["default_provider"]);
    out.heading            = Utf8ToWide(reply["strings.heading"]);
    out.switch_to_username = Utf8ToWide(reply["strings.switch_to_username"]);
    out.switch_to_badge    = Utf8ToWide(reply["strings.switch_to_badge"]);
    return true;
}
