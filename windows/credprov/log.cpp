// Append-only diagnostic log at C:\ProgramData\Rostor\logs\credprov.log.
// LogonUI runs us as SYSTEM so the directory is writable. Nothing here is
// user-facing; secrets are never logged.
#include "common.h"
#include <cstdarg>
#include <cstdio>

void LogLine(const char* fmt, ...)
{
    char msg[1024];
    va_list ap;
    va_start(ap, fmt);
    StringCchVPrintfA(msg, ARRAYSIZE(msg), fmt, ap);
    va_end(ap);

    SYSTEMTIME st;
    GetLocalTime(&st);
    char line[1200];
    StringCchPrintfA(line, ARRAYSIZE(line), "%04u-%02u-%02u %02u:%02u:%02u [pid %lu] %s\r\n",
                     st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
                     GetCurrentProcessId(), msg);

    HANDLE h = CreateFileW(L"C:\\ProgramData\\Rostor\\logs\\credprov.log", FILE_APPEND_DATA,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD written = 0;
    WriteFile(h, line, (DWORD)strlen(line), &written, nullptr);
    CloseHandle(h);
}
