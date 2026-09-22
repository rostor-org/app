// Shared declarations for the Rostor credential provider.
//
// The provider exposes one tile with an identifier field, a secret field and a
// submit button. It contains no user-facing text: every label comes from the
// agent's `ui` reply over the named pipe (contract §2.1).
#pragma once

#ifndef WIN32_NO_STATUS
#include <ntstatus.h>
#define WIN32_NO_STATUS
#endif
#include <unknwn.h>
#include <windows.h>
#include <strsafe.h>
#include <credentialprovider.h>
#include <ntsecapi.h>
#define SECURITY_WIN32
#include <security.h>
#include <intsafe.h>
#include <new>
#include <string>
#include <map>

// Field order is also the display order inside the tile.
enum FIELD_ID
{
    SFI_LABEL     = 0,   // CPFT_LARGE_TEXT: tile_label (or `connecting` during submit)
    SFI_USERNAME  = 1,   // CPFT_EDIT_TEXT: identifier
    SFI_PASSWORD  = 2,   // CPFT_PASSWORD_TEXT: secret
    SFI_SUBMIT    = 3,   // CPFT_SUBMIT_BUTTON
    SFI_NUM_FIELDS = 4,
};

struct FIELD_STATE_PAIR
{
    CREDENTIAL_PROVIDER_FIELD_STATE cpfs;
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE cpfis;
};

// Labels are empty here on purpose: they are filled from the `ui` reply.
static const FIELD_STATE_PAIR s_rgFieldStatePairs[] =
{
    { CPFS_DISPLAY_IN_BOTH,          CPFIS_NONE    },  // SFI_LABEL
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_FOCUSED },  // SFI_USERNAME
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE    },  // SFI_PASSWORD
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE    },  // SFI_SUBMIT
};

static const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR s_rgFieldDescriptors[] =
{
    { SFI_LABEL,    CPFT_LARGE_TEXT,    const_cast<PWSTR>(L""), GUID_NULL },
    { SFI_USERNAME, CPFT_EDIT_TEXT,     const_cast<PWSTR>(L""), GUID_NULL },
    { SFI_PASSWORD, CPFT_PASSWORD_TEXT, const_cast<PWSTR>(L""), GUID_NULL },
    { SFI_SUBMIT,   CPFT_SUBMIT_BUTTON, const_cast<PWSTR>(L""), GUID_NULL },
};

// UI strings from the agent, keyed as in contract §2.1.
struct UiStrings
{
    std::wstring tile_label;
    std::wstring username_label;
    std::wstring password_label;
    std::wstring submit_label;
    std::wstring connecting;
};

// dll.cpp
void DllAddRef();
void DllRelease();

// helpers.cpp
HRESULT FieldDescriptorCoAllocCopy(const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR& rcpfd, PCWSTR pszLabel,
                                   CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd);
HRESULT KerbInteractiveUnlockLogonInit(PWSTR pwzDomain, PWSTR pwzUsername, PWSTR pwzPassword,
                                       CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
                                       KERB_INTERACTIVE_UNLOCK_LOGON* pkiul);
HRESULT KerbInteractiveUnlockLogonPack(const KERB_INTERACTIVE_UNLOCK_LOGON& rkiulIn, BYTE** prgb, DWORD* pcb);
HRESULT RetrieveNegotiateAuthPackage(ULONG* pulAuthPackage);
HRESULT ProtectIfNecessaryAndCopyPassword(PCWSTR pwzPassword, CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
                                          PWSTR* ppwzProtectedPassword);

// log.cpp — diagnostic log for Dan, never shown to users.
void LogLine(const char* fmt, ...);

// pipeclient.cpp — one request/reply over \\.\pipe\rostor-agent.
// Returns a flat map of the reply (nested keys joined with '.').
// On transport failure returns false and fills `code` with the agent-local
// code the credprov must report (agent.unreachable / agent.timeout).
bool PipeCall(const std::string& requestJson, std::map<std::string, std::string>& reply, std::string& code);
bool PipeFetchUi(UiStrings& out);

// json.cpp — just enough JSON for the flat objects in contract §2.
bool JsonParseFlat(const std::string& text, std::map<std::string, std::string>& out);
std::string JsonQuote(const std::wstring& s);
std::wstring Utf8ToWide(const std::string& s);
std::string WideToUtf8(const std::wstring& s);
