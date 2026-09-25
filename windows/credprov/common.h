// Shared declarations for the Rostor credential provider.
//
// The provider exposes one tile with two identifier fields (a plain one and a
// masked one, only one of which is visible at a time), a secret field, a PIN
// field (hidden until the deputy asks for a PIN after a badge tap), a submit
// button and a command link that swaps the identifier fields. It contains no
// user-facing text: every label comes from the deputy's `ui` reply over the
// named pipe (contract §2.1).
//
// Modes (contract §2.1, "Badge-first tile and the organisation name", v0.13.0):
//   username mode  plain identifier + secret; a digits-only burst with an
//                  empty secret is still sent as a badge (§2.3 heuristic).
//   badge mode     the masked field is the identifier — a reader burst shows
//                  as dots, never as digits — and whatever it holds is sent
//                  as a badge number; the secret field is hidden.
// The tile opens in badge mode when the `ui` reply says default_method is
// "badge" AND carries both link texts; otherwise in username mode. The link
// toggles between the two. An older deputy that sends no link texts leaves
// the tile exactly as before v0.13.0: plain field, no link.
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

// Field order is also the display order inside the tile. The IDs are private
// to this DLL and its harness (nothing in the registry or the pipe refers to
// them), so they were renumbered when SFI_BADGE and SFI_SWITCH were added.
enum FIELD_ID
{
    SFI_LABEL     = 0,   // CPFT_LARGE_TEXT: `heading` (tile_label from an older deputy); `connecting` during a submit; the deputy's prompt while a PIN is pending
    SFI_USERNAME  = 1,   // CPFT_EDIT_TEXT: plain identifier (username mode); a digits-only burst here is still a badge (§2.3)
    SFI_BADGE     = 2,   // CPFT_PASSWORD_TEXT: masked identifier (badge mode); its text is always sent as a badge number
    SFI_PASSWORD  = 3,   // CPFT_PASSWORD_TEXT: secret; shown in username mode only
    SFI_PIN       = 4,   // CPFT_PASSWORD_TEXT: badge PIN; hidden unless the deputy asked for it
    SFI_SUBMIT    = 5,   // CPFT_SUBMIT_BUTTON: next to the secret, the masked field or the PIN, whichever is live
    SFI_SWITCH    = 6,   // CPFT_COMMAND_LINK: switch_to_username / switch_to_badge; hidden without link texts and while a PIN is pending
    SFI_TILEIMAGE = 7,   // CPFT_TILE_IMAGE: tile.bmp from the install dir
    SFI_NUM_FIELDS = 8,
};

struct FIELD_STATE_PAIR
{
    CREDENTIAL_PROVIDER_FIELD_STATE cpfs;
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE cpfis;
};

// Username-mode defaults. The credential recomputes the states of
// SFI_USERNAME, SFI_BADGE, SFI_PASSWORD, SFI_PIN and SFI_SWITCH from its mode
// flags (CRostorCredential::ApplyFieldStates); the rest never change.
// Labels are empty here on purpose: they are filled from the `ui` reply.
static const FIELD_STATE_PAIR s_rgFieldStatePairs[] =
{
    { CPFS_DISPLAY_IN_BOTH,          CPFIS_NONE    },  // SFI_LABEL
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_FOCUSED },  // SFI_USERNAME
    { CPFS_HIDDEN,                   CPFIS_NONE    },  // SFI_BADGE (shown in badge mode only)
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE    },  // SFI_PASSWORD
    { CPFS_HIDDEN,                   CPFIS_NONE    },  // SFI_PIN (shown in PIN mode only)
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE    },  // SFI_SUBMIT
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE    },  // SFI_SWITCH (hidden when the deputy sent no link texts)
    { CPFS_DISPLAY_IN_BOTH,          CPFIS_NONE    },  // SFI_TILEIMAGE
};

static const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR s_rgFieldDescriptors[] =
{
    { SFI_LABEL,     CPFT_LARGE_TEXT,    const_cast<PWSTR>(L""), GUID_NULL },
    { SFI_USERNAME,  CPFT_EDIT_TEXT,     const_cast<PWSTR>(L""), GUID_NULL },
    { SFI_BADGE,     CPFT_PASSWORD_TEXT, const_cast<PWSTR>(L""), GUID_NULL },
    { SFI_PASSWORD,  CPFT_PASSWORD_TEXT, const_cast<PWSTR>(L""), GUID_NULL },
    { SFI_PIN,       CPFT_PASSWORD_TEXT, const_cast<PWSTR>(L""), GUID_NULL },
    { SFI_SUBMIT,    CPFT_SUBMIT_BUTTON, const_cast<PWSTR>(L""), GUID_NULL },
    { SFI_SWITCH,    CPFT_COMMAND_LINK,  const_cast<PWSTR>(L""), GUID_NULL },
    { SFI_TILEIMAGE, CPFT_TILE_IMAGE,    const_cast<PWSTR>(L""), GUID_NULL },
};

// UI strings from the deputy, keyed as in contract §2.1. The last four are
// v0.13.0 additions and stay empty when an older deputy answers.
struct UiStrings
{
    std::wstring tile_label;
    std::wstring username_label;
    std::wstring password_label;
    std::wstring submit_label;
    std::wstring connecting;
    std::wstring pin_label;          // label of the PIN field (badge + PIN)
    std::wstring badge_hint;         // cue text of the plain identifier field ("Tap your badge or …")
    std::wstring default_method;     // "password" | "passkey" | "badge" (top-level key of the `ui` reply)
    std::wstring default_provider;   // "rostor" | "windows": which tile the lock screen selects (top-level key; empty = rostor)
    std::wstring heading;            // large text: "Sign in to <tenant>" / "Tap your badge · <tenant>"
    std::wstring switch_to_username; // command-link text while in badge mode
    std::wstring switch_to_badge;    // command-link text while in username mode
};

// Both link texts arrived: the tile can offer the other method.
inline bool HasSwitchLink(const UiStrings& ui)
{
    return !ui.switch_to_username.empty() && !ui.switch_to_badge.empty();
}

// Badge mode is entered on open only when the policy asks for it AND the
// person can switch back; a masked field with no way out would trap anyone
// who needs to type a username.
inline bool OpensInBadgeMode(const UiStrings& ui)
{
    return HasSwitchLink(ui) && ui.default_method == L"badge";
}

// "Which tile is the default" (contract §2.1, v0.13.0): only an explicit
// "windows" hands the selection to Windows' own password tile; absent
// (older deputy), "rostor" or anything else keeps the Rostor tile selected.
inline bool WindowsIsDefaultTile(const UiStrings& ui)
{
    return ui.default_provider == L"windows";
}

// Field labels by field ID, from the `ui` strings. LogonUI renders an edit or
// password field's label as its cue banner, so the plain identifier field
// carries the badge hint (falling back to the plain username label from an
// older deputy) and the masked one the username label, as the contract says.
// The command link's descriptor label is its text in the mode the tile opens
// in; the live text is the field's string value, which the credential updates.
inline PCWSTR FieldLabel(const UiStrings& ui, DWORD fieldID)
{
    switch (fieldID)
    {
    case SFI_USERNAME: return ui.badge_hint.empty() ? ui.username_label.c_str() : ui.badge_hint.c_str();
    case SFI_BADGE:    return ui.username_label.c_str();
    case SFI_PASSWORD: return ui.password_label.c_str();
    case SFI_PIN:      return ui.pin_label.c_str();
    case SFI_SUBMIT:   return ui.submit_label.c_str();
    case SFI_SWITCH:   return OpensInBadgeMode(ui) ? ui.switch_to_username.c_str() : ui.switch_to_badge.c_str();
    default:           return L"";
    }
}

// A keyboard-wedge badge reader types the card number as digits and ends with
// Enter. Six digits is below any real card format and above anything a person
// would plausibly use as a username, so digits-only text of that length in the
// plain identifier field with an empty secret is treated as a tap (contract
// §2.3). The masked field needs no such test: its text is always a badge.
inline bool LooksLikeBadgeBurst(PCWSTR text)
{
    if (!text) return false;
    size_t n = 0;
    for (; text[n]; ++n)
        if (text[n] < L'0' || text[n] > L'9') return false;
    return n >= 6;
}

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

// pipeclient.cpp — one request/reply over \\.\pipe\rostor-deputy.
// Returns a flat map of the reply (nested keys joined with '.').
// On transport failure returns false and fills `code` with the deputy-local
// code the credprov must report (deputy.unreachable / deputy.timeout).
bool PipeCall(const std::string& requestJson, std::map<std::string, std::string>& reply, std::string& code);
bool PipeFetchUi(UiStrings& out);

// json.cpp — just enough JSON for the flat objects in contract §2.
bool JsonParseFlat(const std::string& text, std::map<std::string, std::string>& out);
std::string JsonQuote(const std::wstring& s);
std::wstring Utf8ToWide(const std::string& s);
std::string WideToUtf8(const std::wstring& s);
