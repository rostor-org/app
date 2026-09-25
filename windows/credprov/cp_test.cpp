// Console harness: drives RostorCredProv.dll through the same COM calls
// LogonUI makes, against the running deputy, without registering the DLL.
// Run elevated (the pipe DACL admits Administrators). Built by test.cmd.
//
//   cp_test <dll> <identifier> <secret> [expect-ok|expect-deny]
//   cp_test <dll> --badge <number> <pin|-> expect-ok|expect-deny|expect-pin
//   cp_test <dll> --badge-plain <number> <pin|-> expect-ok|expect-deny|expect-pin
//
// The harness first reads the deputy's `ui` reply itself (pipeclient.cpp),
// so it knows which mode the tile opens in and which tile the policy makes
// the default, and checks the DLL against that.
//
// A password run puts the tile in username mode (clicking the switch link
// when the policy opened it in badge mode), types identifier and secret and
// submits. `--badge` is the badge-first tile (contract §2.1, v0.13.0): it puts
// the tile in badge mode (clicking the link when needed — a v0.13.0 deputy is
// required), types the number into the masked field and submits.
// `--badge-plain` is the pre-v0.13.0 path: the number goes into the plain
// identifier field with an empty secret and the digits-only heuristic turns
// it into a badge. With a PIN given, the first submit must answer
// auth.continue (PIN mode), then the PIN is typed into the PIN field and
// submitted again.
#include "common.h"
#include <cstdio>
#include <cstring>
#include <shlwapi.h>

// {7A4C2E10-5B0D-4F4E-9C1B-3E2D7F1A6B01}
static const CLSID kClsid = { 0x7A4C2E10, 0x5B0D, 0x4F4E, { 0x9C, 0x1B, 0x3E, 0x2D, 0x7F, 0x1A, 0x6B, 0x01 } };

static int failures = 0;
#define CHECK(cond) do { if (!(cond)) { printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #cond); ++failures; } } while (0)

// Records what the credential asks LogonUI to change, so mode switches and
// PIN mode can be checked through the same channel LogonUI sees rather than
// via GetFieldState alone.
struct EventsStub : ICredentialProviderCredentialEvents
{
    DWORD submitAdjacentTo = SFI_PASSWORD;
    CREDENTIAL_PROVIDER_FIELD_STATE state[SFI_NUM_FIELDS] = {};
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE istate[SFI_NUM_FIELDS] = {};
    std::wstring strings[SFI_NUM_FIELDS];

    IFACEMETHODIMP_(ULONG) AddRef() { return 2; }
    IFACEMETHODIMP_(ULONG) Release() { return 1; }
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv)
    {
        if (riid == IID_IUnknown || riid == IID_ICredentialProviderCredentialEvents) { *ppv = this; return S_OK; }
        *ppv = nullptr; return E_NOINTERFACE;
    }
    IFACEMETHODIMP SetFieldState(ICredentialProviderCredential*, DWORD id, CREDENTIAL_PROVIDER_FIELD_STATE s)
    { if (id < SFI_NUM_FIELDS) state[id] = s; return S_OK; }
    IFACEMETHODIMP SetFieldInteractiveState(ICredentialProviderCredential*, DWORD id, CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE s)
    { if (id < SFI_NUM_FIELDS) istate[id] = s; return S_OK; }
    IFACEMETHODIMP SetFieldString(ICredentialProviderCredential*, DWORD id, LPCWSTR s)
    { if (id < SFI_NUM_FIELDS) strings[id] = s ? s : L""; return S_OK; }
    IFACEMETHODIMP SetFieldCheckbox(ICredentialProviderCredential*, DWORD, BOOL, LPCWSTR) { return S_OK; }
    IFACEMETHODIMP SetFieldBitmap(ICredentialProviderCredential*, DWORD, HBITMAP) { return S_OK; }
    IFACEMETHODIMP SetFieldComboBoxSelectedItem(ICredentialProviderCredential*, DWORD, DWORD) { return S_OK; }
    IFACEMETHODIMP DeleteFieldComboBoxItem(ICredentialProviderCredential*, DWORD, DWORD) { return S_OK; }
    IFACEMETHODIMP AppendFieldComboBoxItem(ICredentialProviderCredential*, DWORD, LPCWSTR) { return S_OK; }
    IFACEMETHODIMP SetFieldSubmitButton(ICredentialProviderCredential*, DWORD, DWORD adjacentTo)
    { submitAdjacentTo = adjacentTo; return S_OK; }
    IFACEMETHODIMP OnCreatingWindow(HWND*) { return S_OK; }
};

static std::string narrow(PCWSTR s) { return WideToUtf8(s ? s : L""); }

// One submit round; returns the response so callers can chain.
static CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE Submit(ICredentialProviderCredential* cred, const char* expect)
{
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE resp = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION ser = {};
    PWSTR status = nullptr;
    CREDENTIAL_PROVIDER_STATUS_ICON icon = CPSI_NONE;
    HRESULT hr = cred->GetSerialization(&resp, &ser, &status, &icon);
    printf("GetSerialization hr=0x%08lx resp=%d status='%s' icon=%d (%s)\n", hr, (int)resp, narrow(status).c_str(), (int)icon, expect);
    CHECK(SUCCEEDED(hr));

    if (strcmp(expect, "expect-ok") == 0)
    {
        CHECK(resp == CPGSR_RETURN_CREDENTIAL_FINISHED);
        CHECK(ser.rgbSerialization != nullptr && ser.cbSerialization > sizeof(KERB_INTERACTIVE_UNLOCK_LOGON));
        CHECK(IsEqualCLSID(ser.clsidCredentialProvider, kClsid));
        // Negotiate is package 0 on current Windows; only the lookup's HRESULT matters.
        printf("auth package id %lu\n", ser.ulAuthenticationPackage);
        if (ser.rgbSerialization)
        {
            auto kiul = (KERB_INTERACTIVE_UNLOCK_LOGON*)ser.rgbSerialization;
            CHECK(kiul->Logon.MessageType == KerbInteractiveLogon);
            auto str = [&](const UNICODE_STRING& us) {
                return std::wstring((PCWSTR)(ser.rgbSerialization + (size_t)us.Buffer), us.Length / sizeof(wchar_t));
            };
            std::wstring domain = str(kiul->Logon.LogonDomainName), user = str(kiul->Logon.UserName), pw = str(kiul->Logon.Password);
            printf("packed domain='%s' user='%s' password_len=%u (protected=%s)\n",
                   WideToUtf8(domain).c_str(), WideToUtf8(user).c_str(), (unsigned)pw.size(),
                   pw.size() > 32 ? "yes" : "no");
            CHECK(domain == L".");
            CHECK(!user.empty());
            CHECK(!pw.empty());
            CoTaskMemFree(ser.rgbSerialization);
        }
    }
    else if (strcmp(expect, "expect-pin") == 0)
    {
        // auth.continue: the tile stays up, asks for the PIN, no error icon.
        CHECK(resp == CPGSR_NO_CREDENTIAL_NOT_FINISHED);
        CHECK(icon == CPSI_NONE);
        CHECK(status && *status);
        CHECK(ser.rgbSerialization == nullptr);
    }
    else
    {
        CHECK(resp == CPGSR_NO_CREDENTIAL_FINISHED);
        CHECK(icon == CPSI_ERROR);
        CHECK(status && *status);
        CHECK(ser.rgbSerialization == nullptr);
    }
    CoTaskMemFree(status);
    return resp;
}

static void CheckFieldState(ICredentialProviderCredential* cred, DWORD id,
                            CREDENTIAL_PROVIDER_FIELD_STATE wantS, CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE wantI)
{
    CREDENTIAL_PROVIDER_FIELD_STATE s; CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE i;
    CHECK(SUCCEEDED(cred->GetFieldState(id, &s, &i)));
    if (s != wantS || i != wantI) { printf("FAIL field %lu state %d/%d want %d/%d\n", id, (int)s, (int)i, (int)wantS, (int)wantI); ++failures; }
}

static bool FieldDisplayed(ICredentialProviderCredential* cred, DWORD id)
{
    CREDENTIAL_PROVIDER_FIELD_STATE s = CPFS_HIDDEN; CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE i = CPFIS_NONE;
    CHECK(SUCCEEDED(cred->GetFieldState(id, &s, &i)));
    return s == CPFS_DISPLAY_IN_SELECTED_TILE || s == CPFS_DISPLAY_IN_BOTH;
}

static std::wstring StringValue(ICredentialProviderCredential* cred, DWORD id)
{
    PWSTR v = nullptr;
    CHECK(SUCCEEDED(cred->GetStringValue(id, &v)));
    std::wstring out = v ? v : L"";
    CoTaskMemFree(v);
    return out;
}

// The tile's initial form in a mode: the live identifier field shown and
// focused, the other hidden; secret shown only in username mode; PIN hidden;
// link shown iff the deputy sent it; submit next to the secret or the masked field.
static void CheckInitialForm(ICredentialProviderCredential* cred, bool badgeMode, bool haveSwitch)
{
    if (badgeMode)
    {
        CheckFieldState(cred, SFI_BADGE,    CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_FOCUSED);
        CheckFieldState(cred, SFI_USERNAME, CPFS_HIDDEN,                   CPFIS_NONE);
        CheckFieldState(cred, SFI_PASSWORD, CPFS_HIDDEN,                   CPFIS_NONE);
    }
    else
    {
        CheckFieldState(cred, SFI_USERNAME, CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_FOCUSED);
        CheckFieldState(cred, SFI_BADGE,    CPFS_HIDDEN,                   CPFIS_NONE);
        CheckFieldState(cred, SFI_PASSWORD, CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE);
    }
    CheckFieldState(cred, SFI_PIN,    CPFS_HIDDEN, CPFIS_NONE);
    CheckFieldState(cred, SFI_SWITCH, haveSwitch ? CPFS_DISPLAY_IN_SELECTED_TILE : CPFS_HIDDEN, CPFIS_NONE);
    DWORD adj = 99;
    CHECK(SUCCEEDED(cred->GetSubmitButtonValue(SFI_SUBMIT, &adj)) && adj == (DWORD)(badgeMode ? SFI_BADGE : SFI_PASSWORD));
}

// PIN mode: the identifier that was used stays visible read-only, the secret
// and the link are hidden, the PIN field is shown and focused, the submit
// button sits next to it — both as the credential reports it and as it told LogonUI.
static void CheckPinForm(ICredentialProviderCredential* cred, const EventsStub& events, bool badgeMode, bool haveSwitch)
{
    DWORD idField = badgeMode ? SFI_BADGE : SFI_USERNAME;
    DWORD otherId = badgeMode ? SFI_USERNAME : SFI_BADGE;
    CheckFieldState(cred, idField,      CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_READONLY);
    CheckFieldState(cred, otherId,      CPFS_HIDDEN,                   CPFIS_NONE);
    CheckFieldState(cred, SFI_PASSWORD, CPFS_HIDDEN,                   CPFIS_NONE);
    CheckFieldState(cred, SFI_PIN,      CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_FOCUSED);
    CheckFieldState(cred, SFI_SWITCH,   CPFS_HIDDEN,                   CPFIS_NONE);
    DWORD adj = 99;
    CHECK(SUCCEEDED(cred->GetSubmitButtonValue(SFI_SUBMIT, &adj)) && adj == SFI_PIN);
    CHECK(events.submitAdjacentTo == SFI_PIN);
    CHECK(events.state[SFI_PIN] == CPFS_DISPLAY_IN_SELECTED_TILE && events.state[SFI_PASSWORD] == CPFS_HIDDEN);
    CHECK(events.istate[SFI_PIN] == CPFIS_FOCUSED);
    CHECK(events.istate[idField] == CPFIS_READONLY);
    if (haveSwitch) CHECK(events.state[SFI_SWITCH] == CPFS_HIDDEN);
}

// Put the tile into the wanted mode the way a person would: through the
// command link. Returns false when that is impossible (older deputy, no link).
static bool EnsureMode(ICredentialProviderCredential* cred, const EventsStub& events, const UiStrings& ui, bool wantBadge)
{
    bool inBadge = FieldDisplayed(cred, SFI_BADGE);
    if (inBadge == wantBadge) return true;
    if (!HasSwitchLink(ui))
    {
        printf("FAIL: the deputy sent no switch link; cannot enter %s mode\n", wantBadge ? "badge" : "username");
        ++failures;
        return false;
    }
    std::wstring before = StringValue(cred, SFI_SWITCH);
    CHECK(SUCCEEDED(cred->CommandLinkClicked(SFI_SWITCH)));
    std::wstring after = StringValue(cred, SFI_SWITCH);
    printf("switch link: '%s' -> '%s'\n", WideToUtf8(before).c_str(), WideToUtf8(after).c_str());
    // The link now names the other mode, and LogonUI was told the new text
    // and the new field states.
    CHECK(after == (wantBadge ? ui.switch_to_username : ui.switch_to_badge));
    CHECK(before != after);
    CHECK(events.strings[SFI_SWITCH] == after);
    CHECK(events.state[SFI_BADGE]    == (wantBadge ? CPFS_DISPLAY_IN_SELECTED_TILE : CPFS_HIDDEN));
    CHECK(events.state[SFI_USERNAME] == (wantBadge ? CPFS_HIDDEN : CPFS_DISPLAY_IN_SELECTED_TILE));
    CHECK(events.state[SFI_PASSWORD] == (wantBadge ? CPFS_HIDDEN : CPFS_DISPLAY_IN_SELECTED_TILE));
    CHECK(events.istate[wantBadge ? SFI_BADGE : SFI_USERNAME] == CPFIS_FOCUSED);
    CHECK(events.submitAdjacentTo == (DWORD)(wantBadge ? SFI_BADGE : SFI_PASSWORD));
    // A wrong field ID is rejected; the link is the only command link.
    CHECK(cred->CommandLinkClicked(SFI_USERNAME) == E_INVALIDARG);
    return true;
}

typedef HRESULT (STDAPICALLTYPE *PFN_DllGetClassObject)(REFCLSID, REFIID, void**);

int wmain(int argc, wchar_t** argv)
{
    if (argc < 4)
    {
        printf("usage: cp_test <dll> <identifier> <secret> [expect-ok|expect-deny]\n"
               "       cp_test <dll> --badge <number> <pin|-> expect-ok|expect-deny|expect-pin\n"
               "       cp_test <dll> --badge-plain <number> <pin|-> expect-ok|expect-deny|expect-pin\n");
        return 2;
    }
    bool badgeMasked = wcscmp(argv[2], L"--badge") == 0;
    bool badgePlain  = wcscmp(argv[2], L"--badge-plain") == 0;
    bool badgeRun = badgeMasked || badgePlain;
    if (badgeRun && argc < 6) { printf("badge mode needs <number> <pin|-> <expectation>\n"); return 2; }
    std::string expect = badgeRun ? narrow(argv[5]) : ((argc < 5) ? "expect-ok" : narrow(argv[4]));
    bool expectOk = expect == "expect-ok";

    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

    // What the deputy says the tile should look like (contract §2.1).
    UiStrings ui;
    CHECK(PipeFetchUi(ui));
    printf("ui: default_method '%s' default_provider '%s' heading '%s' link '%s' / '%s'\n",
           WideToUtf8(ui.default_method).c_str(), WideToUtf8(ui.default_provider).c_str(), WideToUtf8(ui.heading).c_str(),
           WideToUtf8(ui.switch_to_username).c_str(), WideToUtf8(ui.switch_to_badge).c_str());
    // v0.13.0: the reply carries which tile is the default, and both link texts.
    CHECK(ui.default_provider == L"rostor" || ui.default_provider == L"windows");
    CHECK(HasSwitchLink(ui));
    bool haveSwitch = HasSwitchLink(ui);
    bool windowsDefault = WindowsIsDefaultTile(ui);
    bool opensInBadge = OpensInBadgeMode(ui);

    HMODULE h = LoadLibraryW(argv[1]);
    CHECK(h != nullptr);
    if (!h) { printf("LoadLibrary failed (%lu)\n", GetLastError()); return 1; }
    auto getClassObject = (PFN_DllGetClassObject)GetProcAddress(h, "DllGetClassObject");
    CHECK(getClassObject != nullptr);
    CHECK(GetProcAddress(h, "DllCanUnloadNow") != nullptr);
    if (!getClassObject) return 1;

    IClassFactory* factory = nullptr;
    CHECK(SUCCEEDED(getClassObject(kClsid, IID_PPV_ARGS(&factory))));
    if (!factory) return 1;
    ICredentialProvider* provider = nullptr;
    CHECK(SUCCEEDED(factory->CreateInstance(nullptr, IID_PPV_ARGS(&provider))));
    factory->Release();
    if (!provider) return 1;

    CHECK(provider->SetUsageScenario(CPUS_CREDUI, 0) == E_NOTIMPL);
    CHECK(SUCCEEDED(provider->SetUsageScenario(CPUS_LOGON, 0)));

    DWORD nFields = 0;
    CHECK(SUCCEEDED(provider->GetFieldDescriptorCount(&nFields)));
    CHECK(nFields == SFI_NUM_FIELDS);
    for (DWORD i = 0; i < nFields; i++)
    {
        CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* fd = nullptr;
        CHECK(SUCCEEDED(provider->GetFieldDescriptorAt(i, &fd)));
        if (fd)
        {
            printf("field %lu type %d label '%s'\n", fd->dwFieldID, (int)fd->cpft, narrow(fd->pszLabel).c_str());
            if (i == SFI_USERNAME || i == SFI_BADGE || i == SFI_PASSWORD || i == SFI_SUBMIT) CHECK(fd->pszLabel && *fd->pszLabel);
            if (i == SFI_BADGE)  CHECK(fd->cpft == CPFT_PASSWORD_TEXT);   // a burst shows as dots
            if (i == SFI_SWITCH) { CHECK(fd->cpft == CPFT_COMMAND_LINK); if (haveSwitch) CHECK(fd->pszLabel && *fd->pszLabel); }
            CoTaskMemFree(fd->pszLabel);
            CoTaskMemFree(fd);
        }
    }

    DWORD count = 0, def = 0; BOOL autoLogon = TRUE;
    CHECK(SUCCEEDED(provider->GetCredentialCount(&count, &def, &autoLogon)));
    CHECK(count == 1 && autoLogon == FALSE);
    // "Which tile is the default" (v0.13.0): Rostor unless the policy says windows.
    printf("default credential %ld (policy default_provider '%s')\n", (long)def, WideToUtf8(ui.default_provider).c_str());
    CHECK(def == (windowsDefault ? CREDENTIAL_PROVIDER_NO_DEFAULT : (DWORD)0));

    ICredentialProviderCredential* cred = nullptr;
    CHECK(SUCCEEDED(provider->GetCredentialAt(0, &cred)));
    if (!cred) return 1;

    ICredentialProviderCredential2* cred2 = nullptr;
    CHECK(SUCCEEDED(cred->QueryInterface(IID_PPV_ARGS(&cred2))));
    if (cred2) { PWSTR sid = (PWSTR)1; CHECK(cred2->GetUserSid(&sid) == S_FALSE && sid == nullptr); cred2->Release(); }

    // The large text is the heading (the tile label from an older deputy).
    std::wstring label = StringValue(cred, SFI_LABEL);
    printf("large text '%s'\n", WideToUtf8(label).c_str());
    CHECK(!label.empty());
    CHECK(label == (ui.heading.empty() ? ui.tile_label : ui.heading));
    CHECK(StringValue(cred, SFI_SWITCH) == (opensInBadge ? ui.switch_to_username : ui.switch_to_badge));

    EventsStub events;
    CHECK(SUCCEEDED(cred->Advise(&events)));
    // The tile opened in the mode the policy asked for.
    printf("tile opened in %s mode\n", opensInBadge ? "badge" : "username");
    CheckInitialForm(cred, opensInBadge, haveSwitch);

    // Move to the mode this run needs, through the link like a person would.
    bool inBadgeMode = badgeMasked;
    if (EnsureMode(cred, events, ui, inBadgeMode))
    {
        CheckInitialForm(cred, inBadgeMode, haveSwitch);
        DWORD idField = inBadgeMode ? SFI_BADGE : SFI_USERNAME;

        if (!badgeRun)
        {
            CHECK(SUCCEEDED(cred->SetStringValue(SFI_USERNAME, argv[2])));
            CHECK(SUCCEEDED(cred->SetStringValue(SFI_PASSWORD, argv[3])));
            Submit(cred, expect.c_str());
        }
        else
        {
            bool withPin = wcscmp(argv[4], L"-") != 0;
            // A reader burst: digits into the live identifier field (masked in
            // badge mode, plain otherwise), secret empty, Enter → submit.
            CHECK(SUCCEEDED(cred->SetStringValue(idField, argv[3])));
            if (!inBadgeMode) CHECK(SUCCEEDED(cred->SetStringValue(SFI_PASSWORD, L"")));
            Submit(cred, withPin ? "expect-pin" : expect.c_str());
            bool inPin = (withPin || expect == "expect-pin");
            if (inPin)
            {
                CheckPinForm(cred, events, inBadgeMode, haveSwitch);
                printf("pin mode: large text '%s'\n", WideToUtf8(events.strings[SFI_LABEL]).c_str());
                CHECK(StringValue(cred, idField) == argv[3]); // badge number kept for the resend
                // A click on the (hidden) link while a PIN is pending changes nothing.
                if (haveSwitch)
                {
                    CHECK(SUCCEEDED(cred->CommandLinkClicked(SFI_SWITCH)));
                    CheckPinForm(cred, events, inBadgeMode, haveSwitch);
                }
            }
            if (withPin)
            {
                CHECK(SUCCEEDED(cred->SetStringValue(SFI_PIN, argv[4])));
                Submit(cred, expect.c_str());
            }
            if (!inPin || withPin)
            {
                // Any final result leaves PIN mode: back to the initial form of
                // the same mode, both identifier fields cleared (one held a card number).
                CheckInitialForm(cred, inBadgeMode, haveSwitch);
                if (withPin)
                {
                    CHECK(events.submitAdjacentTo == (DWORD)(inBadgeMode ? SFI_BADGE : SFI_PASSWORD));
                    CHECK(events.state[SFI_PIN] == CPFS_HIDDEN);
                    if (haveSwitch) CHECK(events.state[SFI_SWITCH] == CPFS_DISPLAY_IN_SELECTED_TILE);
                    CHECK(events.strings[SFI_LABEL] == label); // the heading is back
                }
                CHECK(StringValue(cred, SFI_USERNAME).empty());
                CHECK(StringValue(cred, SFI_BADGE).empty());
            }
        }
    }

    // After a failure LogonUI calls ReportResult; make sure the text survives.
    PWSTR rtext = nullptr; CREDENTIAL_PROVIDER_STATUS_ICON ricon = CPSI_NONE;
    CHECK(SUCCEEDED(cred->ReportResult(expectOk ? 0 : (NTSTATUS)0xC000006D, 0, &rtext, &ricon)));
    if (!expectOk) CHECK(rtext && *rtext);
    CoTaskMemFree(rtext);

    CHECK(SUCCEEDED(cred->UnAdvise()));
    cred->Release();
    provider->Release();
    typedef HRESULT (STDAPICALLTYPE *PFN_DllCanUnloadNow)();
    auto canUnload = (PFN_DllCanUnloadNow)GetProcAddress(h, "DllCanUnloadNow");
    CHECK(canUnload && canUnload() == S_OK);
    FreeLibrary(h);
    CoUninitialize();
    printf(failures ? "cp_test: %d failure(s)\n" : "cp_test: all passed\n", failures);
    return failures ? 1 : 0;
}
