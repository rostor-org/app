// Console harness: drives RostorCredProv.dll through the same COM calls
// LogonUI makes, against the running deputy, without registering the DLL.
// Run elevated (the pipe DACL admits Administrators). Built by test.cmd.
//
//   cp_test <dll> <identifier> <secret> [expect-ok|expect-deny]
//   cp_test <dll> --badge <number> <pin|-> expect-ok|expect-deny|expect-pin
//
// A badge run types the number into the identifier field with an empty
// secret (what a keyboard-wedge reader does) and submits. With a PIN given,
// the first submit must answer auth.continue (PIN mode), then the PIN is
// typed into the PIN field and submitted again.
#include "common.h"
#include <cstdio>
#include <cstring>
#include <shlwapi.h>

// {7A4C2E10-5B0D-4F4E-9C1B-3E2D7F1A6B01}
static const CLSID kClsid = { 0x7A4C2E10, 0x5B0D, 0x4F4E, { 0x9C, 0x1B, 0x3E, 0x2D, 0x7F, 0x1A, 0x6B, 0x01 } };

static int failures = 0;
#define CHECK(cond) do { if (!(cond)) { printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #cond); ++failures; } } while (0)

// Records what the credential asks LogonUI to change, so PIN mode can be
// checked through the same channel LogonUI sees rather than via GetFieldState alone.
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

// One submit round; returns the response so callers can chain.
static CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE Submit(ICredentialProviderCredential* cred, const char* expect)
{
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE resp = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION ser = {};
    PWSTR status = nullptr;
    CREDENTIAL_PROVIDER_STATUS_ICON icon = CPSI_NONE;
    HRESULT hr = cred->GetSerialization(&resp, &ser, &status, &icon);
    printf("GetSerialization hr=0x%08lx resp=%d status='%s' icon=%d (%s)\n", hr, (int)resp, WideToUtf8(status ? status : L"").c_str(), (int)icon, expect);
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


typedef HRESULT (STDAPICALLTYPE *PFN_DllGetClassObject)(REFCLSID, REFIID, void**);

static std::string narrow(PCWSTR s) { return WideToUtf8(s ? s : L""); }

int wmain(int argc, wchar_t** argv)
{
    if (argc < 4) { printf("usage: cp_test <dll> <identifier> <secret> [expect-ok|expect-deny]\n       cp_test <dll> --badge <number> <pin|-> expect-ok|expect-deny|expect-pin\n"); return 2; }
    bool badgeMode = wcscmp(argv[2], L"--badge") == 0;
    if (badgeMode && argc < 6) { printf("badge mode needs <number> <pin|-> <expectation>\n"); return 2; }
    std::string expect = badgeMode ? narrow(argv[5]) : ((argc < 5) ? "expect-ok" : narrow(argv[4]));
    bool expectOk = expect == "expect-ok";

    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
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
            if (i == SFI_USERNAME || i == SFI_PASSWORD || i == SFI_SUBMIT) CHECK(fd->pszLabel && *fd->pszLabel);
            CoTaskMemFree(fd->pszLabel);
            CoTaskMemFree(fd);
        }
    }

    DWORD count = 0, def = 0; BOOL autoLogon = TRUE;
    CHECK(SUCCEEDED(provider->GetCredentialCount(&count, &def, &autoLogon)));
    CHECK(count == 1 && def == 0 && autoLogon == FALSE); // Rostor is the default tile

    ICredentialProviderCredential* cred = nullptr;
    CHECK(SUCCEEDED(provider->GetCredentialAt(0, &cred)));
    if (!cred) return 1;

    ICredentialProviderCredential2* cred2 = nullptr;
    CHECK(SUCCEEDED(cred->QueryInterface(IID_PPV_ARGS(&cred2))));
    if (cred2) { PWSTR sid = (PWSTR)1; CHECK(cred2->GetUserSid(&sid) == S_FALSE && sid == nullptr); cred2->Release(); }

    PWSTR label = nullptr;
    CHECK(SUCCEEDED(cred->GetStringValue(SFI_LABEL, &label)));
    printf("tile label '%s'\n", narrow(label).c_str());
    CHECK(label && *label);
    CoTaskMemFree(label);

    EventsStub events;
    CHECK(SUCCEEDED(cred->Advise(&events)));
    // Initial form: secret shown, PIN hidden, caret in the identifier field.
    CheckFieldState(cred, SFI_USERNAME, CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_FOCUSED);
    CheckFieldState(cred, SFI_PASSWORD, CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE);
    CheckFieldState(cred, SFI_PIN, CPFS_HIDDEN, CPFIS_NONE);
    DWORD adj = 99; CHECK(SUCCEEDED(cred->GetSubmitButtonValue(SFI_SUBMIT, &adj)) && adj == SFI_PASSWORD);

    if (!badgeMode)
    {
        CHECK(SUCCEEDED(cred->SetStringValue(SFI_USERNAME, argv[2])));
        CHECK(SUCCEEDED(cred->SetStringValue(SFI_PASSWORD, argv[3])));
        Submit(cred, expect.c_str());
    }
    else
    {
        bool withPin = wcscmp(argv[4], L"-") != 0;
        // A reader burst: digits into the identifier field, secret empty, Enter → submit.
        CHECK(SUCCEEDED(cred->SetStringValue(SFI_USERNAME, argv[3])));
        CHECK(SUCCEEDED(cred->SetStringValue(SFI_PASSWORD, L"")));
        Submit(cred, withPin ? "expect-pin" : expect.c_str());
        bool inPin = (withPin || expect == "expect-pin");
        if (inPin)
        {
            // PIN mode: secret hidden, PIN shown and focused, submit moved, identifier frozen.
            CheckFieldState(cred, SFI_PASSWORD, CPFS_HIDDEN, CPFIS_NONE);
            CheckFieldState(cred, SFI_PIN, CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_FOCUSED);
            CheckFieldState(cred, SFI_USERNAME, CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_READONLY);
            CHECK(SUCCEEDED(cred->GetSubmitButtonValue(SFI_SUBMIT, &adj)) && adj == SFI_PIN);
            CHECK(events.submitAdjacentTo == SFI_PIN);
            CHECK(events.state[SFI_PIN] == CPFS_DISPLAY_IN_SELECTED_TILE && events.state[SFI_PASSWORD] == CPFS_HIDDEN);
            CHECK(events.istate[SFI_PIN] == CPFIS_FOCUSED);
            printf("pin mode: large text '%s'\n", narrow(events.strings[SFI_LABEL].c_str()).c_str());
            PWSTR u = nullptr; CHECK(SUCCEEDED(cred->GetStringValue(SFI_USERNAME, &u)));
            CHECK(u && wcscmp(u, argv[3]) == 0); // badge number kept for the resend
            CoTaskMemFree(u);
        }
        if (withPin)
        {
            CHECK(SUCCEEDED(cred->SetStringValue(SFI_PIN, argv[4])));
            Submit(cred, expect.c_str());
        }
        if (!inPin || withPin)
        {
            // Any final result leaves PIN mode: back to the initial form with
            // the identifier cleared (it held a card number).
            CheckFieldState(cred, SFI_PASSWORD, CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE);
            CheckFieldState(cred, SFI_PIN, CPFS_HIDDEN, CPFIS_NONE);
            CheckFieldState(cred, SFI_USERNAME, CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_FOCUSED);
            CHECK(SUCCEEDED(cred->GetSubmitButtonValue(SFI_SUBMIT, &adj)) && adj == SFI_PASSWORD);
            if (withPin) CHECK(events.submitAdjacentTo == SFI_PASSWORD);
            PWSTR u = nullptr; CHECK(SUCCEEDED(cred->GetStringValue(SFI_USERNAME, &u)));
            CHECK(u && *u == L'\0');
            CoTaskMemFree(u);
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
