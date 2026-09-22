// Console harness: drives RostorCredProv.dll through the same COM calls
// LogonUI makes, against the running agent, without registering the DLL.
// Run elevated (the pipe DACL admits Administrators). Built by test.cmd.
#include "common.h"
#include <cstdio>
#include <shlwapi.h>

static int failures = 0;
#define CHECK(cond) do { if (!(cond)) { printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #cond); ++failures; } } while (0)

// {7A4C2E10-5B0D-4F4E-9C1B-3E2D7F1A6B01}
static const CLSID kClsid = { 0x7A4C2E10, 0x5B0D, 0x4F4E, { 0x9C, 0x1B, 0x3E, 0x2D, 0x7F, 0x1A, 0x6B, 0x01 } };

typedef HRESULT (STDAPICALLTYPE *PFN_DllGetClassObject)(REFCLSID, REFIID, void**);

static std::string narrow(PCWSTR s) { return WideToUtf8(s ? s : L""); }

int wmain(int argc, wchar_t** argv)
{
    if (argc < 4) { printf("usage: cp_test <dll> <identifier> <secret> [expect-ok|expect-deny]\n"); return 2; }
    bool expectOk = (argc < 5) || (wcscmp(argv[4], L"expect-deny") != 0);

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
    CHECK(count == 1 && def == CREDENTIAL_PROVIDER_NO_DEFAULT && autoLogon == FALSE);

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

    CHECK(SUCCEEDED(cred->SetStringValue(SFI_USERNAME, argv[2])));
    CHECK(SUCCEEDED(cred->SetStringValue(SFI_PASSWORD, argv[3])));

    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE resp = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION ser = {};
    PWSTR status = nullptr;
    CREDENTIAL_PROVIDER_STATUS_ICON icon = CPSI_NONE;
    HRESULT hr = cred->GetSerialization(&resp, &ser, &status, &icon);
    printf("GetSerialization hr=0x%08lx resp=%d status='%s' icon=%d\n", hr, (int)resp, narrow(status).c_str(), (int)icon);
    CHECK(SUCCEEDED(hr));

    if (expectOk)
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
                   narrow(domain.c_str()).c_str(), narrow(user.c_str()).c_str(), (unsigned)pw.size(),
                   pw.size() > 32 ? "yes" : "no");
            CHECK(domain == L".");
            CHECK(!user.empty());
            CHECK(!pw.empty());
            CoTaskMemFree(ser.rgbSerialization);
        }
    }
    else
    {
        CHECK(resp == CPGSR_NO_CREDENTIAL_FINISHED);
        CHECK(icon == CPSI_ERROR);
        CHECK(status && *status);
        CHECK(ser.rgbSerialization == nullptr);
    }
    CoTaskMemFree(status);

    // After a failure LogonUI calls ReportResult; make sure the text survives.
    PWSTR rtext = nullptr; CREDENTIAL_PROVIDER_STATUS_ICON ricon = CPSI_NONE;
    CHECK(SUCCEEDED(cred->ReportResult(expectOk ? 0 : (NTSTATUS)0xC000006D, 0, &rtext, &ricon)));
    if (!expectOk) CHECK(rtext && *rtext);
    CoTaskMemFree(rtext);

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
