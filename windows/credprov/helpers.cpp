// Serialization helpers, after Microsoft's SampleCredentialProvider helpers.cpp.
// These build the KERB_INTERACTIVE_UNLOCK_LOGON blob LogonUI hands to LSA.
#include "common.h"
#include <shlwapi.h>
#include <wincred.h>

HRESULT FieldDescriptorCoAllocCopy(const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR& rcpfd, PCWSTR pszLabel,
                                   CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd)
{
    *ppcpfd = nullptr;
    auto pcpfd = (CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*)CoTaskMemAlloc(sizeof(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR));
    if (!pcpfd) return E_OUTOFMEMORY;
    pcpfd->dwFieldID = rcpfd.dwFieldID;
    pcpfd->cpft = rcpfd.cpft;
    pcpfd->guidFieldType = rcpfd.guidFieldType;
    pcpfd->pszLabel = nullptr;
    HRESULT hr = SHStrDupW(pszLabel ? pszLabel : L"", &pcpfd->pszLabel);
    if (FAILED(hr))
    {
        CoTaskMemFree(pcpfd);
        return hr;
    }
    *ppcpfd = pcpfd;
    return S_OK;
}

static void UnicodeStringInitWithString(PWSTR pwz, UNICODE_STRING* pus)
{
    size_t lenChars = wcslen(pwz);
    pus->Buffer = pwz;
    pus->Length = (USHORT)(lenChars * sizeof(wchar_t));
    pus->MaximumLength = pus->Length;
}

HRESULT KerbInteractiveUnlockLogonInit(PWSTR pwzDomain, PWSTR pwzUsername, PWSTR pwzPassword,
                                       CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
                                       KERB_INTERACTIVE_UNLOCK_LOGON* pkiul)
{
    KERB_INTERACTIVE_UNLOCK_LOGON kiul;
    ZeroMemory(&kiul, sizeof(kiul));
    KERB_INTERACTIVE_LOGON* pkil = &kiul.Logon;

    UnicodeStringInitWithString(pwzDomain, &pkil->LogonDomainName);
    UnicodeStringInitWithString(pwzUsername, &pkil->UserName);
    UnicodeStringInitWithString(pwzPassword, &pkil->Password);

    switch (cpus)
    {
    case CPUS_UNLOCK_WORKSTATION:
        pkil->MessageType = KerbWorkstationUnlockLogon;
        break;
    case CPUS_LOGON:
        pkil->MessageType = KerbInteractiveLogon;
        break;
    default:
        return E_FAIL;
    }
    *pkiul = kiul;
    return S_OK;
}

// Copies a UNICODE_STRING's characters to pwzBuffer and points the packed
// UNICODE_STRING at it; the caller then rewrites Buffer as an offset.
static void UnicodeStringPackedUnicodeStringCopy(const UNICODE_STRING& rus, PWSTR pwzBuffer, UNICODE_STRING* pus)
{
    pus->Length = rus.Length;
    pus->MaximumLength = rus.Length;
    pus->Buffer = pwzBuffer;
    CopyMemory(pus->Buffer, rus.Buffer, pus->Length);
}

HRESULT KerbInteractiveUnlockLogonPack(const KERB_INTERACTIVE_UNLOCK_LOGON& rkiulIn, BYTE** prgb, DWORD* pcb)
{
    const KERB_INTERACTIVE_LOGON* pkilIn = &rkiulIn.Logon;
    DWORD cb = sizeof(rkiulIn) + pkilIn->LogonDomainName.Length + pkilIn->UserName.Length + pkilIn->Password.Length;
    auto pkiulOut = (KERB_INTERACTIVE_UNLOCK_LOGON*)CoTaskMemAlloc(cb);
    if (!pkiulOut) return E_OUTOFMEMORY;

    ZeroMemory(&pkiulOut->LogonId, sizeof(pkiulOut->LogonId));
    BYTE* pbBuffer = (BYTE*)pkiulOut + sizeof(*pkiulOut);
    KERB_INTERACTIVE_LOGON* pkilOut = &pkiulOut->Logon;
    pkilOut->MessageType = pkilIn->MessageType;

    // Strings live after the struct; Buffer holds the byte offset from the
    // start of the blob, which is what LSA expects in a packed logon.
    UnicodeStringPackedUnicodeStringCopy(pkilIn->LogonDomainName, (PWSTR)pbBuffer, &pkilOut->LogonDomainName);
    pkilOut->LogonDomainName.Buffer = (PWSTR)(pbBuffer - (BYTE*)pkiulOut);
    pbBuffer += pkilOut->LogonDomainName.Length;

    UnicodeStringPackedUnicodeStringCopy(pkilIn->UserName, (PWSTR)pbBuffer, &pkilOut->UserName);
    pkilOut->UserName.Buffer = (PWSTR)(pbBuffer - (BYTE*)pkiulOut);
    pbBuffer += pkilOut->UserName.Length;

    UnicodeStringPackedUnicodeStringCopy(pkilIn->Password, (PWSTR)pbBuffer, &pkilOut->Password);
    pkilOut->Password.Buffer = (PWSTR)(pbBuffer - (BYTE*)pkiulOut);

    *prgb = (BYTE*)pkiulOut;
    *pcb = cb;
    return S_OK;
}

HRESULT RetrieveNegotiateAuthPackage(ULONG* pulAuthPackage)
{
    HRESULT hr = E_FAIL;
    HANDLE hLsa = nullptr;
    NTSTATUS status = LsaConnectUntrusted(&hLsa);
    if (SUCCEEDED(HRESULT_FROM_NT(status)))
    {
        ULONG ulAuthPackage;
        LSA_STRING lsaszKerberosName;
        // NEGOSSP_NAME_A is "Negotiate"; it picks MSV1_0 for a local account.
        lsaszKerberosName.Buffer = const_cast<PCHAR>(NEGOSSP_NAME_A);
        lsaszKerberosName.Length = (USHORT)strlen(NEGOSSP_NAME_A);
        lsaszKerberosName.MaximumLength = lsaszKerberosName.Length + 1;
        status = LsaLookupAuthenticationPackage(hLsa, &lsaszKerberosName, &ulAuthPackage);
        if (SUCCEEDED(HRESULT_FROM_NT(status)))
        {
            *pulAuthPackage = ulAuthPackage;
            hr = S_OK;
        }
        LsaDeregisterLogonProcess(hLsa);
    }
    return hr;
}

// In LogonUI scenarios the secret must be CredProtect-ed before it is handed
// to LSA; in CredUI scenarios it must not be. Mirrors the Microsoft sample.
static HRESULT ProtectAndCopyString(PCWSTR pwzToProtect, PWSTR* ppwzProtected)
{
    *ppwzProtected = nullptr;
    HRESULT hr = E_FAIL;
    DWORD cchProtected = 0;
    if (!CredProtectW(FALSE, const_cast<PWSTR>(pwzToProtect), (DWORD)wcslen(pwzToProtect) + 1, nullptr, &cchProtected, nullptr))
    {
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && cchProtected > 0)
        {
            auto pwzProtected = (PWSTR)CoTaskMemAlloc(cchProtected * sizeof(wchar_t));
            if (!pwzProtected) return E_OUTOFMEMORY;
            if (CredProtectW(FALSE, const_cast<PWSTR>(pwzToProtect), (DWORD)wcslen(pwzToProtect) + 1, pwzProtected, &cchProtected, nullptr))
            {
                *ppwzProtected = pwzProtected;
                hr = S_OK;
            }
            else
            {
                hr = HRESULT_FROM_WIN32(GetLastError());
                CoTaskMemFree(pwzProtected);
            }
        }
        else
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
        }
    }
    return hr;
}

HRESULT ProtectIfNecessaryAndCopyPassword(PCWSTR pwzPassword, CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
                                          PWSTR* ppwzProtectedPassword)
{
    *ppwzProtectedPassword = nullptr;
    PCWSTR pwzToProtect = (pwzPassword && *pwzPassword) ? pwzPassword : L"";

    bool alreadyProtected = false;
    CRED_PROTECTION_TYPE protectionType;
    if (CredIsProtectedW(const_cast<PWSTR>(pwzToProtect), &protectionType) && protectionType != CredUnprotected)
        alreadyProtected = true;

    if (alreadyProtected || (cpus != CPUS_LOGON && cpus != CPUS_UNLOCK_WORKSTATION))
        return SHStrDupW(pwzToProtect, ppwzProtectedPassword);
    return ProtectAndCopyString(pwzToProtect, ppwzProtectedPassword);
}
