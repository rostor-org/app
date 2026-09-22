#include "Credential.h"
#include "guid.h"
#include <shlwapi.h>

CRostorCredential::CRostorCredential()
    : _cRef(1), _cpus(CPUS_INVALID), _pCredProvCredentialEvents(nullptr)
{
    DllAddRef();
    ZeroMemory(_rgCredProvFieldDescriptors, sizeof(_rgCredProvFieldDescriptors));
    ZeroMemory(_rgFieldStatePairs, sizeof(_rgFieldStatePairs));
    ZeroMemory(_rgFieldStrings, sizeof(_rgFieldStrings));
}

CRostorCredential::~CRostorCredential()
{
    ClearSecret();
    for (int i = 0; i < ARRAYSIZE(_rgFieldStrings); i++)
    {
        CoTaskMemFree(_rgFieldStrings[i]);
        CoTaskMemFree(_rgCredProvFieldDescriptors[i].pszLabel);
    }
    DllRelease();
}

void CRostorCredential::ClearSecret()
{
    if (_rgFieldStrings[SFI_PASSWORD])
    {
        size_t len = wcslen(_rgFieldStrings[SFI_PASSWORD]);
        SecureZeroMemory(_rgFieldStrings[SFI_PASSWORD], len * sizeof(wchar_t));
    }
}

HRESULT CRostorCredential::Initialize(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
                                      const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* rgcpfd,
                                      const FIELD_STATE_PAIR* rgfsp,
                                      const UiStrings& ui)
{
    _cpus = cpus;
    _ui = ui;
    HRESULT hr = S_OK;
    for (DWORD i = 0; SUCCEEDED(hr) && i < ARRAYSIZE(_rgCredProvFieldDescriptors); i++)
    {
        _rgFieldStatePairs[i] = rgfsp[i];
        _rgCredProvFieldDescriptors[i] = rgcpfd[i];
        PCWSTR label = L"";
        switch (i)
        {
        case SFI_USERNAME: label = _ui.username_label.c_str(); break;
        case SFI_PASSWORD: label = _ui.password_label.c_str(); break;
        case SFI_SUBMIT:   label = _ui.submit_label.c_str(); break;
        }
        hr = SHStrDupW(label, &_rgCredProvFieldDescriptors[i].pszLabel);
    }
    // Field values: the large text shows the tile label; edit fields empty.
    if (SUCCEEDED(hr)) hr = SHStrDupW(_ui.tile_label.c_str(), &_rgFieldStrings[SFI_LABEL]);
    if (SUCCEEDED(hr)) hr = SHStrDupW(L"", &_rgFieldStrings[SFI_USERNAME]);
    if (SUCCEEDED(hr)) hr = SHStrDupW(L"", &_rgFieldStrings[SFI_PASSWORD]);
    if (SUCCEEDED(hr)) hr = SHStrDupW(_ui.submit_label.c_str(), &_rgFieldStrings[SFI_SUBMIT]);
    return hr;
}

// ---- IUnknown ----------------------------------------------------------------

IFACEMETHODIMP_(ULONG) CRostorCredential::AddRef() { return InterlockedIncrement(&_cRef); }

IFACEMETHODIMP_(ULONG) CRostorCredential::Release()
{
    LONG cRef = InterlockedDecrement(&_cRef);
    if (!cRef) delete this;
    return cRef;
}

IFACEMETHODIMP CRostorCredential::QueryInterface(REFIID riid, void** ppv)
{
    static const QITAB qit[] =
    {
        QITABENT(CRostorCredential, ICredentialProviderCredential),
        QITABENT(CRostorCredential, ICredentialProviderCredential2),
        { 0 },
    };
    return QISearch(this, qit, riid, ppv);
}

// ---- ICredentialProviderCredential -------------------------------------------

IFACEMETHODIMP CRostorCredential::Advise(ICredentialProviderCredentialEvents* pcpce)
{
    if (_pCredProvCredentialEvents) _pCredProvCredentialEvents->Release();
    _pCredProvCredentialEvents = pcpce;
    _pCredProvCredentialEvents->AddRef();
    return S_OK;
}

IFACEMETHODIMP CRostorCredential::UnAdvise()
{
    if (_pCredProvCredentialEvents) _pCredProvCredentialEvents->Release();
    _pCredProvCredentialEvents = nullptr;
    return S_OK;
}

IFACEMETHODIMP CRostorCredential::SetSelected(BOOL* pbAutoLogon)
{
    *pbAutoLogon = FALSE;
    return S_OK;
}

IFACEMETHODIMP CRostorCredential::SetDeselected()
{
    // Drop the secret as soon as the tile loses focus.
    ClearSecret();
    CoTaskMemFree(_rgFieldStrings[SFI_PASSWORD]);
    HRESULT hr = SHStrDupW(L"", &_rgFieldStrings[SFI_PASSWORD]);
    if (SUCCEEDED(hr) && _pCredProvCredentialEvents)
        _pCredProvCredentialEvents->SetFieldString(this, SFI_PASSWORD, _rgFieldStrings[SFI_PASSWORD]);
    return hr;
}

IFACEMETHODIMP CRostorCredential::GetFieldState(DWORD dwFieldID, CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
                                                CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis)
{
    if (dwFieldID >= ARRAYSIZE(_rgFieldStatePairs) || !pcpfs || !pcpfis) return E_INVALIDARG;
    *pcpfs = _rgFieldStatePairs[dwFieldID].cpfs;
    *pcpfis = _rgFieldStatePairs[dwFieldID].cpfis;
    return S_OK;
}

IFACEMETHODIMP CRostorCredential::GetStringValue(DWORD dwFieldID, PWSTR* ppwsz)
{
    if (dwFieldID >= ARRAYSIZE(_rgCredProvFieldDescriptors) || !ppwsz) return E_INVALIDARG;
    return SHStrDupW(_rgFieldStrings[dwFieldID], ppwsz);
}

IFACEMETHODIMP CRostorCredential::GetBitmapValue(DWORD, HBITMAP* phbmp)
{
    // No tile image in the PoC; LogonUI shows its generic glyph.
    if (phbmp) *phbmp = nullptr;
    return E_INVALIDARG;
}

IFACEMETHODIMP CRostorCredential::GetSubmitButtonValue(DWORD dwFieldID, DWORD* pdwAdjacentTo)
{
    if (dwFieldID != SFI_SUBMIT || !pdwAdjacentTo) return E_INVALIDARG;
    *pdwAdjacentTo = SFI_PASSWORD;
    return S_OK;
}

IFACEMETHODIMP CRostorCredential::SetStringValue(DWORD dwFieldID, PCWSTR pwz)
{
    if (dwFieldID >= ARRAYSIZE(_rgCredProvFieldDescriptors)) return E_INVALIDARG;
    CREDENTIAL_PROVIDER_FIELD_TYPE cpft = _rgCredProvFieldDescriptors[dwFieldID].cpft;
    if (cpft != CPFT_EDIT_TEXT && cpft != CPFT_PASSWORD_TEXT) return E_INVALIDARG;
    if (dwFieldID == SFI_PASSWORD) ClearSecret();
    PWSTR* ppwszStored = &_rgFieldStrings[dwFieldID];
    CoTaskMemFree(*ppwszStored);
    return SHStrDupW(pwz, ppwszStored);
}

IFACEMETHODIMP CRostorCredential::GetCheckboxValue(DWORD, BOOL*, PWSTR*) { return E_INVALIDARG; }
IFACEMETHODIMP CRostorCredential::GetComboBoxValueCount(DWORD, DWORD*, DWORD*) { return E_INVALIDARG; }
IFACEMETHODIMP CRostorCredential::GetComboBoxValueAt(DWORD, DWORD, PWSTR*) { return E_INVALIDARG; }
IFACEMETHODIMP CRostorCredential::SetCheckboxValue(DWORD, BOOL) { return E_INVALIDARG; }
IFACEMETHODIMP CRostorCredential::SetComboBoxSelectedValue(DWORD, DWORD) { return E_INVALIDARG; }
IFACEMETHODIMP CRostorCredential::CommandLinkClicked(DWORD) { return E_INVALIDARG; }

// Submit: ask the agent; on ok serialize the *local* credential it returned.
IFACEMETHODIMP CRostorCredential::GetSerialization(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
                                                   CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
                                                   PWSTR* ppwszOptionalStatusText,
                                                   CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
    *ppwszOptionalStatusText = nullptr;
    *pcpsiOptionalStatusIcon = CPSI_NONE;
    ZeroMemory(pcpcs, sizeof(*pcpcs));
    _lastMessage.clear();

    // Show "connecting" while the agent works, then restore the label.
    if (_pCredProvCredentialEvents && !_ui.connecting.empty())
        _pCredProvCredentialEvents->SetFieldString(this, SFI_LABEL, _ui.connecting.c_str());

    std::string req = "{\"op\":\"logon\",\"identifier\":" + JsonQuote(_rgFieldStrings[SFI_USERNAME] ? _rgFieldStrings[SFI_USERNAME] : L"")
                    + ",\"secret\":" + JsonQuote(_rgFieldStrings[SFI_PASSWORD] ? _rgFieldStrings[SFI_PASSWORD] : L"")
                    + ",\"locale\":\"en-US\"}";
    std::map<std::string, std::string> reply;
    std::string code;
    bool ok = PipeCall(req, reply, code);
    SecureZeroMemory(&req[0], req.size());

    if (_pCredProvCredentialEvents)
        _pCredProvCredentialEvents->SetFieldString(this, SFI_LABEL, _rgFieldStrings[SFI_LABEL]);

    if (!ok || reply["ok"] != "true")
    {
        // The agent renders text; the credprov never invents any. When the
        // agent itself is unreachable there is no text at all — only a code
        // in the log — and LogonUI shows a generic failure.
        if (ok) code = reply["code"];
        _lastMessage = Utf8ToWide(reply["message"]);
        LogLine("logon: denied (%s)", code.c_str());
        *pcpgsr = CPGSR_NO_CREDENTIAL_FINISHED;
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        if (!_lastMessage.empty()) SHStrDupW(_lastMessage.c_str(), ppwszOptionalStatusText);
        ClearSecret();
        // Zero the secret we just wiped from the JSON too.
        for (auto& kv : reply) if (!kv.second.empty()) SecureZeroMemory(&kv.second[0], kv.second.size());
        return S_OK;
    }

    std::wstring localUser = Utf8ToWide(reply["local_user"]);
    std::wstring localSecret = Utf8ToWide(reply["local_secret"]);
    for (auto& kv : reply) if (!kv.second.empty()) SecureZeroMemory(&kv.second[0], kv.second.size());
    LogLine("logon: ok, local user '%s'", WideToUtf8(localUser).c_str());

    HRESULT hr = E_FAIL;
    PWSTR pwzProtected = nullptr;
    hr = ProtectIfNecessaryAndCopyPassword(localSecret.c_str(), _cpus, &pwzProtected);
    if (!localSecret.empty()) SecureZeroMemory(&localSecret[0], localSecret.size() * sizeof(wchar_t));
    if (SUCCEEDED(hr))
    {
        KERB_INTERACTIVE_UNLOCK_LOGON kiul;
        wchar_t domain[] = L".";
        hr = KerbInteractiveUnlockLogonInit(domain, const_cast<PWSTR>(localUser.c_str()), pwzProtected, _cpus, &kiul);
        if (SUCCEEDED(hr))
        {
            hr = KerbInteractiveUnlockLogonPack(kiul, &pcpcs->rgbSerialization, &pcpcs->cbSerialization);
            if (SUCCEEDED(hr))
            {
                ULONG ulAuthPackage;
                hr = RetrieveNegotiateAuthPackage(&ulAuthPackage);
                if (SUCCEEDED(hr))
                {
                    pcpcs->ulAuthenticationPackage = ulAuthPackage;
                    pcpcs->clsidCredentialProvider = CLSID_RostorCredProv;
                    *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
                }
            }
        }
        SecureZeroMemory(pwzProtected, wcslen(pwzProtected) * sizeof(wchar_t));
        CoTaskMemFree(pwzProtected);
    }
    if (FAILED(hr))
    {
        LogLine("logon: serialization failed (0x%08lx)", hr);
        if (pcpcs->rgbSerialization) { CoTaskMemFree(pcpcs->rgbSerialization); pcpcs->rgbSerialization = nullptr; }
        *pcpgsr = CPGSR_NO_CREDENTIAL_FINISHED;
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
    }
    ClearSecret();
    return hr;
}

IFACEMETHODIMP CRostorCredential::ReportResult(NTSTATUS ntsStatus, NTSTATUS ntsSubstatus,
                                               PWSTR* ppwszOptionalStatusText,
                                               CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    *ppwszOptionalStatusText = nullptr;
    *pcpsiOptionalStatusIcon = CPSI_NONE;
    LogLine("report: status 0x%08lx substatus 0x%08lx", ntsStatus, ntsSubstatus);
    if (ntsStatus != STATUS_SUCCESS)
    {
        // Surface the agent's rendered text; if LSA itself failed after an
        // ALLOW there is no agent text and LogonUI shows its own.
        if (!_lastMessage.empty()) SHStrDupW(_lastMessage.c_str(), ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        // Clear the secret field so a retry starts clean.
        CoTaskMemFree(_rgFieldStrings[SFI_PASSWORD]);
        SHStrDupW(L"", &_rgFieldStrings[SFI_PASSWORD]);
        if (_pCredProvCredentialEvents)
            _pCredProvCredentialEvents->SetFieldString(this, SFI_PASSWORD, _rgFieldStrings[SFI_PASSWORD]);
    }
    return S_OK;
}

// ---- ICredentialProviderCredential2 ------------------------------------------

IFACEMETHODIMP CRostorCredential::GetUserSid(PWSTR* ppszSid)
{
    // S_FALSE + NULL: show under "Other user" rather than on a user tile.
    *ppszSid = nullptr;
    return S_FALSE;
}
