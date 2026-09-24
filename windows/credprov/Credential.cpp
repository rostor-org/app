#include "Credential.h"
#include "guid.h"
#include <shlwapi.h>

CRostorCredential::CRostorCredential()
    : _cRef(1), _cpus(CPUS_INVALID), _pCredProvCredentialEvents(nullptr), _pinMode(false)
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
    const DWORD secrets[] = { SFI_PASSWORD, SFI_PIN };
    for (DWORD id : secrets)
    {
        if (_rgFieldStrings[id])
        {
            size_t len = wcslen(_rgFieldStrings[id]);
            SecureZeroMemory(_rgFieldStrings[id], len * sizeof(wchar_t));
        }
    }
}

// Replace a field's stored value and, when LogonUI is listening, its display.
void CRostorCredential::SetFieldValue(DWORD fieldID, PCWSTR value)
{
    if (fieldID == SFI_PASSWORD || fieldID == SFI_PIN) ClearSecret();
    CoTaskMemFree(_rgFieldStrings[fieldID]);
    _rgFieldStrings[fieldID] = nullptr;
    if (FAILED(SHStrDupW(value, &_rgFieldStrings[fieldID]))) return;
    if (_pCredProvCredentialEvents)
        _pCredProvCredentialEvents->SetFieldString(this, fieldID, _rgFieldStrings[fieldID]);
}

// The agent answered auth.continue for a badge tap: keep the number, swap the
// secret field for the PIN field, move the submit button next to it and put
// the caret there so the person just types the PIN and presses Enter. LogonUI
// cannot relabel a live field, which is why the PIN field is a separate
// (normally hidden) field carrying `pin_label`.
void CRostorCredential::EnterPinMode(PCWSTR badgeNumber, const std::wstring& prompt)
{
    _pinMode = true;
    _badgeNumber = badgeNumber ? badgeNumber : L"";
    _rgFieldStatePairs[SFI_PASSWORD].cpfs  = CPFS_HIDDEN;
    _rgFieldStatePairs[SFI_PASSWORD].cpfis = CPFIS_NONE;
    _rgFieldStatePairs[SFI_PIN].cpfs       = CPFS_DISPLAY_IN_SELECTED_TILE;
    _rgFieldStatePairs[SFI_PIN].cpfis      = CPFIS_FOCUSED;
    _rgFieldStatePairs[SFI_USERNAME].cpfis = CPFIS_READONLY;
    SetFieldValue(SFI_PIN, L"");
    if (_pCredProvCredentialEvents)
    {
        ICredentialProviderCredentialEvents* ev = _pCredProvCredentialEvents;
        ev->SetFieldState(this, SFI_PASSWORD, CPFS_HIDDEN);
        ev->SetFieldState(this, SFI_PIN, CPFS_DISPLAY_IN_SELECTED_TILE);
        ev->SetFieldInteractiveState(this, SFI_USERNAME, CPFIS_READONLY);
        ev->SetFieldInteractiveState(this, SFI_PIN, CPFIS_FOCUSED);
        ev->SetFieldSubmitButton(this, SFI_SUBMIT, SFI_PIN);
        // The large text carries the agent's prompt while the PIN is pending.
        if (!prompt.empty()) ev->SetFieldString(this, SFI_LABEL, prompt.c_str());
    }
}

// Back to the identifier-first form: secret field visible, PIN field hidden,
// submit next to the secret, caret in the identifier field. Secrets are wiped
// either way; the identifier is cleared after a badge attempt (it held the
// card number) but kept after a password denial so the person can retry.
void CRostorCredential::ResetToInitial(bool clearIdentifier)
{
    bool wasPin = _pinMode;
    _pinMode = false;
    if (!_badgeNumber.empty()) SecureZeroMemory(&_badgeNumber[0], _badgeNumber.size() * sizeof(wchar_t));
    _badgeNumber.clear();
    _rgFieldStatePairs[SFI_PASSWORD].cpfs  = CPFS_DISPLAY_IN_SELECTED_TILE;
    _rgFieldStatePairs[SFI_PASSWORD].cpfis = CPFIS_NONE;
    _rgFieldStatePairs[SFI_PIN].cpfs       = CPFS_HIDDEN;
    _rgFieldStatePairs[SFI_PIN].cpfis      = CPFIS_NONE;
    _rgFieldStatePairs[SFI_USERNAME].cpfis = CPFIS_FOCUSED;
    SetFieldValue(SFI_PASSWORD, L"");
    SetFieldValue(SFI_PIN, L"");
    if (clearIdentifier) SetFieldValue(SFI_USERNAME, L"");
    if (wasPin && _pCredProvCredentialEvents)
    {
        ICredentialProviderCredentialEvents* ev = _pCredProvCredentialEvents;
        ev->SetFieldState(this, SFI_PIN, CPFS_HIDDEN);
        ev->SetFieldState(this, SFI_PASSWORD, CPFS_DISPLAY_IN_SELECTED_TILE);
        ev->SetFieldInteractiveState(this, SFI_USERNAME, CPFIS_FOCUSED);
        ev->SetFieldSubmitButton(this, SFI_SUBMIT, SFI_PASSWORD);
        ev->SetFieldString(this, SFI_LABEL, _rgFieldStrings[SFI_LABEL]);
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
        hr = SHStrDupW(FieldLabel(_ui, i), &_rgCredProvFieldDescriptors[i].pszLabel);
    }
    // Field values: the large text shows the tile label; edit fields empty.
    if (SUCCEEDED(hr)) hr = SHStrDupW(_ui.tile_label.c_str(), &_rgFieldStrings[SFI_LABEL]);
    if (SUCCEEDED(hr)) hr = SHStrDupW(L"", &_rgFieldStrings[SFI_USERNAME]);
    if (SUCCEEDED(hr)) hr = SHStrDupW(L"", &_rgFieldStrings[SFI_PASSWORD]);
    if (SUCCEEDED(hr)) hr = SHStrDupW(L"", &_rgFieldStrings[SFI_PIN]);
    if (SUCCEEDED(hr)) hr = SHStrDupW(_ui.submit_label.c_str(), &_rgFieldStrings[SFI_SUBMIT]);
    if (SUCCEEDED(hr)) hr = SHStrDupW(L"", &_rgFieldStrings[SFI_TILEIMAGE]);
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
    // Drop the secrets (and any pending badge) as soon as the tile loses focus.
    ResetToInitial(_pinMode);
    return S_OK;
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

IFACEMETHODIMP CRostorCredential::GetBitmapValue(DWORD dwFieldID, HBITMAP* phbmp)
{
    if (!phbmp) return E_INVALIDARG;
    *phbmp = nullptr;
    if (dwFieldID != SFI_TILEIMAGE) return E_INVALIDARG;
    // The tile image ships beside the agent (install.ps1 copies it). A
    // missing file just leaves LogonUI's generic glyph; never a failure.
    HBITMAP h = static_cast<HBITMAP>(LoadImageW(nullptr, L"C:\\Program Files\\Rostor\\tile.bmp",
        IMAGE_BITMAP, 0, 0, LR_LOADFROMFILE | LR_CREATEDIBSECTION));
    if (!h) return E_FAIL;
    *phbmp = h;
    return S_OK;
}

IFACEMETHODIMP CRostorCredential::GetSubmitButtonValue(DWORD dwFieldID, DWORD* pdwAdjacentTo)
{
    if (dwFieldID != SFI_SUBMIT || !pdwAdjacentTo) return E_INVALIDARG;
    *pdwAdjacentTo = _pinMode ? SFI_PIN : SFI_PASSWORD;
    return S_OK;
}

IFACEMETHODIMP CRostorCredential::SetStringValue(DWORD dwFieldID, PCWSTR pwz)
{
    if (dwFieldID >= ARRAYSIZE(_rgCredProvFieldDescriptors)) return E_INVALIDARG;
    CREDENTIAL_PROVIDER_FIELD_TYPE cpft = _rgCredProvFieldDescriptors[dwFieldID].cpft;
    if (cpft != CPFT_EDIT_TEXT && cpft != CPFT_PASSWORD_TEXT) return E_INVALIDARG;
    if (dwFieldID == SFI_PASSWORD || dwFieldID == SFI_PIN) ClearSecret();
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
//
// Three presentations share this one entry point (contract §2.2/§2.3):
//   password  identifier + secret, as before;
//   badge tap the identifier field holds a reader burst (digits only) and the
//             secret is empty — a keyboard-wedge reader types the number and
//             then Enter, which LogonUI turns into this submit;
//   badge+PIN the tile is in PIN mode after an auth.continue: the remembered
//             number goes out again together with the PIN field.
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

    PCWSTR identifier = _rgFieldStrings[SFI_USERNAME] ? _rgFieldStrings[SFI_USERNAME] : L"";
    PCWSTR secret     = _rgFieldStrings[SFI_PASSWORD] ? _rgFieldStrings[SFI_PASSWORD] : L"";
    PCWSTR pin        = _rgFieldStrings[SFI_PIN]      ? _rgFieldStrings[SFI_PIN]      : L"";

    bool badge = _pinMode || (LooksLikeBadgeBurst(identifier) && *secret == L'\0');
    std::string req;
    if (_pinMode)
        req = "{\"op\":\"logon\",\"badge\":{\"number\":" + JsonQuote(_badgeNumber) + ",\"pin\":" + JsonQuote(pin) + "},\"locale\":\"en-US\"}";
    else if (badge)
        req = "{\"op\":\"logon\",\"badge\":{\"number\":" + JsonQuote(identifier) + "},\"locale\":\"en-US\"}";
    else
        req = "{\"op\":\"logon\",\"identifier\":" + JsonQuote(identifier) + ",\"secret\":" + JsonQuote(secret) + ",\"locale\":\"en-US\"}";
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
        if (badge && !_pinMode && code == "auth.continue" && reply["need"] == "pin")
        {
            // Card known, PIN required: not a result, the tile just asks
            // for one more field and stays up (NOT_FINISHED keeps LogonUI
            // on this credential with the caret where we put it).
            LogLine("logon: badge needs pin");
            EnterPinMode(identifier, _lastMessage);
            *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
            *pcpsiOptionalStatusIcon = CPSI_NONE;
            if (!_lastMessage.empty()) SHStrDupW(_lastMessage.c_str(), ppwszOptionalStatusText);
            for (auto& kv : reply) if (!kv.second.empty()) SecureZeroMemory(&kv.second[0], kv.second.size());
            return S_OK;
        }
        LogLine("logon: denied (%s)%s", code.c_str(), badge ? " [badge]" : "");
        *pcpgsr = CPGSR_NO_CREDENTIAL_FINISHED;
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        if (!_lastMessage.empty()) SHStrDupW(_lastMessage.c_str(), ppwszOptionalStatusText);
        // Back to the initial form; a failed badge attempt also drops the
        // number so the next tap starts from an empty field.
        ResetToInitial(badge);
        // Zero the secret we just wiped from the JSON too.
        for (auto& kv : reply) if (!kv.second.empty()) SecureZeroMemory(&kv.second[0], kv.second.size());
        return S_OK;
    }

    std::wstring localUser = Utf8ToWide(reply["local_user"]);
    std::wstring localSecret = Utf8ToWide(reply["local_secret"]);
    for (auto& kv : reply) if (!kv.second.empty()) SecureZeroMemory(&kv.second[0], kv.second.size());
    LogLine("logon: ok, local user '%s'%s", WideToUtf8(localUser).c_str(), badge ? " [badge]" : "");
    // The badge number and PIN have done their job; the packed credential
    // below is the local one the agent minted, exactly as on the password path.
    ResetToInitial(badge);

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
        // Clear the secrets (and leave any PIN mode) so a retry starts clean.
        ResetToInitial(_pinMode);
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
