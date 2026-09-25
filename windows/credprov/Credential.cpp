#include "Credential.h"
#include "guid.h"
#include <shlwapi.h>

CRostorCredential::CRostorCredential()
    : _cRef(1), _cpus(CPUS_INVALID), _pCredProvCredentialEvents(nullptr),
      _pinMode(false), _badgeMode(false), _haveSwitch(false)
{
    DllAddRef();
    ZeroMemory(_rgCredProvFieldDescriptors, sizeof(_rgCredProvFieldDescriptors));
    ZeroMemory(_rgFieldStatePairs, sizeof(_rgFieldStatePairs));
    ZeroMemory(_rgFieldStrings, sizeof(_rgFieldStrings));
}

CRostorCredential::~CRostorCredential()
{
    ClearSecret();
    ZeroField(SFI_BADGE);
    for (int i = 0; i < ARRAYSIZE(_rgFieldStrings); i++)
    {
        CoTaskMemFree(_rgFieldStrings[i]);
        CoTaskMemFree(_rgCredProvFieldDescriptors[i].pszLabel);
    }
    DllRelease();
}

// Wipe one field's characters in place (the buffer itself is freed by the
// caller, or kept and shown as empty).
void CRostorCredential::ZeroField(DWORD fieldID)
{
    if (_rgFieldStrings[fieldID])
    {
        size_t len = wcslen(_rgFieldStrings[fieldID]);
        SecureZeroMemory(_rgFieldStrings[fieldID], len * sizeof(wchar_t));
    }
}

void CRostorCredential::ClearSecret()
{
    ZeroField(SFI_PASSWORD);
    ZeroField(SFI_PIN);
}

// Replace a field's stored value and, when LogonUI is listening, its display.
// The masked identifier is a credential too (a card number): it is zeroed
// before its buffer goes, but on its own — replacing it must not blank a PIN
// the person is typing, and vice versa.
void CRostorCredential::SetFieldValue(DWORD fieldID, PCWSTR value)
{
    if (fieldID == SFI_PASSWORD || fieldID == SFI_PIN) ClearSecret();
    else if (fieldID == SFI_BADGE) ZeroField(SFI_BADGE);
    CoTaskMemFree(_rgFieldStrings[fieldID]);
    _rgFieldStrings[fieldID] = nullptr;
    if (FAILED(SHStrDupW(value, &_rgFieldStrings[fieldID]))) return;
    if (_pCredProvCredentialEvents)
        _pCredProvCredentialEvents->SetFieldString(this, fieldID, _rgFieldStrings[fieldID]);
}

// ---- mode → field states -----------------------------------------------------
//
// Three flags decide what the tile shows:
//   _badgeMode   the masked field (SFI_BADGE) is the identifier and the secret
//                field is pointless, so it is hidden; otherwise the plain field
//                (SFI_USERNAME) and the secret are shown;
//   _pinMode     a PIN is pending after auth.continue: the identifier that was
//                used goes read-only (the number stays on screen), the secret
//                is hidden, the PIN field is shown and focused, and the switch
//                link is hidden so the tap cannot be abandoned half-way;
//   _haveSwitch  the deputy sent both link texts; without them the link is
//                hidden and the tile behaves as it did before v0.13.0.
// SFI_LABEL, SFI_SUBMIT and SFI_TILEIMAGE keep the static table's states.

void CRostorCredential::ApplyFieldStates()
{
    const bool pin = _pinMode;
    const CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE identifierState = pin ? CPFIS_READONLY : CPFIS_FOCUSED;

    FIELD_STATE_PAIR& user = _rgFieldStatePairs[SFI_USERNAME];
    user.cpfs  = _badgeMode ? CPFS_HIDDEN : CPFS_DISPLAY_IN_SELECTED_TILE;
    user.cpfis = _badgeMode ? CPFIS_NONE : identifierState;

    FIELD_STATE_PAIR& badge = _rgFieldStatePairs[SFI_BADGE];
    badge.cpfs  = _badgeMode ? CPFS_DISPLAY_IN_SELECTED_TILE : CPFS_HIDDEN;
    badge.cpfis = _badgeMode ? identifierState : CPFIS_NONE;

    FIELD_STATE_PAIR& secret = _rgFieldStatePairs[SFI_PASSWORD];
    secret.cpfs  = (_badgeMode || pin) ? CPFS_HIDDEN : CPFS_DISPLAY_IN_SELECTED_TILE;
    secret.cpfis = CPFIS_NONE;

    FIELD_STATE_PAIR& pinField = _rgFieldStatePairs[SFI_PIN];
    pinField.cpfs  = pin ? CPFS_DISPLAY_IN_SELECTED_TILE : CPFS_HIDDEN;
    pinField.cpfis = pin ? CPFIS_FOCUSED : CPFIS_NONE;

    FIELD_STATE_PAIR& link = _rgFieldStatePairs[SFI_SWITCH];
    link.cpfs  = (_haveSwitch && !pin) ? CPFS_DISPLAY_IN_SELECTED_TILE : CPFS_HIDDEN;
    link.cpfis = CPFIS_NONE;
}

// Push the computed states to LogonUI. Visibility first, then the
// non-focused interactive states, then the one focused field last so the
// caret lands on a field that is already visible; finally the submit button
// is moved next to whichever field is live.
void CRostorCredential::PushFieldStates()
{
    ICredentialProviderCredentialEvents* ev = _pCredProvCredentialEvents;
    if (!ev) return;
    static const DWORD dynamicFields[] = { SFI_USERNAME, SFI_BADGE, SFI_PASSWORD, SFI_PIN, SFI_SWITCH };
    for (DWORD id : dynamicFields)
        ev->SetFieldState(this, id, _rgFieldStatePairs[id].cpfs);
    for (DWORD id : dynamicFields)
        if (_rgFieldStatePairs[id].cpfis != CPFIS_FOCUSED)
            ev->SetFieldInteractiveState(this, id, _rgFieldStatePairs[id].cpfis);
    for (DWORD id : dynamicFields)
        if (_rgFieldStatePairs[id].cpfis == CPFIS_FOCUSED)
            ev->SetFieldInteractiveState(this, id, CPFIS_FOCUSED);
    ev->SetFieldSubmitButton(this, SFI_SUBMIT, SubmitAdjacentTo());
}

DWORD CRostorCredential::SubmitAdjacentTo() const
{
    if (_pinMode) return SFI_PIN;
    return _badgeMode ? SFI_BADGE : SFI_PASSWORD;
}

// The link always names the *other* mode.
PCWSTR CRostorCredential::SwitchLinkText() const
{
    return _badgeMode ? _ui.switch_to_username.c_str() : _ui.switch_to_badge.c_str();
}

// The deputy answered auth.continue for a badge tap: keep the number, swap the
// secret field for the PIN field, move the submit button next to it and put
// the caret there so the person just types the PIN and presses Enter. LogonUI
// cannot relabel a live field, which is why the PIN field is a separate
// (normally hidden) field carrying `pin_label`. Works the same from either
// identifier field; the one that was used stays visible, read-only.
void CRostorCredential::EnterPinMode(PCWSTR badgeNumber, const std::wstring& prompt)
{
    _pinMode = true;
    _badgeNumber = badgeNumber ? badgeNumber : L"";
    SetFieldValue(SFI_PIN, L"");
    ApplyFieldStates();
    PushFieldStates();
    // The large text carries the deputy's prompt while the PIN is pending.
    if (_pCredProvCredentialEvents && !prompt.empty())
        _pCredProvCredentialEvents->SetFieldString(this, SFI_LABEL, prompt.c_str());
}

// Back to the initial form of the current mode: PIN field hidden, the live
// identifier focused, submit next to the secret (username mode) or the masked
// field (badge mode), the switch link back if the deputy sent one. Secrets are
// wiped either way; the identifier is cleared after a badge attempt (it held
// the card number) but kept after a password denial so the person can retry.
// The mode itself survives: a person who chose "Use username" stays there.
void CRostorCredential::ResetToInitial(bool clearIdentifier)
{
    bool wasPin = _pinMode;
    _pinMode = false;
    if (!_badgeNumber.empty()) SecureZeroMemory(&_badgeNumber[0], _badgeNumber.size() * sizeof(wchar_t));
    _badgeNumber.clear();
    SetFieldValue(SFI_PASSWORD, L"");
    SetFieldValue(SFI_PIN, L"");
    if (clearIdentifier)
    {
        SetFieldValue(SFI_USERNAME, L"");
        SetFieldValue(SFI_BADGE, L"");
    }
    ApplyFieldStates();
    // Only leaving PIN mode changes what is on screen; nothing to tell
    // LogonUI otherwise (and SetDeselected calls this on every deselect).
    if (wasPin)
    {
        PushFieldStates();
        if (_pCredProvCredentialEvents)
            _pCredProvCredentialEvents->SetFieldString(this, SFI_LABEL, _rgFieldStrings[SFI_LABEL]);
    }
}

HRESULT CRostorCredential::Initialize(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
                                      const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* rgcpfd,
                                      const FIELD_STATE_PAIR* rgfsp,
                                      const UiStrings& ui)
{
    _cpus = cpus;
    _ui = ui;
    _pinMode = false;
    _haveSwitch = HasSwitchLink(_ui);
    _badgeMode = OpensInBadgeMode(_ui);
    HRESULT hr = S_OK;
    for (DWORD i = 0; SUCCEEDED(hr) && i < ARRAYSIZE(_rgCredProvFieldDescriptors); i++)
    {
        _rgFieldStatePairs[i] = rgfsp[i];
        _rgCredProvFieldDescriptors[i] = rgcpfd[i];
        hr = SHStrDupW(FieldLabel(_ui, i), &_rgCredProvFieldDescriptors[i].pszLabel);
    }
    ApplyFieldStates();
    // Field values: the large text shows the heading (the tile label from an
    // older deputy); identifier, secret and PIN fields empty; the submit
    // button and the link carry their texts.
    PCWSTR top = _ui.heading.empty() ? _ui.tile_label.c_str() : _ui.heading.c_str();
    if (SUCCEEDED(hr)) hr = SHStrDupW(top, &_rgFieldStrings[SFI_LABEL]);
    if (SUCCEEDED(hr)) hr = SHStrDupW(L"", &_rgFieldStrings[SFI_USERNAME]);
    if (SUCCEEDED(hr)) hr = SHStrDupW(L"", &_rgFieldStrings[SFI_BADGE]);
    if (SUCCEEDED(hr)) hr = SHStrDupW(L"", &_rgFieldStrings[SFI_PASSWORD]);
    if (SUCCEEDED(hr)) hr = SHStrDupW(L"", &_rgFieldStrings[SFI_PIN]);
    if (SUCCEEDED(hr)) hr = SHStrDupW(_ui.submit_label.c_str(), &_rgFieldStrings[SFI_SUBMIT]);
    if (SUCCEEDED(hr)) hr = SHStrDupW(SwitchLinkText(), &_rgFieldStrings[SFI_SWITCH]);
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
    // Drop the secrets (and any pending badge) as soon as the tile loses
    // focus. In badge mode the identifier field only ever holds a card
    // number, so it goes too; a typed username is kept as before.
    ResetToInitial(_pinMode || _badgeMode);
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
    // The tile image ships beside the deputy (install.ps1 copies it). A
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
    *pdwAdjacentTo = SubmitAdjacentTo();
    return S_OK;
}

IFACEMETHODIMP CRostorCredential::SetStringValue(DWORD dwFieldID, PCWSTR pwz)
{
    if (dwFieldID >= ARRAYSIZE(_rgCredProvFieldDescriptors)) return E_INVALIDARG;
    CREDENTIAL_PROVIDER_FIELD_TYPE cpft = _rgCredProvFieldDescriptors[dwFieldID].cpft;
    if (cpft != CPFT_EDIT_TEXT && cpft != CPFT_PASSWORD_TEXT) return E_INVALIDARG;
    if (dwFieldID == SFI_PASSWORD || dwFieldID == SFI_PIN) ClearSecret();
    else if (dwFieldID == SFI_BADGE) ZeroField(SFI_BADGE);
    PWSTR* ppwszStored = &_rgFieldStrings[dwFieldID];
    CoTaskMemFree(*ppwszStored);
    return SHStrDupW(pwz, ppwszStored);
}

IFACEMETHODIMP CRostorCredential::GetCheckboxValue(DWORD, BOOL*, PWSTR*) { return E_INVALIDARG; }
IFACEMETHODIMP CRostorCredential::GetComboBoxValueCount(DWORD, DWORD*, DWORD*) { return E_INVALIDARG; }
IFACEMETHODIMP CRostorCredential::GetComboBoxValueAt(DWORD, DWORD, PWSTR*) { return E_INVALIDARG; }
IFACEMETHODIMP CRostorCredential::SetCheckboxValue(DWORD, BOOL) { return E_INVALIDARG; }
IFACEMETHODIMP CRostorCredential::SetComboBoxSelectedValue(DWORD, DWORD) { return E_INVALIDARG; }

// The one command link swaps the identifier fields (contract §2.1, v0.13.0):
// badge mode ↔ username mode. Neither field inherits the other's text and no
// secret survives the switch. The link is hidden while a PIN is pending; if a
// click still arrives then it is ignored rather than abandoning the tap.
IFACEMETHODIMP CRostorCredential::CommandLinkClicked(DWORD dwFieldID)
{
    if (dwFieldID != SFI_SWITCH || !_haveSwitch) return E_INVALIDARG;
    if (_pinMode) return S_OK;
    _badgeMode = !_badgeMode;
    LogLine("tile: switched to %s mode", _badgeMode ? "badge" : "username");
    SetFieldValue(SFI_USERNAME, L"");
    SetFieldValue(SFI_BADGE, L"");
    SetFieldValue(SFI_PASSWORD, L"");
    SetFieldValue(SFI_SWITCH, SwitchLinkText());
    ApplyFieldStates();
    PushFieldStates();
    return S_OK;
}

// Submit: ask the deputy; on ok serialize the *local* credential it returned.
//
// Four presentations share this one entry point (contract §2.2/§2.3):
//   password   username mode, identifier + secret, as before;
//   badge tap  either the masked field holds the burst (badge mode: always a
//              badge, no digits test) or the plain field holds a digits-only
//              burst with an empty secret — a keyboard-wedge reader types the
//              number and then Enter, which LogonUI turns into this submit;
//   badge+PIN  the tile is in PIN mode after an auth.continue: the remembered
//              number goes out again together with the PIN field.
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

    // Show "connecting" while the deputy works, then restore the label.
    if (_pCredProvCredentialEvents && !_ui.connecting.empty())
        _pCredProvCredentialEvents->SetFieldString(this, SFI_LABEL, _ui.connecting.c_str());

    const DWORD idField = IdentifierField();
    PCWSTR identifier = _rgFieldStrings[idField]      ? _rgFieldStrings[idField]      : L"";
    PCWSTR secret     = _rgFieldStrings[SFI_PASSWORD] ? _rgFieldStrings[SFI_PASSWORD] : L"";
    PCWSTR pin        = _rgFieldStrings[SFI_PIN]      ? _rgFieldStrings[SFI_PIN]      : L"";

    bool badge = _pinMode || _badgeMode || (LooksLikeBadgeBurst(identifier) && *secret == L'\0');
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
        // The deputy renders text; the credprov never invents any. When the
        // deputy itself is unreachable there is no text at all — only a code
        // in the log — and LogonUI shows a generic failure.
        if (ok) code = reply["code"];
        _lastMessage = Utf8ToWide(reply["message"]);
        if (badge && !_pinMode && code == "auth.continue" && reply["need"] == "pin")
        {
            // Card known, PIN required: not a result, the tile just asks
            // for one more field and stays up (NOT_FINISHED keeps LogonUI
            // on this credential with the caret where we put it).
            LogLine("logon: badge needs pin%s", _badgeMode ? " [masked]" : "");
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
    // below is the local one the deputy minted, exactly as on the password path.
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
        // Surface the deputy's rendered text; if LSA itself failed after an
        // ALLOW there is no deputy text and LogonUI shows its own.
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
