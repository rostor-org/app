// The single Rostor tile.
#pragma once
#include "common.h"

class CRostorCredential : public ICredentialProviderCredential2
{
public:
    // IUnknown
    IFACEMETHODIMP_(ULONG) AddRef();
    IFACEMETHODIMP_(ULONG) Release();
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv);

    // ICredentialProviderCredential
    IFACEMETHODIMP Advise(ICredentialProviderCredentialEvents* pcpce);
    IFACEMETHODIMP UnAdvise();
    IFACEMETHODIMP SetSelected(BOOL* pbAutoLogon);
    IFACEMETHODIMP SetDeselected();
    IFACEMETHODIMP GetFieldState(DWORD dwFieldID, CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
                                 CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis);
    IFACEMETHODIMP GetStringValue(DWORD dwFieldID, PWSTR* ppwsz);
    IFACEMETHODIMP GetBitmapValue(DWORD dwFieldID, HBITMAP* phbmp);
    IFACEMETHODIMP GetCheckboxValue(DWORD dwFieldID, BOOL* pbChecked, PWSTR* ppwszLabel);
    IFACEMETHODIMP GetComboBoxValueCount(DWORD dwFieldID, DWORD* pcItems, DWORD* pdwSelectedItem);
    IFACEMETHODIMP GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, PWSTR* ppwszItem);
    IFACEMETHODIMP GetSubmitButtonValue(DWORD dwFieldID, DWORD* pdwAdjacentTo);
    IFACEMETHODIMP SetStringValue(DWORD dwFieldID, PCWSTR pwz);
    IFACEMETHODIMP SetCheckboxValue(DWORD dwFieldID, BOOL bChecked);
    IFACEMETHODIMP SetComboBoxSelectedValue(DWORD dwFieldID, DWORD dwSelectedItem);
    IFACEMETHODIMP CommandLinkClicked(DWORD dwFieldID);
    IFACEMETHODIMP GetSerialization(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
                                    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
                                    PWSTR* ppwszOptionalStatusText,
                                    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon);
    IFACEMETHODIMP ReportResult(NTSTATUS ntsStatus, NTSTATUS ntsSubstatus,
                                PWSTR* ppwszOptionalStatusText,
                                CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon);

    // ICredentialProviderCredential2: this tile is not bound to a user SID.
    IFACEMETHODIMP GetUserSid(PWSTR* ppszSid);

    CRostorCredential();
    HRESULT Initialize(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
                       const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* rgcpfd,
                       const FIELD_STATE_PAIR* rgfsp,
                       const UiStrings& ui);

private:
    virtual ~CRostorCredential();
    void ClearSecret();
    void ZeroField(DWORD fieldID);
    void SetFieldValue(DWORD fieldID, PCWSTR value);
    void EnterPinMode(PCWSTR badgeNumber, const std::wstring& prompt);
    void ResetToInitial(bool clearIdentifier);

    // Mode → field states. ApplyFieldStates recomputes _rgFieldStatePairs
    // from _badgeMode/_pinMode/_haveSwitch; PushFieldStates tells LogonUI
    // (when it is listening) the states, the focus and where the submit
    // button sits. Every mode change goes through the pair.
    void ApplyFieldStates();
    void PushFieldStates();
    DWORD IdentifierField() const { return _badgeMode ? SFI_BADGE : SFI_USERNAME; }
    DWORD SubmitAdjacentTo() const;
    PCWSTR SwitchLinkText() const;

    LONG _cRef;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO _cpus;
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR _rgCredProvFieldDescriptors[SFI_NUM_FIELDS];
    FIELD_STATE_PAIR _rgFieldStatePairs[SFI_NUM_FIELDS];
    PWSTR _rgFieldStrings[SFI_NUM_FIELDS];
    ICredentialProviderCredentialEvents* _pCredProvCredentialEvents;
    UiStrings _ui;
    std::wstring _lastMessage; // rendered text from the deputy for ReportResult

    // Badge + PIN (contract §2.3): after a tap the deputy may answer
    // auth.continue; the tile then hides the secret field, shows the PIN
    // field and resends the same badge number with the PIN on the next submit.
    bool _pinMode;
    // Badge-first tile (contract §2.1, v0.13.0): which identifier field is
    // live (the masked SFI_BADGE or the plain SFI_USERNAME), and whether the
    // deputy sent the two link texts that make the command link usable.
    bool _badgeMode;
    bool _haveSwitch;
    std::wstring _badgeNumber;
};
