#include "Provider.h"
#include "Credential.h"
#include "guid.h"
#include <shlwapi.h>

CRostorProvider::CRostorProvider() : _cRef(1), _cpus(CPUS_INVALID), _pCredential(nullptr)
{
    DllAddRef();
}

CRostorProvider::~CRostorProvider()
{
    ReleaseEnumeratedCredential();
    DllRelease();
}

void CRostorProvider::ReleaseEnumeratedCredential()
{
    if (_pCredential)
    {
        _pCredential->Release();
        _pCredential = nullptr;
    }
}

IFACEMETHODIMP_(ULONG) CRostorProvider::AddRef() { return InterlockedIncrement(&_cRef); }

IFACEMETHODIMP_(ULONG) CRostorProvider::Release()
{
    LONG cRef = InterlockedDecrement(&_cRef);
    if (!cRef) delete this;
    return cRef;
}

IFACEMETHODIMP CRostorProvider::QueryInterface(REFIID riid, void** ppv)
{
    static const QITAB qit[] =
    {
        QITABENT(CRostorProvider, ICredentialProvider),
        { 0 },
    };
    return QISearch(this, qit, riid, ppv);
}

// Called once per LogonUI session. This is where the `ui` strings are
// fetched (contract §2.1): once, before any tile is built.
IFACEMETHODIMP CRostorProvider::SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD)
{
    switch (cpus)
    {
    case CPUS_LOGON:
    case CPUS_UNLOCK_WORKSTATION:
        break;
    case CPUS_CHANGE_PASSWORD:
    case CPUS_CREDUI:
    default:
        return E_NOTIMPL;
    }
    _cpus = cpus;
    ReleaseEnumeratedCredential();

    UiStrings ui;
    if (!PipeFetchUi(ui))
        ui = UiStrings(); // agent down: empty labels, never invented text
    _ui = ui;
    LogLine("provider: scenario %d, tile label '%s'", (int)cpus, WideToUtf8(_ui.tile_label).c_str());

    CRostorCredential* pCred = new (std::nothrow) CRostorCredential();
    if (!pCred) return E_OUTOFMEMORY;
    HRESULT hr = pCred->Initialize(_cpus, s_rgFieldDescriptors, s_rgFieldStatePairs, _ui);
    if (FAILED(hr))
    {
        pCred->Release();
        return hr;
    }
    _pCredential = pCred;
    return S_OK;
}

IFACEMETHODIMP CRostorProvider::SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*)
{
    return E_NOTIMPL;
}

IFACEMETHODIMP CRostorProvider::Advise(ICredentialProviderEvents*, UINT_PTR) { return E_NOTIMPL; }
IFACEMETHODIMP CRostorProvider::UnAdvise() { return E_NOTIMPL; }

IFACEMETHODIMP CRostorProvider::GetFieldDescriptorCount(DWORD* pdwCount)
{
    *pdwCount = SFI_NUM_FIELDS;
    return S_OK;
}

IFACEMETHODIMP CRostorProvider::GetFieldDescriptorAt(DWORD dwIndex, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd)
{
    if (dwIndex >= SFI_NUM_FIELDS || !ppcpfd) return E_INVALIDARG;
    PCWSTR label = L"";
    switch (dwIndex)
    {
    case SFI_USERNAME: label = _ui.username_label.c_str(); break;
    case SFI_PASSWORD: label = _ui.password_label.c_str(); break;
    case SFI_SUBMIT:   label = _ui.submit_label.c_str(); break;
    }
    return FieldDescriptorCoAllocCopy(s_rgFieldDescriptors[dwIndex], label, ppcpfd);
}

IFACEMETHODIMP CRostorProvider::GetCredentialCount(DWORD* pdwCount, DWORD* pdwDefault, BOOL* pbAutoLogonWithDefault)
{
    *pdwCount = _pCredential ? 1 : 0;
    // Never the default tile: the built-in password provider stays the
    // safety net for the local admin (contract §4).
    *pdwDefault = CREDENTIAL_PROVIDER_NO_DEFAULT;
    *pbAutoLogonWithDefault = FALSE;
    return S_OK;
}

IFACEMETHODIMP CRostorProvider::GetCredentialAt(DWORD dwIndex, ICredentialProviderCredential** ppcpc)
{
    if (dwIndex != 0 || !_pCredential || !ppcpc) return E_INVALIDARG;
    return _pCredential->QueryInterface(IID_PPV_ARGS(ppcpc));
}

HRESULT CRostorProvider_CreateInstance(REFIID riid, void** ppv)
{
    CRostorProvider* pProvider = new (std::nothrow) CRostorProvider();
    if (!pProvider) return E_OUTOFMEMORY;
    HRESULT hr = pProvider->QueryInterface(riid, ppv);
    pProvider->Release();
    return hr;
}
