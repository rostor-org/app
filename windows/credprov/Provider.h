#pragma once
#include "common.h"

class CRostorCredential;

class CRostorProvider : public ICredentialProvider
{
public:
    IFACEMETHODIMP_(ULONG) AddRef();
    IFACEMETHODIMP_(ULONG) Release();
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv);

    IFACEMETHODIMP SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD dwFlags);
    IFACEMETHODIMP SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs);
    IFACEMETHODIMP Advise(ICredentialProviderEvents* pcpe, UINT_PTR upAdviseContext);
    IFACEMETHODIMP UnAdvise();
    IFACEMETHODIMP GetFieldDescriptorCount(DWORD* pdwCount);
    IFACEMETHODIMP GetFieldDescriptorAt(DWORD dwIndex, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd);
    IFACEMETHODIMP GetCredentialCount(DWORD* pdwCount, DWORD* pdwDefault, BOOL* pbAutoLogonWithDefault);
    IFACEMETHODIMP GetCredentialAt(DWORD dwIndex, ICredentialProviderCredential** ppcpc);

    friend HRESULT CRostorProvider_CreateInstance(REFIID riid, void** ppv);

protected:
    CRostorProvider();
    virtual ~CRostorProvider();

private:
    void ReleaseEnumeratedCredential();

    LONG _cRef;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO _cpus;
    CRostorCredential* _pCredential;
    UiStrings _ui;
};

HRESULT CRostorProvider_CreateInstance(REFIID riid, void** ppv);
