// COM plumbing: class factory and the four DLL exports LogonUI needs.
#include "common.h"
#include "guid.h"
#include "Provider.h"
#include <shlwapi.h>

static LONG g_cRef = 0;
HINSTANCE g_hinst = nullptr;

void DllAddRef() { InterlockedIncrement(&g_cRef); }
void DllRelease() { InterlockedDecrement(&g_cRef); }

class CClassFactory : public IClassFactory
{
public:
    CClassFactory() : _cRef(1) {}

    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv)
    {
        static const QITAB qit[] = { QITABENT(CClassFactory, IClassFactory), { 0 } };
        return QISearch(this, qit, riid, ppv);
    }
    IFACEMETHODIMP_(ULONG) AddRef() { return InterlockedIncrement(&_cRef); }
    IFACEMETHODIMP_(ULONG) Release()
    {
        LONG cRef = InterlockedDecrement(&_cRef);
        if (!cRef) delete this;
        return cRef;
    }

    IFACEMETHODIMP CreateInstance(IUnknown* pUnkOuter, REFIID riid, void** ppv)
    {
        if (pUnkOuter) return CLASS_E_NOAGGREGATION;
        return CRostorProvider_CreateInstance(riid, ppv);
    }
    IFACEMETHODIMP LockServer(BOOL bLock)
    {
        if (bLock) DllAddRef(); else DllRelease();
        return S_OK;
    }

private:
    ~CClassFactory() {}
    LONG _cRef;
};

STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, void** ppv)
{
    *ppv = nullptr;
    if (!IsEqualCLSID(rclsid, CLSID_RostorCredProv)) return CLASS_E_CLASSNOTAVAILABLE;
    CClassFactory* pcf = new (std::nothrow) CClassFactory();
    if (!pcf) return E_OUTOFMEMORY;
    HRESULT hr = pcf->QueryInterface(riid, ppv);
    pcf->Release();
    return hr;
}

STDAPI DllCanUnloadNow()
{
    return g_cRef > 0 ? S_FALSE : S_OK;
}

STDAPI_(BOOL) DllMain(HINSTANCE hinstDll, DWORD dwReason, LPVOID)
{
    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hinstDll);
        g_hinst = hinstDll;
        break;
    }
    return TRUE;
}
