// CLSID of the Rostor credential provider. Fixed by the contract (§4); the
// install script and the registry keys use the same value.
#pragma once
#include <initguid.h>

// {7A4C2E10-5B0D-4F4E-9C1B-3E2D7F1A6B01}
DEFINE_GUID(CLSID_RostorCredProv,
    0x7A4C2E10, 0x5B0D, 0x4F4E, 0x9C, 0x1B, 0x3E, 0x2D, 0x7F, 0x1A, 0x6B, 0x01);
