// dragblock.cpp –  консольная DLL c глобальным хуком
#include <Windows.h>
#include <Ole2.h>
#include "MinHook.h"

typedef HRESULT(WINAPI* PFN_DoDragDrop)(
    IDataObject*, IDropSource*, DWORD, DWORD*);

static PFN_DoDragDrop  RealDoDragDrop = nullptr;

static bool HasText(IDataObject* obj)
{
    FORMATETC fmt{ nullptr, nullptr, DVASPECT_CONTENT, -1, TYMED_HGLOBAL };
    fmt.cfFormat = CF_UNICODETEXT;
    if (obj->QueryGetData(&fmt) == S_OK) return true;
    fmt.cfFormat = CF_TEXT;
    return obj->QueryGetData(&fmt) == S_OK;
}

static HRESULT WINAPI HookDoDragDrop(
    IDataObject* pObj, IDropSource* pSrc,
    DWORD okEff, DWORD* pEff)
{
    if (pObj && HasText(pObj)) {
        if (pEff) *pEff = DROPEFFECT_NONE;
        return DRAGDROP_S_CANCEL;          // ← отмена
    }
    return RealDoDragDrop(pObj, pSrc, okEff, pEff);
}

BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID)
{
    if (r == DLL_PROCESS_ATTACH) {
        MH_Initialize();
        MH_CreateHookApi(L"ole32.dll", "DoDragDrop",
            HookDoDragDrop,
            reinterpret_cast<void**>(&RealDoDragDrop));
        MH_EnableHook(MH_ALL_HOOKS);
    }
    else if (r == DLL_PROCESS_DETACH) {
        MH_Uninitialize();
    }
    return TRUE;
}
