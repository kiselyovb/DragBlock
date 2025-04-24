// dragblock.cpp – консольная DLL c глобальным хуком и логированием в файл по имени DLL
#include "pch.h"
#include <Windows.h>
#include <Ole2.h>
#include <chrono>
#include <fstream>
#include "MinHook.h"

typedef HRESULT(WINAPI* PFN_DoDragDrop)(IDataObject*, IDropSource*, DWORD, DWORD*);
static PFN_DoDragDrop RealDoDragDrop = nullptr;

DWORD g_LogLevel = 1; // 0 = отключено, 1 = обычный режим, 2 = отладка
std::wstring g_logFile;

enum LogLevel { LOG_INFO, LOG_ERROR, LOG_DEBUG };

// --- Логирование в текстовый файл ---
void InitLogFileName(HMODULE hModule) {
    wchar_t path[MAX_PATH];
    if (GetModuleFileNameW(hModule, path, MAX_PATH)) {
        std::wstring full(path); // полный путь к DLL или EXE
        size_t lastSlash = full.find_last_of(L"\\/");
        size_t lastDot = full.find_last_of(L".");
        std::wstring baseName = (lastSlash != std::wstring::npos && lastDot != std::wstring::npos && lastDot > lastSlash)
            ? full.substr(lastSlash + 1, lastDot - lastSlash - 1)
            : L"DragBlock";

        std::wstring directory = (lastSlash != std::wstring::npos)
            ? full.substr(0, lastSlash + 1)
            : L"";

        g_logFile = directory + baseName + L".log";

        std::wofstream out(g_logFile, std::ios::app);
        if (out.is_open()) {
            SYSTEMTIME st; GetLocalTime(&st);
            out << st.wYear << L"-" << st.wMonth << L"-" << st.wDay << L" "
                << st.wHour << L":" << st.wMinute << L":" << st.wSecond << L" [INF] "
                << L"Logging to: " << g_logFile << std::endl;
        }
    }
    else {
        g_logFile = L"DragBlock.log"; // fallback
    }
}

void LogToFile(LogLevel level, const wchar_t* message) {
    if (g_LogLevel == 0) return;

    const wchar_t* prefix = (level == LOG_ERROR) ? L"[ERR] " :
        (level == LOG_DEBUG) ? L"[DBG] " : L"[INF] ";

    std::wofstream out(g_logFile, std::ios::app);
    if (out.is_open()) {
        SYSTEMTIME st; GetLocalTime(&st);
        out << st.wYear << L"-" << st.wMonth << L"-" << st.wDay << L" "
            << st.wHour << L":" << st.wMinute << L":" << st.wSecond << L" "
            << prefix << message << std::endl;
    }
}

#define LOG(msg)     if (g_LogLevel >= 1) LogToFile(LOG_INFO, msg)
#define LOG_ERR(msg) if (g_LogLevel >= 1) LogToFile(LOG_ERROR, msg)
#define LOG_DBG(msg) if (g_LogLevel >= 2) LogToFile(LOG_DEBUG, msg)

#define LOG_TIMED_FUNCTION(name, block)                            \
{                                                                  \
    if (g_LogLevel < 2) { block }                                  \
    else {                                                         \
        using namespace std::chrono;                               \
        auto __start = high_resolution_clock::now();               \
        block                                                      \
        auto __end = high_resolution_clock::now();                 \
        auto __elapsed = duration_cast<milliseconds>(__end - __start); \
        wchar_t buffer[256];                                       \
        swprintf(buffer, 256, L"%s executed in %lld ms",           \
                 name, __elapsed.count());                         \
        LogToFile(LOG_DEBUG, buffer);                              \
    }                                                              \
}

static bool HasText(IDataObject* obj) {
    FORMATETC fmt = { 0, nullptr, DVASPECT_CONTENT, -1, TYMED_HGLOBAL };
    fmt.cfFormat = CF_UNICODETEXT;
    if (obj->QueryGetData(&fmt) == S_OK)
        return true;
    fmt.cfFormat = CF_TEXT;
    return obj->QueryGetData(&fmt) == S_OK;
}

static HRESULT WINAPI HookDoDragDrop(IDataObject* pObj, IDropSource* pSrc, DWORD okEff, DWORD* pEff) {
    LOG_DBG(L"Entered HookDoDragDrop");
    bool cancel = false;
    LOG_TIMED_FUNCTION(L"HasText", {
        cancel = (pObj && HasText(pObj));
        });
    if (cancel) {
        if (pEff) *pEff = DROPEFFECT_NONE;
        LOG(L"Drag operation cancelled due to protected text content");
        return DRAGDROP_S_CANCEL;
    }
    return RealDoDragDrop(pObj, pSrc, okEff, pEff);
}

void LoadLogLevelFromRegistry() {
    HKEY hKey;
    DWORD value = 1;
    DWORD size = sizeof(value);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\DragBlock", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExW(hKey, L"LogLevel", NULL, NULL, (LPBYTE)&value, &size) == ERROR_SUCCESS) {
            g_LogLevel = value;
            LOG(L"LogLevel loaded from registry");
        }
        else {
            LOG_ERR(L"LogLevel not found in registry — using default");
        }
        RegCloseKey(hKey);
    }
    else {
        LOG_ERR(L"Registry key SOFTWARE\\DragBlock not found — using default log level");
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        InitLogFileName(hModule);
        LoadLogLevelFromRegistry();
        LOG(L"DragBlock started");

        if (!GetModuleHandleW(L"ole32.dll")) {
            LOG_DBG(L"ole32.dll not loaded yet — loading manually");
            LoadLibraryW(L"ole32.dll");
        }

        if (MH_Initialize() != MH_OK) {
            LOG_ERR(L"MinHook initialization failed");
            return FALSE;
        }
<<<<<<< HEAD

        MH_STATUS hookStatus = MH_CreateHookApi(
            L"ole32.dll", "DoDragDrop",
            HookDoDragDrop, reinterpret_cast<void**>(&RealDoDragDrop));

        if (hookStatus != MH_OK) {
            wchar_t msg[128];
            swprintf(msg, 128, L"Failed to hook DoDragDrop: MH_STATUS = %d", hookStatus);
            LOG_ERR(msg);
=======
        if (MH_CreateHookApi(L"ole32.dll", "DoDragDrop",
            HookDoDragDrop, reinterpret_cast<void**>(&RealDoDragDrop)) != MH_OK) {
            LOG_ERR(L"Failed to hook DoDragDrop");
>>>>>>> 63f1b3e50a89fefc8929d03a4a0b59ed6c8f984d
            return FALSE;
        }
        if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
            LOG_ERR(L"Failed to enable hooks");
            return FALSE;
        }
<<<<<<< HEAD

        LOG(L"DoDragDrop hook installed successfully");

=======
>>>>>>> 63f1b3e50a89fefc8929d03a4a0b59ed6c8f984d
    }
    else if (reason == DLL_PROCESS_DETACH) {
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
        LOG(L"DragBlock stopped");
    }
    return TRUE;
}
