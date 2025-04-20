// dragblock.cpp –  консольная DLL c глобальным хуком
#include "pch.h"
#include <Windows.h>
#include <Ole2.h>
#include <chrono>
#include "MinHook.h"

typedef HRESULT(WINAPI* PFN_DoDragDrop)(
    IDataObject*, IDropSource*, DWORD, DWORD*);
static PFN_DoDragDrop RealDoDragDrop = nullptr;

// --- Настройки логирования ---
DWORD g_LogLevel = 1; // 0 = отключено, 1 = обычный режим, 2 = отладка

enum LogLevel { LOG_INFO, LOG_ERROR, LOG_DEBUG };

// --- Логирование в системный журнал ---
void LogEvent(LogLevel level, const wchar_t* message)
{
    if (g_LogLevel == 0) return;

    WORD type;
    switch (level) {
    case LOG_INFO:  type = EVENTLOG_INFORMATION_TYPE; break;
    case LOG_ERROR: type = EVENTLOG_ERROR_TYPE; break;
    case LOG_DEBUG: type = EVENTLOG_INFORMATION_TYPE; break;
    default:        type = EVENTLOG_INFORMATION_TYPE; break;
    }

    HANDLE hEventLog = RegisterEventSourceW(NULL, L"DragBlock");
    if (hEventLog) {
        LPCWSTR strings[1] = { message };
        ReportEventW(hEventLog, type, 0, 0, NULL, 1, 0, strings, NULL);
        DeregisterEventSource(hEventLog);
    }
}

#define LOG(msg)     if (g_LogLevel >= 1) LogEvent(LOG_INFO, msg)
#define LOG_ERR(msg) if (g_LogLevel >= 1) LogEvent(LOG_ERROR, msg)
#define LOG_DBG(msg) if (g_LogLevel >= 2) LogEvent(LOG_DEBUG, msg)

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
        LogEvent(LOG_DEBUG, buffer);                               \
    }                                                              \
}

// --- Проверка на наличие текста ---
static bool HasText(IDataObject* obj)
{
    FORMATETC fmt = { 0, nullptr, DVASPECT_CONTENT, -1, TYMED_HGLOBAL };

    fmt.cfFormat = CF_UNICODETEXT;
    if (obj->QueryGetData(&fmt) == S_OK)
        return true;

    fmt.cfFormat = CF_TEXT;
    return obj->QueryGetData(&fmt) == S_OK;
}

// --- Хук DoDragDrop ---
static HRESULT WINAPI HookDoDragDrop(
    IDataObject* pObj, IDropSource* pSrc,
    DWORD okEff, DWORD* pEff)
{
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

// --- Регистрация источника событий ---
void RegisterEventSourceIfNeeded()
{
    HKEY hKey;
    LPCWSTR path = L"SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\DragBlock";
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        RegCreateKeyW(HKEY_LOCAL_MACHINE, path, &hKey);
        DWORD types = EVENTLOG_ERROR_TYPE | EVENTLOG_WARNING_TYPE | EVENTLOG_INFORMATION_TYPE;
        RegSetValueExW(hKey, L"TypesSupported", 0, REG_DWORD, (BYTE*)&types, sizeof(DWORD));
        RegCloseKey(hKey);
    }
}

// --- Загрузка уровня логирования из реестра ---
void LoadLogLevelFromRegistry()
{
    HKEY hKey;
    DWORD value = 1;
    DWORD size = sizeof(value);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\DragBlock", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExW(hKey, L"LogLevel", NULL, NULL, (LPBYTE)&value, &size) == ERROR_SUCCESS) {
            g_LogLevel = value;
        }
        RegCloseKey(hKey);
    }
}

// --- DllMain ---
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH) {
        MessageBoxW(NULL, L"DragBlock DLL loaded", L"DragBlock", MB_OK); // ← Уведомление при загрузке

        RegisterEventSourceIfNeeded();
        LoadLogLevelFromRegistry();
        LOG(L"DragBlock started");

        if (MH_Initialize() != MH_OK) {
            LOG_ERR(L"MinHook initialization failed");
            return FALSE;
        }

        if (MH_CreateHookApi(L"ole32.dll", "DoDragDrop",
            HookDoDragDrop, reinterpret_cast<void**>(&RealDoDragDrop)) != MH_OK) {
            LOG_ERR(L"Failed to hook DoDragDrop");
            return FALSE;
        }

        if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
            LOG_ERR(L"Failed to enable hooks");
            return FALSE;
        }

    }
    else if (reason == DLL_PROCESS_DETACH) {
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
        LOG(L"DragBlock stopped");

        MessageBoxW(NULL, L"DragBlock DLL unloaded", L"DragBlock", MB_OK); // ← Уведомление при выгрузке
    }

    return TRUE;
}
