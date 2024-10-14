#include "RpcServerTestCancel.h"

std::unordered_map<HANDLE, std::wstring> g_ThreadDescriptions;
std::mutex g_ThreadDescriptionsMutex;
GUID m_guidMyContext;

void AppendText(HWND hEdit, const std::wstring& text) {
    // 禁用重绘
    SendMessageW(hEdit, WM_SETREDRAW, FALSE, 0);

    CHARRANGE cr = { 0 };
    cr.cpMin = -1;
    cr.cpMax = -1;
    SendMessageW(hEdit, EM_EXSETSEL, 0, (LPARAM)&cr);
    SendMessageW(hEdit, EM_REPLACESEL, FALSE, (LPARAM)text.c_str());

    // 滚动到文本框底部
    SendMessageW(hEdit, WM_VSCROLL, SB_BOTTOM, 0);

    // 启用重绘并强制重新绘制
    SendMessageW(hEdit, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(hEdit, NULL, TRUE);
    SetFocus(hEdit);  // 防止失焦
}

void Log(HWND hEdit, const std::wstring& message, LogLevel level) {
    std::wstringstream ss;
    switch (level) {
    case INFO:
        ss << L"[INFO] ";
        break;
    case KERROR:
        ss << L"[ERROR] ";
        break;
    case WARNING:
        ss << L"[WARNING] ";
        break;
    }
    ss << message << L"\r\n";
    AppendText(hEdit, ss.str());
}

// 检查是否以管理员权限启动
bool IsRunAsAdmin() {
    BOOL isRunAsAdmin = FALSE;
    PSID adminGroup = NULL;

    // 获取管理员组的 SID
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    if (!AllocateAndInitializeSid(&ntAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0, &adminGroup)) {
        return false;
    }

    // 检查当前进程的令牌是否包含管理员组的 SID
    HANDLE token = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_GROUPS* groupInfo = NULL;
        DWORD size = 0;

        // 获取令牌的组信息
        GetTokenInformation(token, TokenGroups, NULL, 0, &size);
        groupInfo = (TOKEN_GROUPS*)malloc(size);

        if (groupInfo && GetTokenInformation(token, TokenGroups, groupInfo, size, &size)) {
            for (DWORD i = 0; i < groupInfo->GroupCount; i++) {
                if (EqualSid(groupInfo->Groups[i].Sid, adminGroup)) {
                    isRunAsAdmin = TRUE;
                    break;
                }
            }
        }

        if (groupInfo) {
            free(groupInfo);
        }
        CloseHandle(token);
    }

    if (adminGroup) {
        FreeSid(adminGroup);
    }

    return isRunAsAdmin;
}

// 启用 SE_DEBUG 权限
bool EnableDebugPrivilege() {
    HANDLE token;
    LUID luid;
    TOKEN_PRIVILEGES tp = { 0 };

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        return false;
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(token);
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(token, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        CloseHandle(token);
        return false;
    }

    CloseHandle(token);
    return GetLastError() == ERROR_SUCCESS;
}

bool ModifyFunctionInWinlogon(bool enable, HWND hEdit) {
    Log(hEdit, enable ? L"Blocking Winlogon Messages..." : L"Enabling Winlogon Messages...", INFO);

    Log(hEdit, L"Attempting to get module handle of Rpcrt4...", INFO);
    auto module = GetModuleHandleW(L"rpcrt4.dll");
    if (!module) {
        Log(hEdit, L"Failed to get module handle.", KERROR);
        return false;
    }

    WCHAR wsModBuffer[55];

    ZeroMemory(wsModBuffer, 55 * sizeof(WCHAR));

    swprintf_s(wsModBuffer, L"Rpcrt4 Module Handle: 0x%p", module);

    Log(hEdit, wsModBuffer, INFO);

    Log(hEdit, L"Attempting to get function RpcServerTestCancel's address...", INFO);

    auto func = GetProcAddress(module, "RpcServerTestCancel");
    if (!func) {
        Log(hEdit, L"Failed to get function address.", KERROR);
        return false;
    }

    WCHAR wsAddsBuffer[55];

    ZeroMemory(wsAddsBuffer, 55 * sizeof(WCHAR));

    swprintf_s(wsAddsBuffer, L"RpcServerTestCancel's address: 0x%p", func);

    Log(hEdit, wsAddsBuffer, INFO);

    auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        Log(hEdit, L"Failed to create snapshot.", KERROR);
        return false;
    }

    PROCESSENTRY32W pe32 = { sizeof(PROCESSENTRY32W) };
    bool success = false;
    if (Process32FirstW(snapshot, &pe32)) {
        Log(hEdit, L"Scanning processes...", INFO);
        do {
            // 跳过系统空闲进程
            if (pe32.th32ProcessID <= 4u)
                continue;

            Log(hEdit, std::wstring(L"Found process: ") + pe32.szExeFile, INFO);
            if (!wcscmp(pe32.szExeFile, L"winlogon.exe")) {
                Log(hEdit, L"Target process found: winlogon.exe", INFO);
                WCHAR wszPID[25];
                swprintf_s(wszPID, L"Target PID: %u", pe32.th32ProcessID);
                Log(hEdit, wszPID, INFO);

                Log(hEdit, L"Attempting to open winlogon.exe process...", INFO);
                auto hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
                if (hProcess) {
                    Log(hEdit, L"Opened process handle successfully.", INFO);

                    Log(hEdit, L"Attempting to turn off memory protection...", INFO);
                    DWORD oldProtect;
                    if (VirtualProtectEx(hProcess, (void*)func, 0x5, PAGE_EXECUTE_READWRITE, &oldProtect))
                    {
                        Log(hEdit, L"Successfully turned off memory protection.", INFO);
                        
                        /*
                        *   在这里对函数返回值自身异或，将得到 NULL，返回值应该不为空，
                        *   如果为空，则表明连接的一方已终止。
                        *   其他终结点应该调用 RpcAsyncAbortCall 结束调用。
                        *     __________________________________________________
                        *    /                                                  \
                        *   |  Raw Hex:                                          |
                        *   |              33C0C3                                |
                        *   |                                                    |
                        *   |  String Literal:                                   |
                        *   |              "\x33\xC0\xC3"                        |
                        *   |                                                    |
                        *   |  Array Literal:                                    |
                        *   |              { 0x33, 0xC0, 0xC3 }                  |
                        *   |                                                    |
                        *   |  Disassembly:                                      |
                        *   |              0 : 33 c0           xor eax, eax      |
                        *   |              2 : c3              ret               |
                        *    \ ________________________________________________ /
                        */
                #ifdef _WIN32
                    #ifndef _WIN64
                        unsigned char buf[] = { 0x33, 0xc0, 0xc2, 0x04, 0 };   // x86-32 为 stdcall 希望被调用函数清理堆栈
                    #else
                        unsigned char buf[] = { 0x33, 0xc0, 0xc3 };
                    #endif
                #endif
                        if (enable) {
                            Log(hEdit, L"Attempting to write instruction bytes for patch...", INFO);
                            success = WriteProcessMemory(hProcess, (void*)func, buf, sizeof(buf), NULL);
                        }
                        else {
                            Log(hEdit, L"Attempting to recover instruction bytes...", INFO);
                            success = WriteProcessMemory(hProcess, (void*)func, (void*)func, sizeof(buf), NULL);
                        }

                        Log(hEdit, L"Attempting to turn on memory protection...", INFO);
                        VirtualProtectEx(hProcess, (void*)func, 0x5, oldProtect, &oldProtect);

                        if (success) {
                            Log(hEdit, L"Memory written successfully.", INFO);
                        }
                        else {
                            Log(hEdit, L"Failed to write memory.", KERROR);
                        }
                    }
                    else {
                        success = false;
                        Log(hEdit, L"Failed to change memory protection.", KERROR);
                    }
                    CloseHandle(hProcess);
                    Log(hEdit, L"Closed process handle.", INFO);
                }
                else {
                    success = false;
                    Log(hEdit, L"Failed to open process.", KERROR);
                }
                break;
            }
        } while (Process32NextW(snapshot, &pe32));
    }
    else {
        Log(hEdit, L"Failed to retrieve first process.", KERROR);
    }

    CloseHandle(snapshot);
    return success;
}

HBITMAP CreateBitmapFromIcon(HICON hIcon, int width, int height) {
    HDC hdcScreen = GetDC(NULL);
    HDC hdcMem = CreateCompatibleDC(hdcScreen);

    // Create a bitmap with an alpha channel
    BITMAPINFO bmi = { 0 };
    bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bmi.bmiHeader.biWidth = width;
    bmi.bmiHeader.biHeight = -height; // Negative height to create a top-down DIB
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biBitCount = 32;
    bmi.bmiHeader.biCompression = BI_RGB;
    void* pBits = NULL;
    HBITMAP hBitmap = CreateDIBSection(hdcScreen, &bmi, DIB_RGB_COLORS, &pBits, NULL, 0);

    if (hBitmap)
    {
        HBITMAP hOldBitmap = (HBITMAP)SelectObject(hdcMem, hBitmap);

        // Fill background with transparent color
        BLENDFUNCTION bf = { AC_SRC_OVER, 0, 255, AC_SRC_ALPHA };
        GdiAlphaBlend(hdcMem, 0, 0, width, height, hdcMem, 0, 0, width, height, bf);

        // Draw icon onto the bitmap
        DrawIconEx(hdcMem, 0, 0, hIcon, width, height, 0, NULL, DI_NORMAL);

        SelectObject(hdcMem, hOldBitmap);
        DeleteDC(hdcMem);
        ReleaseDC(NULL, hdcScreen);
        //DeleteObject(hBitmap);
    }
    return hBitmap;
}


BOOL SetCurrentProcessVolume(DWORD dwVolume, BOOL IsMixer/*TRUE*/)
{
    HRESULT hr = S_OK;
    IMMDeviceCollection* pMultiDevice = NULL;
    IMMDevice* pDevice = NULL;
    IAudioSessionEnumerator* pSessionEnum = NULL;
    IAudioSessionManager2* pASManager = NULL;
    IMMDeviceEnumerator* m_pEnumerator = NULL;
    const IID IID_ISimpleAudioVolume = __uuidof(ISimpleAudioVolume);
    const IID IID_IAudioSessionControl2 = __uuidof(IAudioSessionControl2);

    CoInitialize(NULL);
    hr = CoCreateGuid(&m_guidMyContext);
    if (FAILED(hr))
        return FALSE;
    // Get enumerator for audio endpoint devices.
    hr = CoCreateInstance(__uuidof(MMDeviceEnumerator),
        NULL, CLSCTX_ALL,
        __uuidof(IMMDeviceEnumerator),
        (void**)&m_pEnumerator);
    if (FAILED(hr))
        return FALSE;

    if (IsMixer)
    {
        hr = m_pEnumerator->EnumAudioEndpoints(eRender, DEVICE_STATE_ACTIVE, &pMultiDevice);
    }
    else
    {
        hr = m_pEnumerator->EnumAudioEndpoints(eCapture, DEVICE_STATE_ACTIVE, &pMultiDevice);
    }
    if (FAILED(hr))
        return FALSE;

    UINT deviceCount = 0;
    hr = pMultiDevice->GetCount(&deviceCount);
    if (FAILED(hr))
        return FALSE;

    if ((int)dwVolume < 10)
        dwVolume = 10;
    if ((int)dwVolume > 100)
        dwVolume = 100;
    for (UINT ii = 0; ii < deviceCount; ii++)
    {
        pDevice = NULL;
        hr = pMultiDevice->Item(ii, &pDevice);
        if (FAILED(hr))
            return FALSE;
        hr = pDevice->Activate(__uuidof(IAudioSessionManager), CLSCTX_ALL, NULL, (void**)&pASManager);

        if (FAILED(hr))
            return FALSE;
        hr = pASManager->GetSessionEnumerator(&pSessionEnum);
        if (FAILED(hr))
            return FALSE;
        int nCount;
        hr = pSessionEnum->GetCount(&nCount);
        for (int i = 0; i < nCount; i++)
        {
            IAudioSessionControl* pSessionCtrl;
            hr = pSessionEnum->GetSession(i, &pSessionCtrl);
            if (FAILED(hr))
                continue;
            IAudioSessionControl2* pSessionCtrl2 = nullptr;
            hr = pSessionCtrl->QueryInterface(IID_IAudioSessionControl2, (void**)&pSessionCtrl2);
            if (FAILED(hr))
                continue;
            ULONG pid;
            hr = pSessionCtrl2->GetProcessId(&pid);
            if (FAILED(hr))
                continue;

            ISimpleAudioVolume* pSimplevol = nullptr;
            hr = pSessionCtrl2->QueryInterface(IID_ISimpleAudioVolume, (void**)&pSimplevol);
            if (FAILED(hr))
                continue;
            if (pid == GetCurrentProcessId())
            {
                pSimplevol->SetMasterVolume((float)dwVolume / 100, NULL);
            }
            /*else
            {
                pSimplevol->SetMasterVolume((float)0 / 100, NULL);
            }*/

        }
    }
    m_pEnumerator->Release();
    return TRUE;
}

// 读取配置文件获取是否播放的签名
void getMusicCodeFromConfig(int *MusicCode, int *MusicVolume) {
    rr::RrConfig config;
    bool ret = config.ReadConfig("config.txt");
    if (ret == false) {
        OutputDebugStringW(L"ReadConfig is Error,Cfg=config.txt");
        return;
    }
    int lpdwIllegal = 0;
    *MusicCode = config.ReadIntEx("WMsgInterceptor", "MusicCode", 0, lpdwIllegal);
    *MusicVolume = config.ReadIntEx("WMsgInterceptor", "MusicVolume", 50, lpdwIllegal);
}

// 播放背景音乐函数
void PlayBackgroundMusic()
{
    int MusicCode = 0;
    int MusicVolume = 0;

    getMusicCodeFromConfig(&MusicCode, &MusicVolume);

    if (MusicCode != 0x32769452)
    {
        // 从资源中加载并播放音频
        PlaySoundW(MAKEINTRESOURCE(IDR_WAVE1),
            GetModuleHandleW(NULL),
            SND_RESOURCE | SND_ASYNC | SND_LOOP);
        Sleep(500);
        SetCurrentProcessVolume(MusicVolume, TRUE);
    }
}

HRESULT MySetThreadDescription(HANDLE hThread, PCWSTR lpThreadDescription) {
    if (!lpThreadDescription) {
        return E_POINTER; // Null pointer passed
    }

    std::lock_guard<std::mutex> lock(g_ThreadDescriptionsMutex);
    try {
        g_ThreadDescriptions[hThread] = lpThreadDescription;
    }
    catch (const std::exception& e) {
        Log(hRichEdit, L"SetThreadDescription Exception: "
            + std::wstring(e.what(), e.what() + strlen(e.what())) + L"\n", KERROR);
        return HRESULT_FROM_WIN32(ERROR_UNHANDLED_EXCEPTION); // Catch all exceptions and convert to HRESULT
    }
    return S_OK;  // Success
}

HRESULT MyGetThreadDescription(HANDLE hThread, PWSTR* ppszThreadDescription) {
    if (!ppszThreadDescription) {
        return E_POINTER; // Null pointer passed
    }

    std::lock_guard<std::mutex> lock(g_ThreadDescriptionsMutex);
    auto it = g_ThreadDescriptions.find(hThread);
    if (it != g_ThreadDescriptions.end()) {
        // Allocate memory for the thread description
        size_t len = (it->second.length() + 1) * sizeof(wchar_t);
        *ppszThreadDescription = static_cast<PWSTR>(CoTaskMemAlloc(len));
        if (*ppszThreadDescription) {
            wcscpy_s(*ppszThreadDescription, len / sizeof(wchar_t), it->second.c_str());
            return S_OK;  // Success
        }
        else {
            return E_OUTOFMEMORY;  // Memory allocation failed
        }
    }
    else {
        return HRESULT_FROM_WIN32(ERROR_NOT_FOUND);  // Thread not found
    }
}

void MyFreeThreadDescription(PWSTR pszThreadDescription) {
    if (pszThreadDescription) {
        CoTaskMemFree(pszThreadDescription);
    }
}

