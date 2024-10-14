// WinlogonMessageFilter.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <stdio.h>
#include <Windows.h>
#include <Tlhelp32.h>
#include <Shlwapi.h>
#include <new>
#include <locale.h>
#include <Psapi.h>
#include <vector>

#pragma comment(lib, "Shlwapi.lib")
#define HOOK_MODULE_NAME L"WMsgKMsgHookCore.dll"
#define WINLOGON_NAME    L"winlogon.exe"

typedef struct HANDLER_INFO_STRUCT
{
    DWORD  cbSize = 0;
    DWORD  dwMainThread = 0;
    HMODULE hHookModule = nullptr;
    LPVOID lpHookHandler = nullptr;
    LPVOID lpUnhookHandler = nullptr;
    LPVOID lpSafeFreeLib = nullptr;
    LPVOID lpWinlogonBase = nullptr;
    LPVOID lpHookAddress = nullptr;
    
}HANDLER_INFO_STRUCT, * LPHANDLER_INFO_STRUCT;


typedef BOOL(WINAPI* __GetHandlerAddress)(LPHANDLER_INFO_STRUCT lpHandlerInfo);
typedef BOOL(WINAPI* __SetBaseAddress)(DWORD lpBaseOffest);

BOOL IsFileExist(LPCWSTR wsFileFullPath);
FARPROC WINAPI MyGetProcAddress64(PVOID lpBaseAddress, LPCSTR FunName);
BOOL    WINAPI InjectMouldeHandler(HANDLE hProcess, LPCWSTR pszDllFileName);
BOOL    WINAPI SafeCloseHandle(HANDLE handle);
DWORD   WINAPI GetActiveConsoleSessionId();
BOOL    WINAPI IsProcessInSession(DWORD processId, DWORD sessionId);
DWORD   WINAPI FindWinlogonProcessId();
BOOL    WINAPI CheckProcessHasLoadModule(DWORD dwProcessId, LPCWSTR wsFileName);
BOOL    WINAPI IsRunAsAdministrator();
BOOL    WINAPI ElevateCurrentProcess(LPCWSTR wsFilePath);
BOOL    WINAPI EnableDebugPrivilege();
BOOL    WINAPI RemoteHookingHandler(HANDLE hProcess, PVOID lpProcAddress, LPVOID lpParameter);
DWORD WINAPI BFTracePatternInModule(
    LPCWSTR moduleName, PBYTE pattern, DWORD patternSize, DWORD dwRepeat);


// ETW Trace 特征码 2
BYTE   pattern2[] =
{
    0x48u, 0x8Du, 0x05u, 0, 0, 0, 0, 0x48u, 0x89u, 0x44u, 0x24u , 0
};


void SetConsoleCodePageToUTF8() {
    _wsetlocale(LC_ALL, L"zh-CN");
}

BOOL GetExecutablePath(
    PWCHAR* binPathBuffer,
    DWORD& bufferLen) {

    while (true) {
        SetLastError(0);
        DWORD dwwcharLen = bufferLen * sizeof(WCHAR) + sizeof(WCHAR);
        *binPathBuffer = new WCHAR[dwwcharLen];
        if (*binPathBuffer == nullptr) {
            printf("Error Alloc Memory for search.\n");
            SetLastError(ERROR_OUTOFMEMORY);
            return FALSE;
        }

        DWORD exePathLen = GetModuleFileNameW(nullptr, *binPathBuffer, bufferLen);

        if (exePathLen == 0) {
            printf("Error Get Module File Name.\n");
            return FALSE;
        }

        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
            break;
        delete[] * binPathBuffer;
        bufferLen += 10;
    }
    return TRUE;
}

BOOL InjectModuleToWinlogon(const WCHAR* fullModulePath, HANDLE hWinlogonProc) {

    if (TRUE == InjectMouldeHandler(hWinlogonProc, fullModulePath)) {
        printf("Inject Module to winlogon SUCCESSFULLY.\n");
        return TRUE;
    }
    else {
        printf("Inject Module to winlogon Failed.\n");
        return FALSE;
    }
}

BOOL LoadHookCoreAndGetSymbols(
    const WCHAR* fullDllPath,
    HANDLER_INFO_STRUCT& lpHandleInfo,
    DWORD& dwHookBaseOffest
) {
    HMODULE hHookCore = LoadLibraryW(fullDllPath);
    if (hHookCore == NULL) {
        printf("Error[%d]: Failed in Loading Library.\n", GetLastError());
        return FALSE;
    }

    FARPROC pFunGetHandler = MyGetProcAddress64(hHookCore, "GetHandlerAddress");
    FARPROC pFunSetBaseAddr = MyGetProcAddress64(hHookCore, "RemoteSetHookBaseAddress");

    if (pFunGetHandler == NULL || pFunSetBaseAddr == NULL) {
        printf("Error[%d]: Failed in Loading Library.\n", GetLastError());
        FreeLibrary(hHookCore);
        return FALSE;
    }

    __GetHandlerAddress GetHandlerAddress = (__GetHandlerAddress)pFunGetHandler;
    __SetBaseAddress RemoteSetHookBaseAddress = (__SetBaseAddress)pFunSetBaseAddr;

    WCHAR  SystemDirtory[MAX_PATH] = { 0 };
    WCHAR  winlogonPath[500] = { 0 };
    GetSystemDirectoryW(SystemDirtory, sizeof(SystemDirtory) / sizeof(TCHAR));
    swprintf_s(winlogonPath, sizeof(winlogonPath) / sizeof(TCHAR),
        L"%s\\%s", SystemDirtory, WINLOGON_NAME);

    lpHandleInfo.cbSize = sizeof(HANDLER_INFO_STRUCT);
    if (!GetHandlerAddress(&lpHandleInfo)) {
        printf("Error: Failed GetHandlerAddressInfo.\n");
        FreeLibrary(hHookCore);
        return FALSE;
    }

    dwHookBaseOffest = BFTracePatternInModule(winlogonPath, pattern2, 12, 3);

    printf("dwHookBaseOffest: 0x%X\n", dwHookBaseOffest);
    //system("pause");

    if (dwHookBaseOffest == 0) {
        printf("Error: Failed to Search Special FunctionAddress.\n");
        FreeLibrary(hHookCore);
        return FALSE;
    }

    if (!RemoteSetHookBaseAddress(dwHookBaseOffest)) {
        printf("Error[%d]: Failed to SetHookBaseAddress.\n", GetLastError());
        FreeLibrary(hHookCore);
        return FALSE;
    }

    wprintf(L"lpHookHandler: [0x%I64X], lpUnhookHandler: [0x%I64X], lpHook: [0x%I64X].\n",
        reinterpret_cast<uint64_t>(lpHandleInfo.lpHookHandler),
        reinterpret_cast<uint64_t>(lpHandleInfo.lpUnhookHandler),
        reinterpret_cast<uint64_t>(lpHandleInfo.lpHookAddress));

    return TRUE;
}

void RunHookingAndCleanup(HANDLE hWinlogonProc, const HANDLER_INFO_STRUCT& lpHandleInfo) {
    printf("\n\t> Press any key to enable hooks.\n");
    getchar();
    if (TRUE == RemoteHookingHandler(hWinlogonProc, lpHandleInfo.lpHookHandler, NULL)) {
        printf("Enable Hooks in winlogon SUCCESSFULLY.\n");
    }
    else {
        RemoteHookingHandler(hWinlogonProc, lpHandleInfo.lpSafeFreeLib, NULL);
        return;
    }
    printf("\n\t> Press any key to disable hooks.\n");
    getchar();
    if (TRUE == RemoteHookingHandler(hWinlogonProc, lpHandleInfo.lpUnhookHandler, NULL)) {
        printf("Disable Hooks in winlogon SUCCESSFULLY.\n");
    }
    printf("\n\t> Press any key to uninstall module.\n");
    getchar();
    if (TRUE == RemoteHookingHandler(hWinlogonProc, lpHandleInfo.lpSafeFreeLib, NULL)) {
        printf("UnLoadLibrary in winlogon SUCCESSFULLY.\n");
    }
    SafeCloseHandle(hWinlogonProc);
}

BOOL RunAsAdministratorHandler(LPCWSTR lpBinPathName) {
    // 检查是否以管理员权限运行
    if (IsRunAsAdministrator() == FALSE)
    {
        printf("Error require Administrator Token.\n");
        // 尝试动态提权
        if (!ElevateCurrentProcess(lpBinPathName))
        {
            printf("Failed Auto-Elevate.\n");
            return FALSE;
        }
        else {  // 退出进程
            exit(0);
        }
    }

    // 启用管理员令牌
    if (!EnableDebugPrivilege())
    {
        printf("Failed to Enable Debug Priviledge.\n");
        return FALSE;
    }
    return TRUE;
}

// 主函数
int main() {
    SetConsoleCodePageToUTF8();

    //WCHAR binPathBuffer = L'\0';
    PWCHAR lpbinPathBuffer = 0;
    DWORD bufferLen = MAX_PATH;
    if (!GetExecutablePath(&lpbinPathBuffer, bufferLen))
        return -1;

    if (!RunAsAdministratorHandler(lpbinPathBuffer))
    {
        delete[] lpbinPathBuffer;
        return -1;
    }

    // 删除程序文件名部分
    if (PathRemoveFileSpecW(lpbinPathBuffer) == 0)
    {
        delete[] lpbinPathBuffer;
        printf("Error Remove File Spec.\n");
        return -1;
    }

    printf("Current WorkingDirectury: %ws.\n", lpbinPathBuffer);

    WCHAR fullDllPath[MAX_PATH] = { 0 };
    swprintf_s(fullDllPath, MAX_PATH, L"%s\\%s", lpbinPathBuffer, HOOK_MODULE_NAME);

    if (!IsFileExist(fullDllPath)) {
        printf("Error: Module file [%ws] does not exist or is damaged.\n", HOOK_MODULE_NAME);
        return -1;
    }

    DWORD dwWinlogonId = FindWinlogonProcessId();
    printf("CurrentSession winlogon PID: %d.\n", dwWinlogonId);

    if (CheckProcessHasLoadModule(dwWinlogonId, HOOK_MODULE_NAME))
    {
        printf("Error: Process already Loaded module.\n");
        return -1;
    }

    HANDLE hWinlogonProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwWinlogonId);
    if (hWinlogonProc == nullptr) {
        delete[] lpbinPathBuffer;
        printf("Error OpenProcess(PID: %d, error: %d)\n", dwWinlogonId, GetLastError());
        return -1;
    }

    if (!InjectModuleToWinlogon(fullDllPath, hWinlogonProc))
    {
        delete[] lpbinPathBuffer;
        SafeCloseHandle(hWinlogonProc);
        return -1;
    }

    HANDLER_INFO_STRUCT lpHandleInfo = { 0 };
    __try {
        DWORD dwHookBaseOffest = 0;
        if (!LoadHookCoreAndGetSymbols(fullDllPath, lpHandleInfo, dwHookBaseOffest))
        {
            throw(EXCEPTION_EXECUTE_HANDLER);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {

        printf("LoadHookCoreAndGetSymbols failed.\n");
        // 清理注入的模块
        RemoteHookingHandler(hWinlogonProc, lpHandleInfo.lpSafeFreeLib, NULL);
        delete[] lpbinPathBuffer;
        SafeCloseHandle(hWinlogonProc);
        return -1;
    }

    // 测试样例
    RunHookingAndCleanup(hWinlogonProc, lpHandleInfo);

    system("pause");
    return 0;
}


BOOL IsFileExist(LPCWSTR wsFileFullPath)
{
    DWORD dwAttrib = GetFileAttributesW(wsFileFullPath);
    return INVALID_FILE_ATTRIBUTES != dwAttrib && 0 == (dwAttrib & FILE_ATTRIBUTE_DIRECTORY);
}

// 通过 lea 传地址指令计算函数的实际偏移
DWORD GetLeaFuncOffest(LPVOID lpBaseAddress, DWORD lpStartOffest) {
    // 从给定地址处读取偏移量数值
    int32_t offset = 0;
    ReadProcessMemory(GetCurrentProcess(), 
        reinterpret_cast<LPCVOID>(
            reinterpret_cast<uintptr_t>(lpBaseAddress) + lpStartOffest + 3 ),
        &offset, sizeof(offset), nullptr);

    // 计算函数偏移
    return lpStartOffest + 7 + offset; // x64 lea 寄存器操作数指令长度为 7 字节
}

DWORD WINAPI BFTracePatternInModule(
    LPCWSTR moduleName,
    PBYTE pattern,
    DWORD patternSize,
    DWORD dwRepeat
)
{
    if (pattern == 0 || moduleName == 0 || patternSize == 0 || dwRepeat < 1)
    {
        return 0;
    }

    HMODULE hModule = LoadLibraryW(moduleName);
    if (hModule == nullptr) {
        printf("Failed to load module: %ws.\n", moduleName);
        return 0;
    }

    MODULEINFO moduleInfo;
    if (!GetModuleInformation(GetCurrentProcess(), hModule, &moduleInfo, sizeof(moduleInfo))) {
        printf("Failed to get module information.\n");
        FreeLibrary(hModule);
        return 0;
    }

    
    BYTE* moduleBase = reinterpret_cast<BYTE*>(hModule);
    SIZE_T moduleSize = moduleInfo.SizeOfImage;

    printf("模块基址：%I64X.\n", reinterpret_cast<uint64_t>(hModule));
    printf("模块大小：%I64d Bytes.\n", moduleSize);


    if (moduleSize == 0)
    {
        printf("Failed to get module information.\n");
        FreeLibrary(hModule);
        return 0;
    }

    std::vector<DWORD> vcWMsgFuncTable;
    DWORD vcMachOffest = 0; // 用于记录查找的特征码偏移
    DWORD MatchLimit = patternSize * dwRepeat;  // 连续重复匹配次数限制

    for (DWORD idx_out = 0; idx_out < moduleSize - MatchLimit; idx_out++)
    {
        DWORD idx_ier = 0;
        for (idx_ier; idx_ier < MatchLimit - 1; idx_ier++)
        {
            if (moduleBase[idx_out + idx_ier] != pattern[idx_ier % patternSize]
                && pattern[idx_ier % patternSize] != 0u)
            {
                break;
            }
        }

        if (idx_ier == MatchLimit - 1) {
            if (moduleBase[idx_out + idx_ier] == pattern[patternSize - 1]
                || pattern[patternSize - 1] == 0u)
            {
                vcMachOffest = idx_out;
                break;
            }
        }
    }

    if (vcMachOffest == 0) {
        printf("找不到模式字符串！\n");
        return NULL;
    }

    printf("匹配到模式字符串位于偏移: [0x%X] 处，动态地址：[0x%I64X]。\n",
        vcMachOffest, reinterpret_cast<uint64_t>(moduleBase) + vcMachOffest);

    DWORD tmpOffest = 0;
    for (UINT i = 0; i < 2; i++)
    {
        tmpOffest = 0;
        tmpOffest = GetLeaFuncOffest(moduleBase, vcMachOffest + 0xc * i);

        vcWMsgFuncTable.push_back(tmpOffest);
        printf("第 %d 个函数实际地址：[0x%0I64X]。\n",
            i, reinterpret_cast<uint64_t>(moduleBase) + tmpOffest);
    }

    FreeLibrary(hModule);
    return vcWMsgFuncTable[1];
}

BOOL WINAPI SafeCloseHandle(HANDLE handle)
{
    BOOL bResponse = TRUE;
    if (handle != nullptr) {
        bResponse = CloseHandle(handle);
        handle = nullptr;
    }
    return bResponse;
}


BOOL WINAPI IsRunAsAdministrator() // 判断是否以管理员身份运行
{
    BOOL bIsElevated = FALSE;
    HANDLE hToken = NULL;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {

        TOKEN_ELEVATION te = { 0 };
        DWORD dwReturnLength = 0;

        if (GetTokenInformation(hToken, TokenElevation,
            &te, sizeof(te), &dwReturnLength))
        {
            if (dwReturnLength == sizeof(te))
                bIsElevated = te.TokenIsElevated;
        }
        SafeCloseHandle(hToken);
    }
    return bIsElevated;
}

BOOL WINAPI ElevateCurrentProcess(LPCWSTR wsFilePath)
{
    TCHAR szPath[MAX_PATH] = { 0 };

    if (GetModuleFileNameW(NULL, szPath, MAX_PATH) != 0)
    {
        // Launch itself as administrator.
        SHELLEXECUTEINFO sei = { 0 };
        sei.cbSize = sizeof(SHELLEXECUTEINFO);
        sei.lpVerb = L"runas";
        sei.lpFile = szPath;
        sei.lpParameters = (LPCTSTR)wsFilePath;
        sei.nShow = SW_SHOWNORMAL;

        if (!ShellExecuteEx(&sei))
        {
            DWORD dwStatus = GetLastError();
            if (dwStatus == ERROR_CANCELLED)
            {
                // The user refused to allow privileges elevation.
                printf("The user refused to allow privileges elevation.\n");
                return FALSE;
            }
            else if (dwStatus == ERROR_FILE_NOT_FOUND)
            {
                // The file defined by lpFile was not found and
                // an error message popped up.
                printf("Error Cannot Access Files.\n");
                return FALSE;
            }
            return FALSE;
        }
        return TRUE;
    }
    return FALSE;
}

BOOL WINAPI EnableDebugPrivilege()
{
    HANDLE handleToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &handleToken))
    {
        printf("Error OpenProcessToken.\n");
        return FALSE;
    }

    LUID debugNameValue = { 0 };
    if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &debugNameValue))
    {
        SafeCloseHandle(handleToken);
        printf("Error LookupPrivilegeValue.\n");
        return FALSE;
    }
    TOKEN_PRIVILEGES tokenPri = { 0 };
    tokenPri.PrivilegeCount = 1;
    tokenPri.Privileges[0].Luid = debugNameValue;
    tokenPri.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(handleToken,
        FALSE, &tokenPri, sizeof(tokenPri), nullptr, nullptr))
    {
        SafeCloseHandle(handleToken);
        printf("Error AdjustTokenPrivileges.\n");
        return FALSE;
    }
    SafeCloseHandle(handleToken);
    return TRUE;
}


DWORD WINAPI GetActiveConsoleSessionId() {
    return WTSGetActiveConsoleSessionId();
}


BOOL WINAPI IsProcessInSession(DWORD processId, DWORD sessionId) {
    DWORD session;
    if (!ProcessIdToSessionId(processId, &session)) {
        printf("Error: ProcessIdToSessionId failed.\n");
        return FALSE;
    }
    return session == sessionId;
}


DWORD WINAPI FindWinlogonProcessId() {
    DWORD dwProcessId = 0;
    DWORD activeSessionId = GetActiveConsoleSessionId();
    if (activeSessionId == 0xFFFFFFFF) {
        printf("Error: Unable to retrieve active console session ID.\n");
        return 0;
    }

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        printf("Error: CreateToolhelp32Snapshot failed.\n");
        return 0;
    }

    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(snapshot, &entry)) {
        printf("Error: Process32First failed.\n");
        SafeCloseHandle(snapshot);
        return 0;
    }

    do {

        if (entry.cntThreads <= 1u) continue; // 跳过僵尸进程

        if (_wcsicmp(entry.szExeFile, L"winlogon.exe") == 0) {
            if (IsProcessInSession(entry.th32ProcessID, activeSessionId)) {
                dwProcessId = entry.th32ProcessID;
                break;
            }
        }
    } while (Process32Next(snapshot, &entry));

    SafeCloseHandle(snapshot);
    return dwProcessId;
}


/// <summary>
/// MyGetProcAddress64 is a function to replace GetProcAddress for 64-bit
/// architecture, used to retrieve the entry address of a function within a module.
/// </summary>
/// <param name="lpBaseAddress">The base address of the module.</param>
/// <param name="FunName">The name of the function to retrieve.</param>
/// <returns>The entry address of the function if found, or 0 if not found.</returns>
FARPROC WINAPI MyGetProcAddress64(PVOID lpBaseAddress, LPCSTR FunName) {
    if (lpBaseAddress == nullptr || FunName == nullptr) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }

    __try {
        // Get DOS header
        PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(lpBaseAddress);
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            SetLastError(ERROR_IMAGE_MACHINE_TYPE_MISMATCH);
            return 0;
        }

        // Get NT header
        PIMAGE_NT_HEADERS ntHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(
            (reinterpret_cast<BYTE*>(lpBaseAddress)) + dosHeader->e_lfanew);
        if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
            SetLastError(ERROR_IMAGE_MACHINE_TYPE_MISMATCH);
            return 0;
        }

        // Get export directory
        PIMAGE_EXPORT_DIRECTORY exports =
            reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>((reinterpret_cast<BYTE*>(lpBaseAddress))
                + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

        // Get export tables
        DWORD* nameTable = reinterpret_cast<DWORD*>(
            (reinterpret_cast<BYTE*>(lpBaseAddress)) + exports->AddressOfNames);
        DWORD* addressTable = reinterpret_cast<DWORD*>(
            (reinterpret_cast<BYTE*>(lpBaseAddress)) + exports->AddressOfFunctions);
        WORD* ordinalTable = reinterpret_cast<WORD*>(
            (reinterpret_cast<BYTE*>(lpBaseAddress)) + exports->AddressOfNameOrdinals);

        // Linear search in export table
        for (DWORD i = 0; i < exports->NumberOfNames; i++) {
            PCHAR pFuncName = reinterpret_cast<PCHAR>(
                (reinterpret_cast<BYTE*>(lpBaseAddress)) + nameTable[i]);

            if (pFuncName != nullptr) {
                // Copy function name and ensure null-termination
                size_t strLength = strnlen_s(pFuncName, MAX_PATH);
                char* buffer = new (std::nothrow) char[strLength + 1];
                if (buffer != nullptr) {
                    memcpy_s(buffer, strLength + 1, pFuncName, strLength);
                    buffer[strLength] = '\0';

                    // Compare function names
                    int compareResult = _stricmp(buffer, FunName);

                    delete[] buffer; // Free allocated memory
                    if (compareResult == 0) {
                        // Function name found, return function address
                        DWORD functionRVA = addressTable[ordinalTable[i]];
                        FARPROC pfunAddress = reinterpret_cast<FARPROC>(
                            reinterpret_cast<UINT64>(lpBaseAddress) + functionRVA);
                        SetLastError(0);
                        return pfunAddress;
                    }
                }
                else {
                    printf("Error out of memory.\n");
                    SetLastError(ERROR_OUTOFMEMORY);
                    return 0;
                }
            }
            else {
                printf("Error GetFunctionNameTable.\n");
                SetLastError(ERROR_ACCESS_DENIED);
                return 0;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        printf("Exception occurred while accessing memory.\n");
        SetLastError(ERROR_ACCESS_DENIED);
        return 0;
    }

    // Function not found
    SetLastError(ERROR_PROC_NOT_FOUND);
    return 0;
}

BOOL WINAPI CheckProcessHasLoadModule(DWORD dwProcessId, LPCWSTR wsFileName) {

    /*
    * 参数为TH32CS_SNAPMODULE 或 TH32CS_SNAPMODULE32时,
    * 如果函数失败并返回ERROR_BAD_LENGTH，则重试该函数直至成功
    * 进程创建未初始化完成时，CreateToolhelp32Snapshot会返回error 299，但其它情况下不会。
    */

    HANDLE hSnapshot = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE |
        TH32CS_SNAPMODULE32,
        dwProcessId);
    while (INVALID_HANDLE_VALUE == hSnapshot) {
        DWORD dwError = GetLastError();
        if (dwError == ERROR_BAD_LENGTH) {
            hSnapshot = CreateToolhelp32Snapshot(
                TH32CS_SNAPMODULE |
                TH32CS_SNAPMODULE32,
                dwProcessId);
            continue;
        }
        else {
            printf("CreateToolhelp32Snapshot failed: %d, targetProcessId:%d.\n",
                dwError, dwProcessId);
            return FALSE;
        }
    }

    MODULEENTRY32W mi = { 0 };
    mi.dwSize = sizeof(MODULEENTRY32W); // 第一次使用必须初始化成员
    BOOL bRet = Module32FirstW(hSnapshot, &mi);
    while (bRet) {
        // mi.szModule 是短路径
        if (wcsstr(wsFileName, mi.szModule) ||
            wcsstr(mi.szModule, wsFileName)) {
            if (hSnapshot != NULL) CloseHandle(hSnapshot);
            return TRUE;
        }
        mi.dwSize = sizeof(MODULEENTRY32W);
        bRet = Module32NextW(hSnapshot, &mi);
    }
    if (hSnapshot != NULL) SafeCloseHandle(hSnapshot);
    return FALSE;
}

BOOL WINAPI InjectMouldeHandler(
    HANDLE hProcess,
    LPCWSTR pszDllFileName
)
{
    // 1.目标进程句柄
    if (hProcess == nullptr || pszDllFileName == nullptr)
    {
        wprintf(L"Error: InvalidSyntax error from InjectMouldeHandler.\n");
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    size_t pathSize = (wcslen(pszDllFileName) + 1) * sizeof(wchar_t);

    SetLastError(0);
    // 2.在目标进程中申请空间
    LPVOID lpPathAddr = VirtualAllocEx(hProcess, 0, pathSize,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (lpPathAddr == nullptr)
    {
        wprintf(L"Error[%d]: Failed to apply memory in the target process!\n", GetLastError());
        return FALSE;
    }

    SetLastError(0);
    // 3.在目标进程中写入 Dll 路径
    if (FALSE == WriteProcessMemory(hProcess, lpPathAddr,
        pszDllFileName, pathSize, NULL))
    {
        wprintf(L"Error[%d]: Failed to write module path in target process!\n", GetLastError());
        return FALSE;
    }

    SetLastError(0);
    // 4.加载 ntdll.dll
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll == nullptr)
    {
        wprintf(L"Error[%d]: Failed to load NTDLL.DLL!\n", GetLastError());
        VirtualFreeEx(hProcess, lpPathAddr, 0, MEM_RELEASE);
        return FALSE;
    }

    SetLastError(0);
    // 5.获取 LoadLibraryW 的函数地址, FARPROC 可以自适应 32 位与 64 位
    FARPROC pFuncProcAddr = MyGetProcAddress64(GetModuleHandleW(L"kernel32.dll"),
        "LoadLibraryW");
    if (pFuncProcAddr == nullptr)
    {
        wprintf(L"Error[%d]: Failed to obtain the address of the LoadLibrary function!\n",
            GetLastError());
        VirtualFreeEx(hProcess, lpPathAddr, 0, MEM_RELEASE);
        return FALSE;
    }

    // 6.获取 NtCreateThreadEx 函数地址,该函数在32位与64位下原型不同
    // _WIN64 用来判断编译环境 ，_WIN32用来判断是否是 Windows 系统
#ifdef _WIN64
    typedef DWORD(WINAPI* __NtCreateThreadEx)(
        PHANDLE ThreadHandle,
        ACCESS_MASK DesiredAccess,
        LPVOID ObjectAttributes,
        HANDLE ProcessHandle,
        LPTHREAD_START_ROUTINE lpStartAddress,
        LPVOID lpParameter,
        ULONG CreateThreadFlags,
        SIZE_T ZeroBits,
        SIZE_T StackSize,
        SIZE_T MaximumStackSize,
        LPVOID pUnkown
        );
#else
    typedef DWORD(WINAPI* __NtCreateThreadEx)(
        PHANDLE ThreadHandle,
        ACCESS_MASK DesiredAccess,
        LPVOID ObjectAttributes,
        HANDLE ProcessHandle,
        LPTHREAD_START_ROUTINE lpStartAddress,
        LPVOID lpParameter,
        BOOL CreateSuspended,
        DWORD dwStackSize,
        DWORD dw1,
        DWORD dw2,
        LPVOID pUnkown
        );
#endif

    SetLastError(0);
    __NtCreateThreadEx NtCreateThreadEx =
        (__NtCreateThreadEx)MyGetProcAddress64(hNtdll, "NtCreateThreadEx");
    if (NtCreateThreadEx == nullptr)
    {
        wprintf(L"Error[%d]: Failed to obtain NtCreateThreadEx function address!\n",
            GetLastError());
        VirtualFreeEx(hProcess, lpPathAddr, 0, MEM_RELEASE);
        return FALSE;
    }

    SetLastError(0);
    // 7.在目标进程中创建远线程
    HANDLE hRemoteThread = NULL;
    DWORD lpExitCode = 0;
    DWORD dwStatus = NtCreateThreadEx(&hRemoteThread, PROCESS_ALL_ACCESS, NULL,
        hProcess,
        (LPTHREAD_START_ROUTINE)pFuncProcAddr, lpPathAddr, 0, 0, 0, 0, NULL);
    if (hRemoteThread == nullptr)
    {
        wprintf(L"Error[%d]: Failed to create thread in target process!\n", GetLastError());
        VirtualFreeEx(hProcess, lpPathAddr, 0, MEM_RELEASE);
        return FALSE;
    }

    SetLastError(0);
    // 8.等待线程结束
    if (WAIT_TIMEOUT == WaitForSingleObject(hRemoteThread, 2000))
    {
        wprintf(L"Error[%d]: Remote thread not responding.\n", GetLastError());
        VirtualFreeEx(hProcess, lpPathAddr, 0, MEM_RELEASE);
        return FALSE;
    }

    GetExitCodeThread(hRemoteThread, &lpExitCode);
    if (lpExitCode == 0)
    {
        wprintf(L"Error: Injection module failed in the target process.\n");
        VirtualFreeEx(hProcess, lpPathAddr, 0, MEM_RELEASE);
        return FALSE;
    }

    // 9.清理环境
    VirtualFreeEx(hProcess, lpPathAddr, 0, MEM_RELEASE);
    SafeCloseHandle(hRemoteThread);
    return TRUE;
}

BOOL WINAPI RemoteHookingHandler(
    HANDLE hProcess,
    PVOID  lpProcAddress,
    LPVOID lpParameter
)
{
    // 1.目标进程句柄
    if (hProcess == nullptr || lpProcAddress == nullptr)
    {
        wprintf(L"Error: InvalidSyntax error from RemoteHookingHandler.\n");
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    SetLastError(0);
    // 4.加载 ntdll.dll
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll == nullptr)
    {
        wprintf(L"Error[%d]: Failed to load NTDLL.DLL!\n", GetLastError());
        return FALSE;
    }

    // 6.获取 NtCreateThreadEx 函数地址,该函数在 32 位与 64 位下原型不同
    // _WIN64 用来判断编译环境 ，_WIN32用来判断是否是 Windows 系统
#ifdef _WIN64
    typedef DWORD(WINAPI* __NtCreateThreadEx)(
        PHANDLE ThreadHandle,
        ACCESS_MASK DesiredAccess,
        LPVOID ObjectAttributes,
        HANDLE ProcessHandle,
        LPTHREAD_START_ROUTINE lpStartAddress,
        LPVOID lpParameter,
        ULONG CreateThreadFlags,
        SIZE_T ZeroBits,
        SIZE_T StackSize,
        SIZE_T MaximumStackSize,
        LPVOID pUnkown
        );
#else
    typedef DWORD(WINAPI* __NtCreateThreadEx)(
        PHANDLE ThreadHandle,
        ACCESS_MASK DesiredAccess,
        LPVOID ObjectAttributes,
        HANDLE ProcessHandle,
        LPTHREAD_START_ROUTINE lpStartAddress,
        LPVOID lpParameter,
        BOOL CreateSuspended,
        DWORD dwStackSize,
        DWORD dw1,
        DWORD dw2,
        LPVOID pUnkown
        );
#endif

    SetLastError(0);
    __NtCreateThreadEx NtCreateThreadEx =
        (__NtCreateThreadEx)MyGetProcAddress64(hNtdll, "NtCreateThreadEx");
    if (NULL == NtCreateThreadEx)
    {
        wprintf(L"Error[%d]: Failed to obtain NtCreateThreadEx function address!\n",
            GetLastError());
        return FALSE;
    }

    SetLastError(0);
    // 7.在目标进程中创建远线程
    HANDLE hRemoteThread = NULL;
    DWORD lpExitCode = 0;
    DWORD dwStatus = NtCreateThreadEx(&hRemoteThread, PROCESS_ALL_ACCESS, NULL,
        hProcess, (LPTHREAD_START_ROUTINE)lpProcAddress, lpParameter, 0, 0, 0, 0, NULL);
    if (hRemoteThread == nullptr)
    {
        wprintf(L"Error[%d]: Failed to create thread in target process!\n", GetLastError());
        return FALSE;
    }

    SetLastError(0);
    // 8.等待线程结束
    if (WAIT_TIMEOUT == WaitForSingleObject(hRemoteThread, 15000))
    {
        wprintf(L"Error[%d]: Remote thread not responding.\n", GetLastError());
        return FALSE;
    }

    GetExitCodeThread(hRemoteThread, &lpExitCode);
    if (lpExitCode == 0)
    {
        wprintf(L"Error: Control HOOK routine failed in the target process.\n");
        return FALSE;
    }

    // 9.清理环境
    SafeCloseHandle(hRemoteThread);
    return TRUE;
}