

#include "pch.h"


#define HHOOK_FUNCCOUNT         2L
#define HOOK_MODULE_NAME        L"WMsgHookCore.dll"


typedef struct HHOOKFUNCTABLE {
    LPVOID pfn_WMsgKMsgHandler;
    LPVOID pfn_WMsgMsgHandler;
}HHOOKFUNCTABLE;

typedef struct HANDLER_INFO_STRUCT
{
    DWORD  cbSize = 0;
    DWORD  dwMainThread = 0;
    HMODULE hHookModule = nullptr;
    LPVOID lpHookHandler = nullptr;
    LPVOID lpUnhookHandler = nullptr;
    LPVOID lpSafeFreeLib = nullptr;
    LPVOID lpWinlogonBase = nullptr;
    HHOOKFUNCTABLE lpHookFuncTable;
}HANDLER_INFO_STRUCT, * LPHANDLER_INFO_STRUCT;


typedef int(__fastcall* __WMsgKMessageHandler)(
    unsigned int         uMachineState,
    unsigned int         uMsgWLGenericKey,
    PRPC_ASYNC_STATE     pAsync,
    LPDWORD              lpStatus   // int* pReserved
    );


typedef struct _LDR_PROTECT_STRUCT
{
    BOOL  bEnableProtect;
}LDR_PROTECT_STRUCT, * LPLDR_PROTECT_STRUCT;


#pragma data_seg("WMsgHookData")
BYTE pOriginalBytes[HHOOK_FUNCCOUNT][13] = { 0 };
HANDLER_INFO_STRUCT lpgHandlerInfo = { 0 };
#pragma data_seg()
#pragma comment(linker,"/SECTION:WMsgHookData,RWS")


BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    DisableThreadLibraryCalls(hModule);
    WCHAR wsFileName[MAX_PATH] = { 0 };
    WCHAR wsDebugPrint[56] = { 0 };
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        GetModuleFileNameW(NULL, wsFileName, MAX_PATH);
        if (!wcsstr(wsFileName, L"winlogon.exe"))
        {
            swprintf_s(wsDebugPrint, L"This thread is not in winlogon, TID: [%d].\n",
                GetCurrentThreadId());
            OutputDebugStringW(wsDebugPrint);
            return TRUE;
        }
        else {
            swprintf_s(wsDebugPrint, L"Init Hook in winlogon, TID: [%d].\n",
                GetCurrentThreadId());
            OutputDebugStringW(wsDebugPrint);
            lpgHandlerInfo.hHookModule = hModule;
            return InitHandlerAddress();
        }
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        if (!wcsstr(wsFileName, L"winlogon.exe"))
        {
            return TRUE;
        }
        //UnhookWMsgKMessageExceptionHandler(NULL);
        break;
    }
    return TRUE;
}

/*
    * /////////////////////////////////// 功能 //////////////////////////////////////
    *
    * WMsgMessageHandler 控制 账户状态/UAC 相关的功能
    * uMsgCSessionKey       uMsgWLGenericKey        MajorAction
    * 0001                  04002009            关闭本地计算机
    * 0001                  04002003            重启本地计算机
    * 0500                  1E88                请求提升管理员权限
    * 0501                  06B8                已经提升管理员权限
    * 0403                  0000                切换用户进行时（建议窗口在 Winlogon 下创建，并置前端）
    * 0202                  0000                切换用户恢复时（具体操作未知）
    * 0205                  0000                切换用户恢复时（具体操作未知）
    * 注意：（1）对于非已知代码的情况，不要使用阻滞过程，否则会导致死锁。
    *       （2）如果不需要执行指定的过程，函数返回值必须是 1，如果为 0 可能会陷入等待。
    *
    * /////////////////////////////////// 功能 //////////////////////////////////////
    *
    * WMsgKMessageHandler 控制 系统热键/注销 相关的功能
    * uMsgCSessionKey       uMsgWLGenericKey        MajorAction
    * 0404                  4                       Ctrl+Shift+Esc, 任务管理器
    * 0404                  0                       Ctrl+Alt+Delete, 安全桌面
    * 0404                  5                       Win+L, 锁屏, LogonUI Windows
    * 0404                  7                       Win+P, 投影屏幕
    * 0404                  6                       Win+U, 设置/辅助功能
    * 0404                  C                       Win+Plus, 放大镜
    * 0404                  D                       Win+Ctrl+Enter, 讲述人
    * 0404                  E                       Win+Enter, 未知
    * 0402                  5                       左Alt+LShift+Print Screen, 高对比度主题
    * 0402                  1                       连续按下五次左侧 Shift，滞粘键
    * 0402                  2                       按住右侧 Shift 键 8 秒，筛选键
    * 0001                  3                       Alt+F4 资源管理器，重启计算机
    * 0001                  4009                    Alt+F4 资源管理器，关闭计算机
    * 0001                  0                       Alt+F4 资源管理器，注销计算机
    *
    * ////////////////////////////////// 分割线 /////////////////////////////////////
    * 
*/
int __fastcall HookedWMsgKMessageHandler(
    unsigned int         uMachineState,
    unsigned int         uMsgWLGenericKey,
    PRPC_ASYNC_STATE     pAsync,
    LPDWORD              lpStatus   // int* pReserved
)
{
    int dwFunResponse = 0;
    DWORD dwMsgBoxResponse = 0;
    WCHAR wsTitle[] = L"TestHookingHandler";
    WCHAR wsSvcMsg[100] = { 0 };

    //if (uMsgCSessionKey == 0x404)
    //{
    swprintf_s(wsSvcMsg,
        L"Intercepted procedure call message: \nuMsgCSessionKey: %X, uMsgWLGenericKey: %X.\n ",
        uMachineState, uMsgWLGenericKey);
    if (SvcMessageBox(wsTitle, wsSvcMsg,
        MB_YESNO | MB_ICONINFORMATION | MB_SYSTEMMODAL,
        TRUE, dwMsgBoxResponse))
    {
        if (dwMsgBoxResponse == IDNO)
        {
            return 1;
        }
    }
    //}

    // UnHook
    DWORD sltIntem = 1;
    UnhookWMsgFuncHandler(&sltIntem);
    auto WMsgKMessageHandler = (__WMsgKMessageHandler)lpgHandlerInfo.lpHookFuncTable.pfn_WMsgKMsgHandler;

    dwFunResponse = WMsgKMessageHandler(uMachineState, uMsgWLGenericKey, pAsync, lpStatus);
    // Re-hook
    HookWMsgFuncHandler(&sltIntem);
    return dwFunResponse;
}


BOOL WINAPI InitHandlerAddress()
{
    WCHAR wsDbPrint[155] = { 0 };
    swprintf_s(wsDbPrint, L"Op:[GetModuleHandleW] ArgList:[HOOK_MODULE_NAME].\n");
    OutputDebugStringW(wsDbPrint);
    SetLastError(0);

    HMODULE hHookCore = GetModuleHandleW(HOOK_MODULE_NAME);
    if (hHookCore == NULL)
    {
        swprintf_s(wsDbPrint, L"Er:[GetModuleHandleW, HOOK_MODULE_NAME] Status:[%d].\n",
            GetLastError());
        OutputDebugStringW(wsDbPrint);
        return FALSE;
    }

    swprintf_s(wsDbPrint, L"Op:[GetModuleHandleW] ArgList:[Current].\n");
    OutputDebugStringW(wsDbPrint);
    SetLastError(0);
    HMODULE hModuleBase = GetModuleHandleW(NULL);
    if (hModuleBase == NULL)
    {
        swprintf_s(wsDbPrint, L"Er:[GetModuleHandleW, NULL] Status:[%d].\n",
            GetLastError());
        OutputDebugStringW(wsDbPrint);
        return FALSE;
    }

    swprintf_s(wsDbPrint, L"Op:[InitHandlerAddress] ArgList:[].\n");
    OutputDebugStringW(wsDbPrint);
    // 将函数指针等写入全局变量
    lpgHandlerInfo.lpWinlogonBase = hModuleBase;  // Winlogon 进程加载基址
    lpgHandlerInfo.dwMainThread = GetCurrentThreadId();  // 保存初始化例程所在线程TID
    lpgHandlerInfo.lpHookHandler = &HookWMsgFuncHandler;
    lpgHandlerInfo.lpUnhookHandler =
        &UnhookWMsgFuncHandler;
    lpgHandlerInfo.lpSafeFreeLib = &SafeFreeLibrary;
    //lpgHandlerInfo.lpEPLFuncAddress = &EasyProtectLibrary;

    if (lpgHandlerInfo.lpHookHandler == NULL ||
        lpgHandlerInfo.lpUnhookHandler == NULL ||
        lpgHandlerInfo.lpSafeFreeLib == NULL)
    {
        swprintf_s(wsDbPrint, L"Er:[CheckGlobalParameter] Status:[nullpointer].\n");
        OutputDebugStringW(wsDbPrint);
        return FALSE;
    }
    swprintf_s(wsDbPrint, L"Op:[InitHandlerAddress], pt:[0x%I64X].\n",
        reinterpret_cast<UINT64>(&lpgHandlerInfo));
    OutputDebugStringW(wsDbPrint);
    return TRUE;
}


BOOL WINAPI RemoteSetHookBaseAddress(HHOOKFUNCTABLE* funcOffestTable)
{
    if (lpgHandlerInfo.lpWinlogonBase == nullptr ||
        funcOffestTable == nullptr)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }


    // 修正地址 = 模块基址 + 偏移量
    __try {
        if (funcOffestTable->pfn_WMsgKMsgHandler != nullptr) {
            PVOID lpHookAddressTemp = reinterpret_cast<PVOID>(
                reinterpret_cast<UINT64>(funcOffestTable->pfn_WMsgKMsgHandler)
                + reinterpret_cast<UINT64>(lpgHandlerInfo.lpWinlogonBase));
            // 设置全局指针地址
            lpgHandlerInfo.lpHookFuncTable.pfn_WMsgKMsgHandler = lpHookAddressTemp;
        }
        else {
            lpgHandlerInfo.lpHookFuncTable.pfn_WMsgKMsgHandler = nullptr;
        }

        if (funcOffestTable->pfn_WMsgMsgHandler != nullptr) {
            PVOID lpHookAddressTemp = reinterpret_cast<PVOID>(
                reinterpret_cast<UINT64>(funcOffestTable->pfn_WMsgMsgHandler)
                + reinterpret_cast<UINT64>(lpgHandlerInfo.lpWinlogonBase));
            lpgHandlerInfo.lpHookFuncTable.pfn_WMsgMsgHandler = lpHookAddressTemp;
        }
        else {
            lpgHandlerInfo.lpHookFuncTable.pfn_WMsgMsgHandler = nullptr;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        OutputDebugStringW(L"Exception occurred while accessing memory.\n");
        SetLastError(ERROR_ACCESS_DENIED);
    }
    return TRUE;
}

// 用于检测虚拟地址是否有效，且对当前进程可以读写访问
BOOL IsExecutableAddress(LPVOID VirtualAddress)
{
    BOOL IsOk = FALSE;
    MEMORY_BASIC_INFORMATION MemoryBasicInfo = { 0 };


    if (!VirtualQuery(VirtualAddress, &MemoryBasicInfo, sizeof(MEMORY_BASIC_INFORMATION))) {

        return IsOk;
    }

    if ((MemoryBasicInfo.State == MEM_COMMIT) &&
        ((MemoryBasicInfo.Protect & PAGE_READONLY) ||
            (MemoryBasicInfo.Protect & PAGE_READWRITE) ||
            (MemoryBasicInfo.Protect & PAGE_EXECUTE_READ) ||
            (MemoryBasicInfo.Protect & PAGE_EXECUTE_READWRITE)))
    {
        IsOk = TRUE;
    }

    return IsOk;
}


// 检测地址指针是否有效
BOOL CheckPointerValidity(LPVOID ptr) {
    // 获取指针的值
    uintptr_t pointerValue = reinterpret_cast<uintptr_t>(ptr);
    WCHAR errString[56] = { 0 };
    __try {

        // 额外的检查条件
        if ((pointerValue >> 56) == 0xFF ||  // 高位是 FF
            !IsExecutableAddress(ptr)  // 进一步检查指针地址是否可读可写
            ) {
            throw L"Invalid pointer";
        }

        // 如果上面的检查通过，表示指针是有效且可写的
        return TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // 捕获异常，指针无效或不可写
        swprintf_s(errString, L"Read access is not allowed at 0x%I64X.\n", pointerValue);
        OutputDebugStringW(errString);
        return FALSE;
    }
}

BOOL WINAPI IsHookBaseAddressValidInternal(LPVOID lpHookAddress)
{
    PVOID lpWinlogonBaseTemp = lpgHandlerInfo.lpWinlogonBase;
    PVOID lpHookAddressTemp = lpHookAddress;// lpgHandlerInfo.lpHookAddress;
    HMODULE hWinlogonHandle =
        reinterpret_cast<HMODULE>(lpWinlogonBaseTemp);
    MODULEINFO moduleInfo = { 0 };
    UINT64 ulModuleBaseLb = 0, ulModuleBaseUp = 0;
    UINT64 ulHookAddress =
        reinterpret_cast<UINT64>(lpHookAddressTemp);

    if (lpWinlogonBaseTemp == nullptr ||
        lpHookAddressTemp == nullptr)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (!CheckPointerValidity(lpWinlogonBaseTemp))
    {
        SetLastError(ERROR_INVALID_ADDRESS);
        return FALSE;
    }

    if (!GetModuleInformation(GetCurrentProcess(),
        hWinlogonHandle, &moduleInfo, sizeof(moduleInfo))) {
        SetLastError(ERROR_INVALID_DLL);
        return FALSE;
    }

    ulModuleBaseLb =
        reinterpret_cast<UINT64>(lpWinlogonBaseTemp);
    ulModuleBaseUp =
        reinterpret_cast<UINT64>(lpWinlogonBaseTemp)
        + moduleInfo.SizeOfImage;

    if (ulHookAddress >= ulModuleBaseUp ||
        ulHookAddress <= ulModuleBaseLb)
    {
        SetLastError(ERROR_INVALID_DATA);
        return FALSE;
    }

    if (!CheckPointerValidity(lpHookAddressTemp))
    {
        SetLastError(ERROR_INVALID_ADDRESS);
        return FALSE;
    }

    return TRUE;
}


BOOL WINAPI GetHandlerAddress(LPHANDLER_INFO_STRUCT lpHandlerInfo)
{
    // 结构体指针不为空
    if (lpHandlerInfo == nullptr)
    {
        OutputDebugStringW(L"Er:[GetHandlerAddress] status:[Invalid nullptr].\n");
        return FALSE;
    }
    // 计算 cbSize 成员的地址
    SIZE_T cbSizeOff = offsetof(HANDLER_INFO_STRUCT, cbSize);
    PDWORD lpcbSize = reinterpret_cast<PDWORD>(lpHandlerInfo + cbSizeOff);
    // 保证传入结构体大小等于预期的大小
    if (*lpcbSize != sizeof(HANDLER_INFO_STRUCT))
    {
        OutputDebugStringW(L"Er:[GetHandlerAddress] status:[Invalid HANDLER_INFO_STRUCT Size].\n");
        return FALSE;
    }
    // 将传入结构体指针中的各个字段赋值给lpHandlerInfo结构体中对应的字段，并返回TRUE
    lpHandlerInfo->lpHookHandler = lpgHandlerInfo.lpHookHandler;
    lpHandlerInfo->lpUnhookHandler = lpgHandlerInfo.lpUnhookHandler;
    lpHandlerInfo->lpHookFuncTable.pfn_WMsgKMsgHandler = 
        lpgHandlerInfo.lpHookFuncTable.pfn_WMsgKMsgHandler;
    lpHandlerInfo->lpHookFuncTable.pfn_WMsgMsgHandler = 
        lpHandlerInfo->lpHookFuncTable.pfn_WMsgMsgHandler;
    //TODO: 深拷贝
    lpHandlerInfo->lpWinlogonBase = lpgHandlerInfo.lpWinlogonBase;
    lpHandlerInfo->lpSafeFreeLib = lpgHandlerInfo.lpSafeFreeLib;
    lpHandlerInfo->dwMainThread = lpgHandlerInfo.dwMainThread;
    lpHandlerInfo->hHookModule = lpgHandlerInfo.hHookModule;
    return TRUE;
}

DWORD EnableHookFuncInternal(LPVOID hTargetAddress, LPVOID lpOverrideSource) {
    LPVOID hHookAddress = hTargetAddress;

    BOOL bResponse = FALSE;
    DWORD oldProtect = 0;
    SIZE_T bufferSize = 0;


    // 首先进行必要的安全检查
    if (IsHookBaseAddressValidInternal(hHookAddress) == FALSE)
    {
        OutputDebugStringW(L"Er:[HookHandler] status:[Invalid Address].\n");
        return GetLastError();
    }

    // our trampoline
    unsigned char boing[] = {
        0x49, 0xbb, 0xde, 0xad,
        0xc0, 0xde, 0xde, 0xad,
        0xc0, 0xde, 0x41, 0xff,
        0xe3 };

    // add in the address of our hook
    *(LPVOID*)(boing + 2) = lpOverrideSource;
    bufferSize = sizeof(boing);


    // disable write protect
    SetLastError(0);
    bResponse = VirtualProtect(hHookAddress, bufferSize, PAGE_EXECUTE_READWRITE, &oldProtect);
    if (!bResponse)
    {
        OutputDebugStringW(L"Er:[HookHandler] status:[VirtualProect failed, EXECUTE_READWRITE].\n");
        return GetLastError();
    }

    // save the original bytes
    // TODO: 这里要正确处理备份的原始字节
    if (memcpy_s(pOriginalBytes, bufferSize, hHookAddress, bufferSize) != 0)
    {
        OutputDebugStringW(L"Er:[HookHandler] status:[memcpy failed, 1:2].\n");
        // 尝试下一个挂钩，跳过这个失败的（恢复内存保护）
        ::VirtualProtect(hHookAddress, bufferSize, oldProtect, &oldProtect);
        return ERROR_ACCESS_DENIED;
    }

    SetLastError(0);
    // write the hook
    if (memcpy_s(hHookAddress, bufferSize, boing, bufferSize) != 0)
    {
        OutputDebugStringW(L"Er:[HookHandler] status:[memcpy failed, 2:2].\n");
        return ERROR_ACCESS_DENIED;  // TODO: 通过传参返回，告知必须重启计算机
    }

    // Flush Cache to make code work
    bResponse = FlushInstructionCache(GetCurrentProcess(), hHookAddress, bufferSize);
    if (!bResponse)
    {
        OutputDebugStringW(L"Er:[HookHandler] status:[FlushInstructionCache failed].\n");
        return ERROR_ACCESS_DENIED;  // TODO: 通过传参返回，告知必须重启计算机
    }

    // enable write protect
    bResponse = VirtualProtect(hHookAddress, bufferSize, oldProtect, &oldProtect);
    if (!bResponse)
    {
        OutputDebugStringW(L"Er:[HookHandler] status:[VirtualProect failed].\n");
        return GetLastError();  // TODO: 通过传参返回，告知必须重启计算机
    }
    return ERROR_SUCCESS;
}

// TODO: 挂钩，统计挂钩成功个数，更新钩子函数列表
DWORD WINAPI HookWMsgFuncHandler(LPVOID lpThreadParameter)
{
    LPVOID pfn_WMsgKMsgHandler = lpgHandlerInfo.lpHookFuncTable.pfn_WMsgKMsgHandler;
    LPVOID pfn_WMsgMsgHandler = lpgHandlerInfo.lpHookFuncTable.pfn_WMsgMsgHandler;

    LDR_PROTECT_STRUCT ldrpt = { TRUE };

    // Enable FreeLibrary Protect
    ldrpt.bEnableProtect = TRUE;
    if (EasyProtectLibrary(&ldrpt) == 0)
    {
        OutputDebugStringW(L"Er:[HookHandler] status:[EasyProtectLibrary failed].\n");
        return FALSE;
    }

    EnableHookFuncInternal(pfn_WMsgKMsgHandler, );
    return TRUE;
}

DWORD DisableHookFuncInternal(const LPVOID lpTargetAddress) {
    DWORD bResponse = ERROR_SUCCESS;
    DWORD oldProtect = 0;
    // disable write protect
    bResponse = VirtualProtect(lpTargetAddress, 13, PAGE_EXECUTE_READWRITE, &oldProtect);
    if (!bResponse)
    {
        OutputDebugStringW(L"Er:[UnHookHandler] status:[VirtualProect failed, EXECUTE_READWRITE].\n");
        return bResponse;
    }

    // recover original bytes
    if (memcpy_s(lpTargetAddress, 13, pOriginalBytes, 13) != 0)
    {
        OutputDebugStringW(L"Er:[UnHookHandler] status:[memcpy failed].\n");
        return bResponse;
    }

    // Flush Cache to make code work
    bResponse = FlushInstructionCache(GetCurrentProcess(), lpTargetAddress, 13);
    if (!bResponse)
    {
        OutputDebugStringW(L"Er:[HookHandler] status:[FlushInstructionCache failed].\n");
        return GetLastError();
    }

    // enable write protect
    bResponse = VirtualProtect(lpTargetAddress, 13, oldProtect, &oldProtect);
    if (!bResponse)
    {
        OutputDebugStringW(L"Er:[UnHookHandler] status:[VirtualProect failed].\n");
        return bResponse;
    }
    return bResponse;
}


DWORD WINAPI UnhookWMsgFuncHandler(LPVOID lpThreadParameter)
{
    DWORD bResponse = ERROR_SUCCESS;
    DWORD sltIntem = 0;

    __try {
        if (lpThreadParameter != nullptr) {
            sltIntem = *(DWORD*)lpThreadParameter;
        }

        LPVOID pfn_WMsgKMsgHandler =
            lpgHandlerInfo.lpHookFuncTable.pfn_WMsgKMsgHandler;

        LPVOID pfn_WMsgMsgHandler =
            lpgHandlerInfo.lpHookFuncTable.pfn_WMsgMsgHandler;

        switch (sltIntem) {
        case 1:
            bResponse = DisableHookFuncInternal(pfn_WMsgKMsgHandler);
            break;
        case 2:
            bResponse = DisableHookFuncInternal(pfn_WMsgMsgHandler);
            break;
        default:
            bResponse = DisableHookFuncInternal(pfn_WMsgKMsgHandler);
            bResponse |= DisableHookFuncInternal(pfn_WMsgMsgHandler);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        OutputDebugStringW(L"Exception occurred while accessing memory.\n");
        SetLastError(ERROR_ACCESS_DENIED);
        return ERROR_ACCESS_DENIED;
    }
    return bResponse;
}


DWORD WINAPI EasyProtectLibrary(LPVOID lpThreadParameter)
{
    auto ldrpt = (LPLDR_PROTECT_STRUCT)lpThreadParameter;
    if (ldrpt == nullptr) return 0;

    BOOL bNewValue = ldrpt->bEnableProtect;
    BOOL bOldProtect = 0;
    DWORD index = 0;
    DWORD bResponse = 0;
    const WCHAR lpFileName[] = HOOK_MODULE_NAME;
    PPEB_LDR_DATA pPebLdrData = nullptr;
    PLDR_DATA_TABLE_ENTRY pLdrDataEntry = nullptr;
    PLIST_ENTRY pListEntryStart = nullptr;
    PLIST_ENTRY pListEntryEnd = nullptr;
    SIZE_T ulTestSize = 0;
    SIZE_T ulRealSize = wcsnlen_s(lpFileName, MAX_PATH);
#ifdef _WIN64
    ULONGLONG ModuleSum = NULL;
    PPEB peb = (PPEB)__readgsqword(0x60);
#else
    ULONG ModuleSum = NULL;
    PPEB32 peb = (PPEB32)__readfsdword(0x30);
#endif
    __try {
        pPebLdrData = peb->Ldr;
        // 以模块加载顺序排列的链表
        pListEntryStart = pPebLdrData->InLoadOrderModuleList.Flink;
        pListEntryEnd = pPebLdrData->InLoadOrderModuleList.Blink;
        for (index = 0; pListEntryStart != pListEntryEnd; index++)
        {
            pLdrDataEntry = CONTAINING_RECORD(pListEntryStart,
                LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

            ulTestSize = wcsnlen_s(pLdrDataEntry->BaseDllName.Buffer, MAX_PATH);
            if (ulTestSize != ulRealSize || ulTestSize == MAX_PATH)
            {
                pListEntryStart = pListEntryStart->Flink;
                continue;
            }

            if (!_wcsicmp(pLdrDataEntry->BaseDllName.Buffer, lpFileName))
            {
                if (bNewValue == TRUE)
                {
                    // 引用计数主要有两个成员，引用计数为 -1 表示静态加载的模块，
                    // 并且不允许卸载
                    pLdrDataEntry->DdagNode->LoadCount = 0xffffffff;
                    pLdrDataEntry->ObsoleteLoadCount = 0xffff;
                    pLdrDataEntry->Flags |= (1 << 5); // 将第六位置为 1
                }
                else {
                    // 引用计数主要有两个成员，引用计数为 -1 表示静态加载的模块，
                    // 并且不允许卸载
                    pLdrDataEntry->DdagNode->LoadCount = 1;
                    pLdrDataEntry->ObsoleteLoadCount = 1;
                    // ProcessStaticImport 位域如果为 1, 则任何卸载调用都将直接返回 TRUE
                    // 而不做任何资源释放操作
                    pLdrDataEntry->Flags &= ~(1 << 5); // 将第六位清零
                }

                //pLdrDataEntry->uFlags.ProcessStaticImport = bNewValue;
                bResponse |= 0x1;
                break;
            }
            pListEntryStart = pListEntryStart->Flink;
        }

        // 以内存位置排列的模块链表
        pListEntryStart = pPebLdrData->InMemoryOrderModuleList.Flink;
        pListEntryEnd = pPebLdrData->InMemoryOrderModuleList.Blink;
        for (index = 0; pListEntryStart != pListEntryEnd; index++)
        {
            pLdrDataEntry = CONTAINING_RECORD(pListEntryStart,
                LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

            ulTestSize = wcsnlen_s(pLdrDataEntry->BaseDllName.Buffer, MAX_PATH);
            if (ulTestSize != ulRealSize || ulTestSize == MAX_PATH)
            {
                pListEntryStart = pListEntryStart->Flink;
                continue;
            }

            if (!_wcsicmp(pLdrDataEntry->BaseDllName.Buffer, lpFileName))
            {
                if (bNewValue == TRUE)
                {
                    pLdrDataEntry->DdagNode->LoadCount = 0xffffffff;
                    pLdrDataEntry->ObsoleteLoadCount = 0xffff;
                    pLdrDataEntry->Flags |= (1 << 5);
                }
                else {
                    pLdrDataEntry->DdagNode->LoadCount = 1;
                    pLdrDataEntry->ObsoleteLoadCount = 1;
                    pLdrDataEntry->Flags &= ~(1 << 5);
                }
                //pLdrDataEntry->uFlags.ProcessStaticImport = bNewValue;
                bResponse |= 0x2;
                break;
            }
            pListEntryStart = pListEntryStart->Flink;
        }

        // 以初始化顺序加载的模块列表
        pListEntryStart = pPebLdrData->InInitializationOrderModuleList.Flink;
        pListEntryEnd = pPebLdrData->InInitializationOrderModuleList.Blink;
        for (index = 0; pListEntryStart != pListEntryEnd; index++)
        {
            pLdrDataEntry = CONTAINING_RECORD(pListEntryStart,
                LDR_DATA_TABLE_ENTRY, InInitializationOrderLinks);

            ulTestSize = wcsnlen_s(pLdrDataEntry->BaseDllName.Buffer, MAX_PATH);
            if (ulTestSize != ulRealSize || ulTestSize == MAX_PATH)
            {
                pListEntryStart = pListEntryStart->Flink;
                continue;
            }

            if (!_wcsicmp(pLdrDataEntry->BaseDllName.Buffer, lpFileName))
            {
                if (bNewValue == TRUE)
                {
                    pLdrDataEntry->DdagNode->LoadCount = 0xffffffff;
                    pLdrDataEntry->ObsoleteLoadCount = 0xffff;
                    pLdrDataEntry->Flags |= (1 << 5);
                }
                else {
                    pLdrDataEntry->DdagNode->LoadCount = 1;
                    pLdrDataEntry->ObsoleteLoadCount = 1;
                    pLdrDataEntry->Flags &= ~(1 << 5);
                }

                bResponse |= 0x4;
                break;
            }
            pListEntryStart = pListEntryStart->Flink;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        OutputDebugStringW(L"Er:Exception occurred while accessing memory.\n");
        return FALSE;
    }

    return bResponse;
}

DWORD WINAPI SafeFreeLibrary(LPVOID lpThreadParameter)
{
    DWORD dwMainThread = lpgHandlerInfo.dwMainThread;
    HMODULE hThisModule = lpgHandlerInfo.hHookModule;

    // Safely free module
    if (dwMainThread != GetCurrentThreadId())
    {
        DWORD dwExitCode = TRUE;
        LDR_PROTECT_STRUCT ldrpt = { FALSE };
        EasyProtectLibrary(&ldrpt); // 解除保护
        // 卸载模块
        FreeLibraryAndExitThread(hThisModule, dwExitCode);
        return TRUE;
    }
    return FALSE;
}