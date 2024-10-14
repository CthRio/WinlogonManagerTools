#include <windows.h>
#include <tchar.h>
#include <string>
#include <thread>
#include <Tlhelp32.h>
#include <psapi.h>
#include <shobjidl_core.h>
#include <iostream>
#include "resource.h"


#pragma comment(linker,"\"/manifestdependency:type='win32' "\
						"name='Microsoft.Windows.Common-Controls' "\
						"version='6.0.0.0' processorArchitecture='*' "\
						"publicKeyToken='6595b64144ccf1df' language='*'\"")

const wchar_t* PIPE_NAME = L"\\\\.\\pipe\\StartupManagerPipe";
const wchar_t* MUTEX_RUN_NAME = L"Global\\WMHProgramMutex";
const wchar_t* MUTEX_NAME = L"Global\\StartupManagerMutex";
const DWORD PIPE_TIMEOUT_MS = 25000; // 25 秒超时

struct StartParams {
    bool is64Bit;
    HWND hwndMan;
    HWND hwndLog;
    HANDLE hThread;
    HANDLE hEventExit;
};

void LogMessage(HWND hwndLog, const wchar_t* message) {
    // 在日志窗口添加消息
    SendMessageW(hwndLog, EM_SETSEL, -1, -1);
    SendMessageW(hwndLog, EM_REPLACESEL, FALSE, (LPARAM)message);
    SendMessageW(hwndLog, EM_REPLACESEL, FALSE, (LPARAM)L"\r\n");
    SendMessageW(hwndLog, EM_SCROLLCARET, 0, 0);
}

BOOL WINAPI SafeCloseHandle(HANDLE* lpHandle)
{
    BOOL bResponse = FALSE;

    __try {
        HANDLE handle = *lpHandle;
        if (handle != nullptr) {
            bResponse = CloseHandle(handle);
            *lpHandle = nullptr;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        bResponse = FALSE;
    }
    return bResponse;
}

DWORD Is64BitProcess(DWORD processId) {
    BOOL is64BitOS = FALSE;
    BOOL isWow64 = FALSE;

    // 获取系统信息，判断操作系统是64位还是32位
    SYSTEM_INFO systemInfo;
    GetNativeSystemInfo(&systemInfo);

    if (systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
        systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64) {
        is64BitOS = TRUE;
    }

    // 打开进程，获取进程句柄
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (hProcess == NULL) {
        //std::cerr << "无法打开进程: " << GetLastError() << std::endl;
        return 2;
    }

    // 调用IsWow64Process函数，判断进程是64位还是32位
    if (!IsWow64Process(hProcess, &isWow64)) {
        //std::cerr << "无法调用 IsWow64Process: " << GetLastError() << std::endl;
        SafeCloseHandle(&hProcess);
        return 2;
    }

    // 关闭进程句柄
    SafeCloseHandle(&hProcess);

    // 根据操作系统和进程的Wow64状态判断进程架构
    if (is64BitOS) {
        if (isWow64) {
            return 0;  // 32位进程
        }
        else {
            return 1;   // 64位进程
        }
    }
    else {
        return 0; // 32位操作系统上，所有进程都是32位
    }
}

DWORD GetActiveConsoleSessionId() {
    return WTSGetActiveConsoleSessionId();
}

BOOL IsProcessInSession(DWORD processId, DWORD sessionId) {
    DWORD session;
    if (!ProcessIdToSessionId(processId, &session)) {
        printf("Error: ProcessIdToSessionId failed.\n");
        return FALSE;
    }
    return session == sessionId;
}

DWORD FindWinlogonProcessId() {
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

    PROCESSENTRY32W entry = { 0 };
    entry.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(snapshot, &entry)) {
        printf("Error: Process32First failed.\n");
        SafeCloseHandle(&snapshot);
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
    } while (Process32NextW(snapshot, &entry));

    SafeCloseHandle(&snapshot);
    return dwProcessId;
}

BOOL ShowInTaskbar(HWND hWnd, BOOL bShow)
{

    HRESULT hr;
    ITaskbarList* pTaskbarList;
    hr = CoCreateInstance(CLSID_TaskbarList, NULL, CLSCTX_INPROC_SERVER,
        IID_ITaskbarList, (void**)&pTaskbarList);

    if (SUCCEEDED(hr))
    {

        pTaskbarList->HrInit();
        if (bShow)
            pTaskbarList->AddTab(hWnd);
        else
            pTaskbarList->DeleteTab(hWnd);

        pTaskbarList->Release();
        return TRUE;
    }

    return FALSE;
}

DWORD StartProgramWithAdminPrivileges(StartParams* params) {
    // 第一次调用，获取所需缓冲区大小
    DWORD pathSize = MAX_PATH;
    wchar_t* modulePath = new wchar_t[pathSize];
    if (!GetModuleFileNameExW(GetCurrentProcess(), NULL, modulePath, pathSize)) {
        pathSize = GetLastError() == ERROR_INSUFFICIENT_BUFFER ? pathSize * 2 : 0;
    }

    // 处理缓冲区大小不足的情况
    if (pathSize > MAX_PATH) {
        delete[] modulePath;
        modulePath = new wchar_t[pathSize];
        if (!GetModuleFileNameExW(GetCurrentProcess(), NULL, modulePath, pathSize)) {
            LogMessage(params->hwndLog, L"Failed to get module file name.");
            delete[] modulePath;
            delete params;
            return 1;
        }
    }

    // 使用循环获取目录路径
    for (UINT i = pathSize - 1; i > 0; i--) {
        if (modulePath[i] == L'\\')
        {
            for (UINT j = i; j < pathSize; j++) {
                modulePath[j] = L'\0';
            }
            break;
        }
    }

    pathSize = wcslen(modulePath) + 1;

    // 构建程序路径
    const wchar_t* programName =
        params->is64Bit ? L"WMsgInterceptor.exe" : L"\\x86\\WMsgInterceptor.exe";

    wchar_t* programPath = nullptr;
    pathSize += wcslen(programName) + 1;
    programPath = new wchar_t[pathSize];
    swprintf_s(programPath, pathSize, L"%s\\%s", modulePath, programName);

    // 创建命名管道
    HANDLE hPipe = CreateNamedPipeW(
        PIPE_NAME,
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, // 使用非阻塞模式
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1, 1024, 1024, 0, NULL);

    delete[] modulePath; // 释放内存

    if (hPipe == INVALID_HANDLE_VALUE) {
        LogMessage(params->hwndLog, L"Failed to create named pipe.");
        delete[] programPath; // 释放内存
        delete params;
        return 1;
    }

    // 设置启动信息
    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.lpVerb = L"runas"; // 以管理员权限运行
    sei.lpFile = programPath;
    sei.nShow = SW_SHOWNORMAL;
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;

    wchar_t logMessage[MAX_PATH + 50];
    swprintf_s(logMessage, MAX_PATH + 50, L"Starting %s with admin privileges...", programPath);
    LogMessage(params->hwndLog, logMessage);

    if (!ShellExecuteExW(&sei)) {
        LogMessage(params->hwndLog, L"Failed to start program with admin privileges.");
        SafeCloseHandle(&hPipe);
        delete params;
        return 1;
    }

    delete[] programPath; // 释放内存

    // 等待程序连接到命名管道
    OVERLAPPED overlapped = { 0 };
    overlapped.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);

    if (overlapped.hEvent == NULL)
        return 1;

    ConnectNamedPipe(hPipe, &overlapped);

    DWORD dwWaitResult = WaitForSingleObject(overlapped.hEvent, PIPE_TIMEOUT_MS);
    if (dwWaitResult == WAIT_TIMEOUT) {
        // 超时处理，可以选择关闭管道或者其他操作
        LogMessage(params->hwndLog, L"Connection pipeline timeout!");
        if(sei.hProcess) TerminateProcess(sei.hProcess, 1);
        CloseHandle(hPipe);
        CloseHandle(overlapped.hEvent);

        Sleep(3000);

        // 发送关闭消息给窗口
        SendMessageW(params->hwndMan, WM_CLOSE, 0, 0);
        delete params;
        return 1;
    }
    else if (dwWaitResult == WAIT_OBJECT_0) {
        LogMessage(params->hwndLog, L"Program connected to named pipe.");
    }
    else {
        LogMessage(params->hwndLog, L"Failed to connect to named pipe.");
        SafeCloseHandle(&hPipe);
        
        Sleep(3000);

        // 发送关闭消息给窗口
        SendMessageW(params->hwndMan, WM_CLOSE, 0, 0);
        delete params;
        return 1;
    }

    SafeCloseHandle(&overlapped.hEvent);

    // 接收验证请求
    wchar_t buffer[128];
    ZeroMemory(buffer, 128 * sizeof(wchar_t));

    DWORD bytesRead;
    if (ReadFile(hPipe, buffer, sizeof(buffer) - sizeof(wchar_t), &bytesRead, NULL)) {
        buffer[bytesRead / sizeof(wchar_t)] = L'\0';
        swprintf_s(logMessage, MAX_PATH + 50, L"Received: %s", buffer);
        LogMessage(params->hwndLog, logMessage);

        // 发送确认信息
        const wchar_t* response = L"Confirmed by Startup Manager";
        DWORD bytesWritten;
        WriteFile(hPipe, response, wcslen(response) * sizeof(wchar_t), &bytesWritten, NULL);

        // 关闭命名管道
        SafeCloseHandle(&hPipe);

        Sleep(3000);

        // 发送关闭消息给窗口
        SendMessageW(params->hwndMan, WM_CLOSE, 0, 0);
    }

    // 关闭命名管道
    SafeCloseHandle(&hPipe);

    // 等待退出事件信号
    WaitForSingleObject(params->hEventExit, INFINITE);

    delete params;

    return 0;
}

DWORD ExitThreadProc(StartParams* params) {

    LogMessage(params->hwndLog, L"Preparing to exit the process...");

    // 设置退出事件，通知线程退出
    if (params->hEventExit != NULL) {
        SetEvent(params->hEventExit);

        // 等待线程结束
        if (params->hThread != NULL) {
            ShowWindow(params->hwndMan, SW_MINIMIZE);
            if (WaitForSingleObject(params->hThread, 60000) == WAIT_TIMEOUT) {
                LogMessage(params->hwndLog, L"Thread waiting timeout, forcing thread termination.");
                TerminateThread(params->hThread, 0);
                Sleep(3000);
            }
            SafeCloseHandle(&(params->hThread));
        }
        SafeCloseHandle(&(params->hEventExit));
    }
    SendMessageW(params->hwndMan, WM_DESTROY, 0, 0);
    return 0;
}


void RunTestCheck() {
    HANDLE hMutex = CreateMutexW(NULL, TRUE, MUTEX_NAME);
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        MessageBoxW(NULL, L"Another instance is already running.",
            L"Message", MB_OK | MB_ICONWARNING);
        exit(0);
    }

    HANDLE hMutex2 = CreateMutexW(NULL, FALSE, MUTEX_RUN_NAME);
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        MessageBoxW(NULL, L"Another instance is already running.",
            L"Message", MB_OK | MB_ICONWARNING);
        exit(0);
    }

    if(hMutex2) {  // 关闭 Mutex
        CloseHandle(hMutex2);
    }
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static HANDLE hThread = NULL;
    static HANDLE hEventExit = NULL;
    static HWND hwndLog = NULL;
    static HBITMAP hBitmapBuffer = NULL;
    static HDC hdcBuffer = NULL;
    static int width, height;

    switch (msg) {
    case WM_CREATE: {
        hwndLog = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", NULL,
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
            10, 10, 600, 400, hwnd, NULL, GetModuleHandle(NULL), NULL);

        // 创建离屏缓冲区
        HDC hdc = GetDC(hwnd);
        hdcBuffer = CreateCompatibleDC(hdc);
        RECT rect;
        GetClientRect(hwnd, &rect);
        width = rect.right;
        height = rect.bottom;
        hBitmapBuffer = CreateCompatibleBitmap(hdc, width, height);
        SelectObject(hdcBuffer, hBitmapBuffer);
        ReleaseDC(hwnd, hdc);

        // 查找 Winlogon 进程 ID
        DWORD dwWinlogonId = FindWinlogonProcessId();
        if (dwWinlogonId == 0) {
            MessageBoxW(hwnd, L"Unable to find the running winlogon.exe process!", L"Error", MB_OK | MB_ICONERROR);
            return -1; // 创建失败，返回 -1
        }

        // 记录消息
        wchar_t message[256];
        swprintf_s(message, L"Winlogon Process ID: %d", dwWinlogonId);
        LogMessage(hwndLog, message);

        // 检查 Winlogon 是否为 64 位进程
        DWORD is64Bit = Is64BitProcess(dwWinlogonId);

        if (is64Bit == 2) {
            LogMessage(hwndLog, L"Unable to check target process!");
            return -1;
        }

        // 创建退出事件
        hEventExit = CreateEventW(NULL, TRUE, FALSE, NULL);

        StartParams* params = new StartParams;

        params->hEventExit = hEventExit;
        params->hwndLog = hwndLog;
        params->hwndMan = hwnd;
        params->is64Bit = ((is64Bit == 1) ? true : false);

        // 启动新线程
        hThread = CreateThread(NULL, 0, 
            (LPTHREAD_START_ROUTINE)StartProgramWithAdminPrivileges,
            params, 0, NULL);

        if (hThread == NULL) {
            LogMessage(hwndLog, L"Unable to create new thread!");
            delete params; // 清理 StartParams
            return -1;
        }
        return 0;
    }
    case WM_SIZE: {
        int newWidth = LOWORD(lParam);
        int newHeight = HIWORD(lParam);
        if (newWidth != width || newHeight != height) {
            HDC hdc = GetDC(hwnd);
            HBITMAP hNewBitmap = CreateCompatibleBitmap(hdc, newWidth, newHeight);
            SelectObject(hdcBuffer, hNewBitmap);
            DeleteObject(hBitmapBuffer);
            hBitmapBuffer = hNewBitmap;
            width = newWidth;
            height = newHeight;
            ReleaseDC(hwnd, hdc);
        }
        InvalidateRect(hwnd, NULL, TRUE);
        break;
    }
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);

        // 绘制内容到离屏缓冲区
        RECT rect;
        GetClientRect(hwnd, &rect);
        FillRect(hdcBuffer, &rect, (HBRUSH)(COLOR_WINDOW + 1));
        // 在这里绘制其他内容

        // 将离屏缓冲区内容绘制到窗口
        BitBlt(hdc, 0, 0, width, height, hdcBuffer, 0, 0, SRCCOPY);

        EndPaint(hwnd, &ps);
        break;
    }
    case WM_CLOSE: {
        StartParams* params = new StartParams;
        params->hEventExit = hEventExit;
        params->hwndMan = hwnd;
        params->hwndLog = hwndLog;
        params->hThread = hThread;
        HANDLE hCloseThread = CreateThread(NULL, 0,
            (LPTHREAD_START_ROUTINE)ExitThreadProc,
            params, 0, NULL);

        if (hCloseThread != NULL) {
            CloseHandle(hCloseThread); // 关闭线程句柄，不需要等待
        }
        else {  // 如果线程创建失败，立即强制结束
            TerminateThread(params->hThread, 0);
            SafeCloseHandle(&hEventExit);
            SafeCloseHandle(&hThread);
            SendMessageW(hwndLog, WM_CLOSE, 0, 0);
        }
        break;
    }
    case WM_DESTROY: {
        // 释放缓冲区资源
        DeleteObject(hBitmapBuffer);
        DeleteDC(hdcBuffer);
        PostQuitMessage(0);
        break;
    }
    default:
        return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    return 0;
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow) {
    RunTestCheck(); // 检查是否已在运行

    // 加载不同尺寸的图标资源
    HICON hIcon48 = (HICON)LoadImageW(hInstance,
        MAKEINTRESOURCEW(IDI_ICON1), IMAGE_ICON,
        48, 48, LR_DEFAULTCOLOR);
    HICON hIcon32 = (HICON)LoadImageW(hInstance,
        MAKEINTRESOURCEW(IDI_ICON2), IMAGE_ICON,
        32, 32, LR_DEFAULTCOLOR);

    const wchar_t CLASS_NAME[] = L"WMH Startup Manager Window Class";

    WNDCLASS wc = { };
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    // 设置窗口类图标
    wc.hIcon = hIcon32;     // 设置小图标

    RegisterClassW(&wc);

    HWND hwnd = CreateWindowExW(
        WS_EX_TOPMOST | WS_EX_COMPOSITED,
        CLASS_NAME,
        L"WMH Startup Manager",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 640, 480,
        NULL,
        NULL,
        hInstance,
        NULL
    );

    if (hwnd == NULL) {
        return 0;
    }

    // 获取屏幕尺寸
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);

    // 获取窗口尺寸
    RECT windowRect;
    GetWindowRect(hwnd, &windowRect);
    int windowWidth = windowRect.right - windowRect.left;
    int windowHeight = windowRect.bottom - windowRect.top;

    // 计算窗口居中位置
    int posX = (screenWidth - windowWidth) / 5;
    int posY = (screenHeight - windowHeight) / 5;

    // 设置窗口位置
    SetWindowPos(hwnd, NULL, posX, posY, 0, 0, SWP_NOSIZE | SWP_NOZORDER);

    // 设置窗口图标
    SendMessageW(hwnd, WM_SETICON, ICON_BIG, (LPARAM)hIcon48);   // 设置大图标
    SendMessageW(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)hIcon32); // 设置小图标

    // 显示窗口，并从任务栏隐藏 Tab
    ShowWindow(hwnd, nCmdShow);
    ShowInTaskbar(hwnd, FALSE);

    MSG msg = { };
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    return 0;
}
