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
const DWORD PIPE_TIMEOUT_MS = 25000; // 25 �볬ʱ

struct StartParams {
    bool is64Bit;
    HWND hwndMan;
    HWND hwndLog;
    HANDLE hThread;
    HANDLE hEventExit;
};

void LogMessage(HWND hwndLog, const wchar_t* message) {
    // ����־���������Ϣ
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

    // ��ȡϵͳ��Ϣ���жϲ���ϵͳ��64λ����32λ
    SYSTEM_INFO systemInfo;
    GetNativeSystemInfo(&systemInfo);

    if (systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
        systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64) {
        is64BitOS = TRUE;
    }

    // �򿪽��̣���ȡ���̾��
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (hProcess == NULL) {
        //std::cerr << "�޷��򿪽���: " << GetLastError() << std::endl;
        return 2;
    }

    // ����IsWow64Process�������жϽ�����64λ����32λ
    if (!IsWow64Process(hProcess, &isWow64)) {
        //std::cerr << "�޷����� IsWow64Process: " << GetLastError() << std::endl;
        SafeCloseHandle(&hProcess);
        return 2;
    }

    // �رս��̾��
    SafeCloseHandle(&hProcess);

    // ���ݲ���ϵͳ�ͽ��̵�Wow64״̬�жϽ��̼ܹ�
    if (is64BitOS) {
        if (isWow64) {
            return 0;  // 32λ����
        }
        else {
            return 1;   // 64λ����
        }
    }
    else {
        return 0; // 32λ����ϵͳ�ϣ����н��̶���32λ
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
        if (entry.cntThreads <= 1u) continue; // ������ʬ����

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
    // ��һ�ε��ã���ȡ���軺������С
    DWORD pathSize = MAX_PATH;
    wchar_t* modulePath = new wchar_t[pathSize];
    if (!GetModuleFileNameExW(GetCurrentProcess(), NULL, modulePath, pathSize)) {
        pathSize = GetLastError() == ERROR_INSUFFICIENT_BUFFER ? pathSize * 2 : 0;
    }

    // ����������С��������
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

    // ʹ��ѭ����ȡĿ¼·��
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

    // ��������·��
    const wchar_t* programName =
        params->is64Bit ? L"WMsgInterceptor.exe" : L"\\x86\\WMsgInterceptor.exe";

    wchar_t* programPath = nullptr;
    pathSize += wcslen(programName) + 1;
    programPath = new wchar_t[pathSize];
    swprintf_s(programPath, pathSize, L"%s\\%s", modulePath, programName);

    // ���������ܵ�
    HANDLE hPipe = CreateNamedPipeW(
        PIPE_NAME,
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, // ʹ�÷�����ģʽ
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1, 1024, 1024, 0, NULL);

    delete[] modulePath; // �ͷ��ڴ�

    if (hPipe == INVALID_HANDLE_VALUE) {
        LogMessage(params->hwndLog, L"Failed to create named pipe.");
        delete[] programPath; // �ͷ��ڴ�
        delete params;
        return 1;
    }

    // ����������Ϣ
    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.lpVerb = L"runas"; // �Թ���ԱȨ������
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

    delete[] programPath; // �ͷ��ڴ�

    // �ȴ��������ӵ������ܵ�
    OVERLAPPED overlapped = { 0 };
    overlapped.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);

    if (overlapped.hEvent == NULL)
        return 1;

    ConnectNamedPipe(hPipe, &overlapped);

    DWORD dwWaitResult = WaitForSingleObject(overlapped.hEvent, PIPE_TIMEOUT_MS);
    if (dwWaitResult == WAIT_TIMEOUT) {
        // ��ʱ��������ѡ��رչܵ�������������
        LogMessage(params->hwndLog, L"Connection pipeline timeout!");
        if(sei.hProcess) TerminateProcess(sei.hProcess, 1);
        CloseHandle(hPipe);
        CloseHandle(overlapped.hEvent);

        Sleep(3000);

        // ���͹ر���Ϣ������
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

        // ���͹ر���Ϣ������
        SendMessageW(params->hwndMan, WM_CLOSE, 0, 0);
        delete params;
        return 1;
    }

    SafeCloseHandle(&overlapped.hEvent);

    // ������֤����
    wchar_t buffer[128];
    ZeroMemory(buffer, 128 * sizeof(wchar_t));

    DWORD bytesRead;
    if (ReadFile(hPipe, buffer, sizeof(buffer) - sizeof(wchar_t), &bytesRead, NULL)) {
        buffer[bytesRead / sizeof(wchar_t)] = L'\0';
        swprintf_s(logMessage, MAX_PATH + 50, L"Received: %s", buffer);
        LogMessage(params->hwndLog, logMessage);

        // ����ȷ����Ϣ
        const wchar_t* response = L"Confirmed by Startup Manager";
        DWORD bytesWritten;
        WriteFile(hPipe, response, wcslen(response) * sizeof(wchar_t), &bytesWritten, NULL);

        // �ر������ܵ�
        SafeCloseHandle(&hPipe);

        Sleep(3000);

        // ���͹ر���Ϣ������
        SendMessageW(params->hwndMan, WM_CLOSE, 0, 0);
    }

    // �ر������ܵ�
    SafeCloseHandle(&hPipe);

    // �ȴ��˳��¼��ź�
    WaitForSingleObject(params->hEventExit, INFINITE);

    delete params;

    return 0;
}

DWORD ExitThreadProc(StartParams* params) {

    LogMessage(params->hwndLog, L"Preparing to exit the process...");

    // �����˳��¼���֪ͨ�߳��˳�
    if (params->hEventExit != NULL) {
        SetEvent(params->hEventExit);

        // �ȴ��߳̽���
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

    if(hMutex2) {  // �ر� Mutex
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

        // ��������������
        HDC hdc = GetDC(hwnd);
        hdcBuffer = CreateCompatibleDC(hdc);
        RECT rect;
        GetClientRect(hwnd, &rect);
        width = rect.right;
        height = rect.bottom;
        hBitmapBuffer = CreateCompatibleBitmap(hdc, width, height);
        SelectObject(hdcBuffer, hBitmapBuffer);
        ReleaseDC(hwnd, hdc);

        // ���� Winlogon ���� ID
        DWORD dwWinlogonId = FindWinlogonProcessId();
        if (dwWinlogonId == 0) {
            MessageBoxW(hwnd, L"Unable to find the running winlogon.exe process!", L"Error", MB_OK | MB_ICONERROR);
            return -1; // ����ʧ�ܣ����� -1
        }

        // ��¼��Ϣ
        wchar_t message[256];
        swprintf_s(message, L"Winlogon Process ID: %d", dwWinlogonId);
        LogMessage(hwndLog, message);

        // ��� Winlogon �Ƿ�Ϊ 64 λ����
        DWORD is64Bit = Is64BitProcess(dwWinlogonId);

        if (is64Bit == 2) {
            LogMessage(hwndLog, L"Unable to check target process!");
            return -1;
        }

        // �����˳��¼�
        hEventExit = CreateEventW(NULL, TRUE, FALSE, NULL);

        StartParams* params = new StartParams;

        params->hEventExit = hEventExit;
        params->hwndLog = hwndLog;
        params->hwndMan = hwnd;
        params->is64Bit = ((is64Bit == 1) ? true : false);

        // �������߳�
        hThread = CreateThread(NULL, 0, 
            (LPTHREAD_START_ROUTINE)StartProgramWithAdminPrivileges,
            params, 0, NULL);

        if (hThread == NULL) {
            LogMessage(hwndLog, L"Unable to create new thread!");
            delete params; // ���� StartParams
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

        // �������ݵ�����������
        RECT rect;
        GetClientRect(hwnd, &rect);
        FillRect(hdcBuffer, &rect, (HBRUSH)(COLOR_WINDOW + 1));
        // �����������������

        // ���������������ݻ��Ƶ�����
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
            CloseHandle(hCloseThread); // �ر��߳̾��������Ҫ�ȴ�
        }
        else {  // ����̴߳���ʧ�ܣ�����ǿ�ƽ���
            TerminateThread(params->hThread, 0);
            SafeCloseHandle(&hEventExit);
            SafeCloseHandle(&hThread);
            SendMessageW(hwndLog, WM_CLOSE, 0, 0);
        }
        break;
    }
    case WM_DESTROY: {
        // �ͷŻ�������Դ
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
    RunTestCheck(); // ����Ƿ���������

    // ���ز�ͬ�ߴ��ͼ����Դ
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
    // ���ô�����ͼ��
    wc.hIcon = hIcon32;     // ����Сͼ��

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

    // ��ȡ��Ļ�ߴ�
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);

    // ��ȡ���ڳߴ�
    RECT windowRect;
    GetWindowRect(hwnd, &windowRect);
    int windowWidth = windowRect.right - windowRect.left;
    int windowHeight = windowRect.bottom - windowRect.top;

    // ���㴰�ھ���λ��
    int posX = (screenWidth - windowWidth) / 5;
    int posY = (screenHeight - windowHeight) / 5;

    // ���ô���λ��
    SetWindowPos(hwnd, NULL, posX, posY, 0, 0, SWP_NOSIZE | SWP_NOZORDER);

    // ���ô���ͼ��
    SendMessageW(hwnd, WM_SETICON, ICON_BIG, (LPARAM)hIcon48);   // ���ô�ͼ��
    SendMessageW(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)hIcon32); // ����Сͼ��

    // ��ʾ���ڣ��������������� Tab
    ShowWindow(hwnd, nCmdShow);
    ShowInTaskbar(hwnd, FALSE);

    MSG msg = { };
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    return 0;
}
