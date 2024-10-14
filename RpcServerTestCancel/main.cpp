#include "RpcServerTestCancel.h"
#include "CustomDialog.h"
#include "main.h"


int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) {

    if (!VerifyStartup()) {
        MessageBoxW(NULL, L"Error: This program can only be run from the startup manager.",
            L"Message", MB_OK | MB_ICONWARNING | MB_APPLMODAL | MB_TOPMOST);
        exit(0);
        return 1; // �������˳�
    }

    RunTestCheck(); // ����Ƿ���������

    g_hInstance = hInstance;

    //SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);

    const wchar_t CLASS_NAME[] = TOOLAPPCLASSNAME;

    WNDCLASS wc = {};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;

    // ���ز�ͬ�ߴ��ͼ����Դ
    HICON hIcon48 = (HICON)LoadImageW(hInstance,
        MAKEINTRESOURCEW(IDI_ICON1), IMAGE_ICON,
        48, 48, LR_DEFAULTCOLOR);
    HICON hIcon32 = (HICON)LoadImageW(hInstance,
        MAKEINTRESOURCEW(IDI_ICON2), IMAGE_ICON,
        32, 32, LR_DEFAULTCOLOR);

    // ���ô�����ͼ��
    wc.hIcon = hIcon32;     // ����Сͼ��

    wc.hCursor = LoadCursorW(hInstance, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);  //   (COLOR_WINDOW + 1);
    wc.style = CS_HREDRAW | CS_VREDRAW | CS_DBLCLKS;

    if (!RegisterClassW(&wc)) {
        return 0;
    }

    HWND hwnd = CreateWindowExW(
        WS_EX_OVERLAPPEDWINDOW | WS_EX_TOPMOST,
        CLASS_NAME,
        TOOLAPPTITLENAME,
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 760, 600,
        NULL, NULL, hInstance, NULL
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
    int posX = (screenWidth - windowWidth) / 2;
    int posY = (screenHeight - windowHeight) / 2;

    // ���ô���λ��
    SetWindowPos(hwnd, NULL, posX, posY, 0, 0, SWP_NOSIZE | SWP_NOZORDER);

    // ���ô���ͼ��
    SendMessageW(hwnd, WM_SETICON, ICON_BIG, (LPARAM)hIcon48);   // ���ô�ͼ��
    SendMessageW(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)hIcon32); // ����Сͼ��

    BOOL value = TRUE;
    ::DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, &value, sizeof(value));

    // ���÷ֲ㴰�ں�͸����
    SetWindowLongW(hwnd, GWL_EXSTYLE, GetWindowLongW(hwnd, GWL_EXSTYLE) | WS_EX_LAYERED);
    SetLayeredWindowAttributes(hwnd, 0, (255 * 75) / 100, LWA_ALPHA);

    // ��ʾ����
    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg = {};
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    return 0;
}

// 
// ---------------------------------------------------------------------
// 

bool VerifyStartup() {
    // ���ӵ������ܵ�
    HANDLE hPipe = CreateFileW(
        PIPE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, 0, NULL);

    if (hPipe == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to connect to named pipe." << std::endl;
        return false;
    }

    // ������֤����
    const wchar_t* request = L"Verification request from program";
    DWORD bytesWritten;
    if (!WriteFile(hPipe, request, wcslen(request) * sizeof(wchar_t), &bytesWritten, NULL)) {
        std::cerr << "Failed to write to named pipe." << std::endl;
        CloseHandle(hPipe);
        return false;
    }

    // ����ȷ����Ϣ
    wchar_t buffer[128] = { 0 };
    DWORD bytesRead;
    if (ReadFile(hPipe, buffer, sizeof(buffer) - sizeof(wchar_t), &bytesRead, NULL)) {
        buffer[bytesRead / sizeof(wchar_t)] = L'\0';
        std::wcout << L"Received: " << buffer << std::endl;
        if (std::wstring(buffer) == L"Confirmed by Startup Manager") {
            CloseHandle(hPipe);
            return true;
        }
    }

    CloseHandle(hPipe);
    return false;
}


void RunTestCheck() {
    HANDLE hMutex = CreateMutexW(NULL, TRUE, MUTEX_NAME);
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        exit(0);
    }
}


LRESULT CALLBACK RichEditSubclassProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam, UINT_PTR, DWORD_PTR) {
    switch (uMsg) {
    case WM_KEYDOWN:
        switch (wParam) {
        case VK_DELETE:
        case VK_BACK:
            // ͨ������0��ֹ����ɾ������
            return 0;
        case 'A':
            if (GetKeyState(VK_CONTROL) & 0x8000) {
                // ����Ctrl+Aʱѡ�������ı�
                SendMessageW(hwnd, EM_SETSEL, 0, -1);
                return 0;
            }
            break;
        }
        break;
    case WM_CHAR:  // ��ֹӢ���ַ�����
    case WM_IME_COMPOSITION: // ��ֹIME�����뷨�༭�����ϳ�
    case WM_PASTE:
        return 0; // ��ֹ�ı����루ճ����
    case WM_RBUTTONDOWN: {  // �����Ҽ��˵�
        HMENU hMenu = CreatePopupMenu();
        AppendMenuW(hMenu, MF_STRING, ID_SELECT_ALL, L"Select All");
        AppendMenuW(hMenu, MF_STRING, ID_CANCEL, L"Cancel");
        AppendMenuW(hMenu, MF_STRING, ID_COPY, L"Copy");
        AppendMenuW(hMenu, MF_STRING, ID_CLEAR, L"Clean Up");
        POINT pt;
        GetCursorPos(&pt);
        TrackPopupMenu(hMenu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, NULL);
        DestroyMenu(hMenu);
        return 0;
    }
    case WM_COMMAND:   // ����Ҽ��˵���Ӧ
        switch (LOWORD(wParam)) {
        case ID_SELECT_ALL:
            SendMessageW(hwnd, EM_SETSEL, 0, -1);
            break;
        case ID_CANCEL:
            SendMessageW(hwnd, EM_SETSEL, -1, 0);
            break;
        case ID_COPY:
            SendMessageW(hwnd, WM_COPY, 0, 0);
            break;
        case ID_CLEAR:
            SetWindowTextW(hwnd, L"");
            break;
        }
        break;
    }
    return DefSubclassProc(hwnd, uMsg, wParam, lParam);
}


DWORD WINAPI OnExitMainWnd(LPVOID lpThreadParameter)
{

    MySetThreadDescription(GetCurrentThread(), EXITTHREADDATA);

    ExtStruct* extSt = (ExtStruct*)lpThreadParameter;

    Log(hRichEdit, L"Process is closing...", INFO);

    // �����Ƚ���ҹ������˳�����
    if (extSt->IsEnabledHook)
    {
        bool status = ModifyFunctionInWinlogon(false, hRichEdit);
        if (status)
            SendMessage(hStatusbar, SB_SETTEXT, 0, (LPARAM)L"Hook Disabled");
    }

    Sleep(extSt->dwWaitMillisecond);

    // �û������ȷ����ť���رմ���
    if (extSt->hwndMain != NULL)
        PostMessageW(extSt->hwndMain, WM_DESTROY, GetCurrentThreadId(), 1);

    return 0;
}


LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    static HDC hdcBackBuffer;
    static HBITMAP hbmBackBuffer;
    static HBITMAP hbmOldBuffer;
    static RECT clientRect;
    static HBITMAP hBackgroundBitmap = NULL;
    static bool IsEnabledHook;

    switch (uMsg) {
    case WM_CREATE: {
        LoadLibraryW(L"Msftedit.dll");

        // ��������
        HFONT hFont = CreateFontW(35, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
            OUT_OUTLINE_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
            VARIABLE_PITCH, L"Segoe UI");

        // ��ӿؼ�����
        hButtonStart = CreateWindowW(L"BUTTON", L"Start",
            WS_VISIBLE | WS_CHILD,
            10, 10, 90, 45,
            hwnd, (HMENU)ID_START,
            NULL, NULL);

        hButtonStop = CreateWindowW(L"BUTTON", L"Stop",
            WS_VISIBLE | WS_CHILD | WS_DISABLED,   // ��ʼ״̬�ǽ�ֹ��
            110, 10, 90, 45,
            hwnd, (HMENU)ID_STOP,
            NULL, NULL);

        hButtonExit = CreateWindowW(L"BUTTON", L"Exit",
            WS_VISIBLE | WS_CHILD,
            210, 10, 90, 45,
            hwnd, (HMENU)ID_EXIT,
            NULL, NULL);

        SendMessageW(hButtonStart, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessageW(hButtonStop, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessageW(hButtonExit, WM_SETFONT, (WPARAM)hFont, TRUE);

        // �������ı���
        hRichEdit = CreateWindowW(MSFTEDIT_CLASS, NULL,
            WS_CHILD | WS_VISIBLE |
            WS_VSCROLL | ES_MULTILINE |
            ES_AUTOVSCROLL,
            10, 60, 260, 200,
            hwnd, NULL,
            NULL, NULL);

        // ���ñ���ɫΪ��ɫ
        SendMessageW(hRichEdit, EM_SETBKGNDCOLOR, FALSE, RGB(30, 30, 30));

        // �����ı���ɫΪ��ɫ
        CHARFORMATW cf = { 0 };
        SendMessageW(hRichEdit, EM_SETCHARFORMAT, SCF_ALL, (LPARAM)&cf);
        cf.cbSize = sizeof(CHARFORMATW);
        cf.dwMask = CFM_COLOR;
        cf.crTextColor = RGB(255, 255, 255);
        SendMessageW(hRichEdit, EM_SETCHARFORMAT, SCF_ALL, (LPARAM)&cf);

        // �������໯�����ڶԸ��ı�������Ҽ��˵������Ʊ༭����
        SetWindowSubclass(hRichEdit, RichEditSubclassProc, 0, 0);

        // ��� �����ڡ���ϵͳ�˵�
        HMENU hSysMenu = GetSystemMenu(hwnd, FALSE);
        AppendMenuW(hSysMenu, MF_SEPARATOR, 0, NULL);
        AppendMenuW(hSysMenu, MF_STRING, ID_ABOUT, L"&About ...(A)");

        // �޸� SetMenuItemInfo �����԰�����ݼ���λͼ
        HICON hIcon = LoadIconW(NULL, IDI_ASTERISK);
        if (hIcon)
        {
            HBITMAP hBitmap = CreateBitmapFromIcon(hIcon, 20, 20);

            MENUITEMINFO mii = { sizeof(MENUITEMINFO) };
            mii.fMask = MIIM_BITMAP | MIIM_ID | MIIM_STATE;
            mii.wID = ID_ABOUT;
            mii.hbmpItem = hBitmap;
            SetMenuItemInfoW(hSysMenu, ID_ABOUT, FALSE, &mii);
            DestroyIcon(hIcon);
        }

        // ����״̬��
        hStatusbar = CreateWindowExW(0, STATUSCLASSNAME, NULL,
            WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
            0, 0, 0, 0, hwnd, NULL, NULL, NULL);
        int parts[] = { 155, -1 };
        SendMessageW(hStatusbar, SB_SETPARTS, sizeof(parts) / sizeof(int), (LPARAM)parts);
        SendMessageW(hStatusbar, SB_SETTEXT, 0, (LPARAM)L"Hook Disabled");

        // ����˫����
        GetClientRect(hwnd, &clientRect);
        HDC hdc = GetDC(hwnd);
        hdcBackBuffer = CreateCompatibleDC(hdc);
        hbmBackBuffer = CreateCompatibleBitmap(hdc, clientRect.right, clientRect.bottom);
        hbmOldBuffer = (HBITMAP)SelectObject(hdcBackBuffer, hbmBackBuffer);
        ReleaseDC(hwnd, hdc);

        // ���ù���ԱȨ��
        if (!IsRunAsAdmin() || !EnableDebugPrivilege())
        {
            Log(hRichEdit, L"The program must be launched as an administrator.", KERROR);
            EnableWindow(hButtonStart, FALSE);
            EnableWindow(hButtonStop, FALSE);
            //EnableWindow(hButtonExit, FALSE);
        }
        // ������ñ�������
        PlayBackgroundMusic();
        break;
    }
    case WM_GETMINMAXINFO: {
        MINMAXINFO* lpMinMax = (MINMAXINFO*)lParam;
        lpMinMax->ptMinTrackSize.x = 580; // ���ô��ڵ���С���
        lpMinMax->ptMinTrackSize.y = 480; // ���ô��ڵ���С�߶�
        return 0;
    }
    case WM_SIZE: {  // ���ͻ������ڴ�С�����仯ʱ����̬�����ؼ���λ��
        GetClientRect(hwnd, &clientRect);
        //SetWindowPos(hRichEdit, NULL, 10, 65, clientRect.right - 20, clientRect.bottom - 175, SWP_NOZORDER);

        // �����󻺳����ߴ�
        HDC hdc = GetDC(hwnd);
        HBITMAP hbmNewBuffer = CreateCompatibleBitmap(hdc, clientRect.right, clientRect.bottom);
        SelectObject(hdcBackBuffer, hbmNewBuffer);
        DeleteObject(hbmBackBuffer);
        hbmBackBuffer = hbmNewBuffer;
        ReleaseDC(hwnd, hdc);

        int btnWidth = 90;
        int btnHeight = 45;
        int spacing = 20;
        int totalWidth = btnWidth * 3 + spacing * 2;
        int startX = (clientRect.right - totalWidth) / 2;
        int startY = 10;

        SetWindowPos(hButtonStart, NULL, startX, startY, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
        SetWindowPos(hButtonStop, NULL, startX + btnWidth + spacing, startY, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
        SetWindowPos(hButtonExit, NULL, startX + 2 * (btnWidth + spacing), startY, 0, 0, SWP_NOSIZE | SWP_NOZORDER);

        int richEditHeight = clientRect.bottom - startY - btnHeight - 45;
        SetWindowPos(hRichEdit, NULL, 10, startY + btnHeight + 10, clientRect.right - 20, richEditHeight, SWP_NOZORDER);
        SetWindowPos(hStatusbar, NULL, 0, clientRect.bottom - 30, clientRect.right, 25, SWP_NOZORDER);

        InvalidateRect(hwnd, NULL, FALSE);
        break;
    }
    case WM_KEYDOWN:
        if (IsWindowVisible((HWND)GetSystemMenu(hwnd, FALSE)) && (wParam == 'A')) {
            SendMessageW(hwnd, WM_SYSCOMMAND, ID_ABOUT, 0);
            return 0;
        }
        break;
    case WM_SYSCOMMAND: {
        if (wParam == ID_ABOUT) {
            // ���ȱ��ݰ�ť״̬�����ð�ť����
            bool isEnBTStart = IsWindowEnabled(hButtonStart);
            bool isEnBTStop = IsWindowEnabled(hButtonStop);

            // ��ʱ���ð�ť
            EnableWindow(hButtonStart, FALSE);
            EnableWindow(hButtonStop, FALSE);

            // �������ڶԻ���
            MessageBoxW(hwnd,
                TOOLABOUTSTRING,
                L"About",
                MB_OK | MB_ICONINFORMATION | MB_APPLMODAL | MB_TOPMOST);

            // �ָ���ť״̬
            EnableWindow(hButtonStart, isEnBTStart);
            EnableWindow(hButtonStop, isEnBTStop);
            return 0;
        }
        return DefWindowProcW(hwnd, uMsg, wParam, lParam);
    }
    case WM_COMMAND: {
        switch (LOWORD(wParam)) {
        case ID_START:
            if (!IsEnabledHook)
            {
                Log(hRichEdit, L"============== Start ==============", INFO);
                bool status = ModifyFunctionInWinlogon(true, hRichEdit);
                Log(hRichEdit, L"===================================", INFO);
                if (status)
                {
                    IsEnabledHook = true;
                    EnableWindow(hButtonStart, FALSE);
                    EnableWindow(hButtonStop, TRUE);
                    SendMessageW(hStatusbar, SB_SETTEXT, 0, (LPARAM)L"Hook Enabled");
                }
                //PlaySoundW(L"MouseClick", NULL, SND_ASYNC);
            }
            break;
        case ID_STOP:
            if (IsEnabledHook)
            {
                Log(hRichEdit, L"============== Stop ==============", INFO);
                bool status = ModifyFunctionInWinlogon(false, hRichEdit);
                Log(hRichEdit, L"==================================", INFO);
                if (status)
                {
                    IsEnabledHook = false;
                    EnableWindow(hButtonStop, FALSE);
                    EnableWindow(hButtonStart, TRUE);
                    SendMessageW(hStatusbar, SB_SETTEXT, 0, (LPARAM)L"Hook Disabled");
                }
                //PlaySoundW(L"MouseClick", NULL, SND_ASYNC);
            }
            break;
        case ID_EXIT:
            PostMessageW(hwnd, WM_CLOSE, 0, 0);
            break;
        }
        break;
    }
    case WM_ERASEBKGND:
        return 1; // ͨ���ƹ�Ĭ�ϲ���������ֹ��˸
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);

        // �ں󻺳����ϻ��Ʊ���
        FillRect(hdcBackBuffer, &clientRect, (HBRUSH)(COLOR_WINDOW + 1));

        // ���м�ָ�ؼ��ռ�ĺ���
        HPEN hPen = CreatePen(PS_SOLID, 1, RGB(0, 0, 0));
        HPEN hOldPen = (HPEN)SelectObject(hdcBackBuffer, hPen);
        MoveToEx(hdcBackBuffer, 10, 60, NULL);
        LineTo(hdcBackBuffer, clientRect.right - 10, 60);
        SelectObject(hdcBackBuffer, hOldPen);
        DeleteObject(hPen);

        // ���󻺳������ǵ�ǰ������
        BitBlt(hdc, 0, 0, clientRect.right, clientRect.bottom, hdcBackBuffer, 0, 0, SRCCOPY);
        EndPaint(hwnd, &ps);
        break;
    }
    case WM_CLOSE:
    {

        // ���ȱ��ݰ�ť״̬�����ð�ť����
        bool isEnBTStart = IsWindowEnabled(hButtonStart);
        bool isEnBTStop = IsWindowEnabled(hButtonStop);


        // ��ȡ���λ��
        POINT cursorPos;
        GetCursorPos(&cursorPos);
        ScreenToClient(hwnd, &cursorPos);

        // ��ȡ���ھ���
        RECT windowRect;
        GetWindowRect(hwnd, &windowRect);

        // ������������
        int titleBarWidth = GetSystemMetrics(SM_CXSIZEFRAME);
        int titleBarHight = GetSystemMetrics(SM_CYSIZEFRAME);

        // ������Ƿ��ڱ������������
        if ((cursorPos.x < (windowRect.left + titleBarWidth) * 0.34)
            && (cursorPos.y < (windowRect.top + titleBarHight) * 0.05))
        {
            // ��ֹ�رմ��ڣ��˲�����ֹ˫��������ͼ�괥���ر�
            return 0;
        }

        // ���ð�ť��2024.07.05 �޸��� BUG ֮ǰ�Ƿ������ж�λ��֮ǰ��
        EnableWindow(hButtonStart, FALSE);
        EnableWindow(hButtonStop, FALSE);

        // ��ʾ�Զ���Ի���
        INT_PTR result = CustomDialog::Show(hwnd, g_hInstance);
        if (result == IDOK) {

            static ExtStruct ext;

            ext.hwndMain = hwnd;
            ext.dwWaitMillisecond = 1000;
            ext.IsEnabledHook = IsEnabledHook;

            CreateThread(nullptr, 0, OnExitMainWnd, &ext, 0, nullptr);
        }
        else {  // �û������ȡ����ť����ִ�йرղ���
            // ���ݱ��ݵ�״̬�ָ���ť
            EnableWindow(hButtonStart, isEnBTStart);
            EnableWindow(hButtonStop, isEnBTStop);
        }
        break;
    }
    case WM_DESTROY: {

        // �رձ�������
        PlaySoundW(NULL, GetModuleHandleW(NULL), SND_SYNC);

        HANDLE hRemoteThread =
            OpenThread(THREAD_QUERY_INFORMATION, FALSE, (DWORD)wParam);

        if (!hRemoteThread)
            break;

        PWSTR lpThreadData = nullptr;
        HRESULT hr = MyGetThreadDescription(GetCurrentThread(), &lpThreadData);
        if (SUCCEEDED(hr) && lpThreadData != nullptr
            && !wcscmp(lpThreadData, EXITTHREADDATA))
        {
            SelectObject(hdcBackBuffer, hbmOldBuffer);
            DeleteObject(hbmBackBuffer);
            DeleteDC(hdcBackBuffer);
            MyFreeThreadDescription(lpThreadData);
            PostQuitMessage(0);
        }
        else {
            if (lpThreadData) MyFreeThreadDescription(lpThreadData);
            Log(hRichEdit, L"Verification of caller thread safety failed.", KERROR);
            if (IDYES == MessageBoxW(NULL,
                L"Are you sure you want to continue closing the window?",
                L"Raise Exception",
                MB_YESNO | MB_SYSTEMMODAL | MB_TOPMOST |
                MB_ICONEXCLAMATION)) {
                SelectObject(hdcBackBuffer, hbmOldBuffer);
                DeleteObject(hbmBackBuffer);
                DeleteDC(hdcBackBuffer);
                PostQuitMessage(0);
            }
        }
        break;
    }
    default:
        return DefWindowProcW(hwnd, uMsg, wParam, lParam);
    }
    return 0;
}
