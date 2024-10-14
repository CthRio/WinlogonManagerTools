#include "RpcServerTestCancel.h"
#include "CustomDialog.h"
#include "main.h"


int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) {

    if (!VerifyStartup()) {
        MessageBoxW(NULL, L"Error: This program can only be run from the startup manager.",
            L"Message", MB_OK | MB_ICONWARNING | MB_APPLMODAL | MB_TOPMOST);
        exit(0);
        return 1; // 非正常退出
    }

    RunTestCheck(); // 检查是否已在运行

    g_hInstance = hInstance;

    //SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);

    const wchar_t CLASS_NAME[] = TOOLAPPCLASSNAME;

    WNDCLASS wc = {};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;

    // 加载不同尺寸的图标资源
    HICON hIcon48 = (HICON)LoadImageW(hInstance,
        MAKEINTRESOURCEW(IDI_ICON1), IMAGE_ICON,
        48, 48, LR_DEFAULTCOLOR);
    HICON hIcon32 = (HICON)LoadImageW(hInstance,
        MAKEINTRESOURCEW(IDI_ICON2), IMAGE_ICON,
        32, 32, LR_DEFAULTCOLOR);

    // 设置窗口类图标
    wc.hIcon = hIcon32;     // 设置小图标

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


    // 获取屏幕尺寸
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);

    // 获取窗口尺寸
    RECT windowRect;
    GetWindowRect(hwnd, &windowRect);
    int windowWidth = windowRect.right - windowRect.left;
    int windowHeight = windowRect.bottom - windowRect.top;

    // 计算窗口居中位置
    int posX = (screenWidth - windowWidth) / 2;
    int posY = (screenHeight - windowHeight) / 2;

    // 设置窗口位置
    SetWindowPos(hwnd, NULL, posX, posY, 0, 0, SWP_NOSIZE | SWP_NOZORDER);

    // 设置窗口图标
    SendMessageW(hwnd, WM_SETICON, ICON_BIG, (LPARAM)hIcon48);   // 设置大图标
    SendMessageW(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)hIcon32); // 设置小图标

    BOOL value = TRUE;
    ::DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, &value, sizeof(value));

    // 设置分层窗口和透明度
    SetWindowLongW(hwnd, GWL_EXSTYLE, GetWindowLongW(hwnd, GWL_EXSTYLE) | WS_EX_LAYERED);
    SetLayeredWindowAttributes(hwnd, 0, (255 * 75) / 100, LWA_ALPHA);

    // 显示窗口
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
    // 连接到命名管道
    HANDLE hPipe = CreateFileW(
        PIPE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, 0, NULL);

    if (hPipe == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to connect to named pipe." << std::endl;
        return false;
    }

    // 发送验证请求
    const wchar_t* request = L"Verification request from program";
    DWORD bytesWritten;
    if (!WriteFile(hPipe, request, wcslen(request) * sizeof(wchar_t), &bytesWritten, NULL)) {
        std::cerr << "Failed to write to named pipe." << std::endl;
        CloseHandle(hPipe);
        return false;
    }

    // 接收确认信息
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
            // 通过返回0阻止键盘删除操作
            return 0;
        case 'A':
            if (GetKeyState(VK_CONTROL) & 0x8000) {
                // 按下Ctrl+A时选择所有文本
                SendMessageW(hwnd, EM_SETSEL, 0, -1);
                return 0;
            }
            break;
        }
        break;
    case WM_CHAR:  // 阻止英文字符输入
    case WM_IME_COMPOSITION: // 阻止IME（输入法编辑器）合成
    case WM_PASTE:
        return 0; // 阻止文本输入（粘贴）
    case WM_RBUTTONDOWN: {  // 创建右键菜单
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
    case WM_COMMAND:   // 添加右键菜单响应
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

    // 必须先解除挂钩才能退出进程
    if (extSt->IsEnabledHook)
    {
        bool status = ModifyFunctionInWinlogon(false, hRichEdit);
        if (status)
            SendMessage(hStatusbar, SB_SETTEXT, 0, (LPARAM)L"Hook Disabled");
    }

    Sleep(extSt->dwWaitMillisecond);

    // 用户点击了确定按钮，关闭窗口
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

        // 创建字体
        HFONT hFont = CreateFontW(35, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
            OUT_OUTLINE_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
            VARIABLE_PITCH, L"Segoe UI");

        // 添加控件窗口
        hButtonStart = CreateWindowW(L"BUTTON", L"Start",
            WS_VISIBLE | WS_CHILD,
            10, 10, 90, 45,
            hwnd, (HMENU)ID_START,
            NULL, NULL);

        hButtonStop = CreateWindowW(L"BUTTON", L"Stop",
            WS_VISIBLE | WS_CHILD | WS_DISABLED,   // 初始状态是禁止的
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

        // 创建富文本框
        hRichEdit = CreateWindowW(MSFTEDIT_CLASS, NULL,
            WS_CHILD | WS_VISIBLE |
            WS_VSCROLL | ES_MULTILINE |
            ES_AUTOVSCROLL,
            10, 60, 260, 200,
            hwnd, NULL,
            NULL, NULL);

        // 设置背景色为暗色
        SendMessageW(hRichEdit, EM_SETBKGNDCOLOR, FALSE, RGB(30, 30, 30));

        // 设置文本颜色为亮色
        CHARFORMATW cf = { 0 };
        SendMessageW(hRichEdit, EM_SETCHARFORMAT, SCF_ALL, (LPARAM)&cf);
        cf.cbSize = sizeof(CHARFORMATW);
        cf.dwMask = CFM_COLOR;
        cf.crTextColor = RGB(255, 255, 255);
        SendMessageW(hRichEdit, EM_SETCHARFORMAT, SCF_ALL, (LPARAM)&cf);

        // 窗口子类化，便于对富文本框添加右键菜单和限制编辑操作
        SetWindowSubclass(hRichEdit, RichEditSubclassProc, 0, 0);

        // 添加 “关于”到系统菜单
        HMENU hSysMenu = GetSystemMenu(hwnd, FALSE);
        AppendMenuW(hSysMenu, MF_SEPARATOR, 0, NULL);
        AppendMenuW(hSysMenu, MF_STRING, ID_ABOUT, L"&About ...(A)");

        // 修改 SetMenuItemInfo 调用以包含快捷键和位图
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

        // 创建状态栏
        hStatusbar = CreateWindowExW(0, STATUSCLASSNAME, NULL,
            WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
            0, 0, 0, 0, hwnd, NULL, NULL, NULL);
        int parts[] = { 155, -1 };
        SendMessageW(hStatusbar, SB_SETPARTS, sizeof(parts) / sizeof(int), (LPARAM)parts);
        SendMessageW(hStatusbar, SB_SETTEXT, 0, (LPARAM)L"Hook Disabled");

        // 启用双缓冲
        GetClientRect(hwnd, &clientRect);
        HDC hdc = GetDC(hwnd);
        hdcBackBuffer = CreateCompatibleDC(hdc);
        hbmBackBuffer = CreateCompatibleBitmap(hdc, clientRect.right, clientRect.bottom);
        hbmOldBuffer = (HBITMAP)SelectObject(hdcBackBuffer, hbmBackBuffer);
        ReleaseDC(hwnd, hdc);

        // 启用管理员权限
        if (!IsRunAsAdmin() || !EnableDebugPrivilege())
        {
            Log(hRichEdit, L"The program must be launched as an administrator.", KERROR);
            EnableWindow(hButtonStart, FALSE);
            EnableWindow(hButtonStop, FALSE);
            //EnableWindow(hButtonExit, FALSE);
        }
        // 最后启用背景音乐
        PlayBackgroundMusic();
        break;
    }
    case WM_GETMINMAXINFO: {
        MINMAXINFO* lpMinMax = (MINMAXINFO*)lParam;
        lpMinMax->ptMinTrackSize.x = 580; // 设置窗口的最小宽度
        lpMinMax->ptMinTrackSize.y = 480; // 设置窗口的最小高度
        return 0;
    }
    case WM_SIZE: {  // 当客户区窗口大小发生变化时，动态调整控件的位置
        GetClientRect(hwnd, &clientRect);
        //SetWindowPos(hRichEdit, NULL, 10, 65, clientRect.right - 20, clientRect.bottom - 175, SWP_NOZORDER);

        // 调整后缓冲区尺寸
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
            // 首先备份按钮状态并禁用按钮操作
            bool isEnBTStart = IsWindowEnabled(hButtonStart);
            bool isEnBTStop = IsWindowEnabled(hButtonStop);

            // 暂时禁用按钮
            EnableWindow(hButtonStart, FALSE);
            EnableWindow(hButtonStop, FALSE);

            // 弹出关于对话框
            MessageBoxW(hwnd,
                TOOLABOUTSTRING,
                L"About",
                MB_OK | MB_ICONINFORMATION | MB_APPLMODAL | MB_TOPMOST);

            // 恢复按钮状态
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
        return 1; // 通过绕过默认擦除背景防止闪烁
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);

        // 在后缓冲区上绘制背景
        FillRect(hdcBackBuffer, &clientRect, (HBRUSH)(COLOR_WINDOW + 1));

        // 画中间分割控件空间的黑线
        HPEN hPen = CreatePen(PS_SOLID, 1, RGB(0, 0, 0));
        HPEN hOldPen = (HPEN)SelectObject(hdcBackBuffer, hPen);
        MoveToEx(hdcBackBuffer, 10, 60, NULL);
        LineTo(hdcBackBuffer, clientRect.right - 10, 60);
        SelectObject(hdcBackBuffer, hOldPen);
        DeleteObject(hPen);

        // 将后缓冲区覆盖到前缓冲区
        BitBlt(hdc, 0, 0, clientRect.right, clientRect.bottom, hdcBackBuffer, 0, 0, SRCCOPY);
        EndPaint(hwnd, &ps);
        break;
    }
    case WM_CLOSE:
    {

        // 首先备份按钮状态并禁用按钮操作
        bool isEnBTStart = IsWindowEnabled(hButtonStart);
        bool isEnBTStop = IsWindowEnabled(hButtonStop);


        // 获取光标位置
        POINT cursorPos;
        GetCursorPos(&cursorPos);
        ScreenToClient(hwnd, &cursorPos);

        // 获取窗口矩形
        RECT windowRect;
        GetWindowRect(hwnd, &windowRect);

        // 计算标题栏宽度
        int titleBarWidth = GetSystemMetrics(SM_CXSIZEFRAME);
        int titleBarHight = GetSystemMetrics(SM_CYSIZEFRAME);

        // 检查光标是否在标题栏左边区域
        if ((cursorPos.x < (windowRect.left + titleBarWidth) * 0.34)
            && (cursorPos.y < (windowRect.top + titleBarHight) * 0.05))
        {
            // 禁止关闭窗口，此操作防止双击标题栏图标触发关闭
            return 0;
        }

        // 禁用按钮（2024.07.05 修复此 BUG 之前是放在了判断位置之前）
        EnableWindow(hButtonStart, FALSE);
        EnableWindow(hButtonStop, FALSE);

        // 显示自定义对话框
        INT_PTR result = CustomDialog::Show(hwnd, g_hInstance);
        if (result == IDOK) {

            static ExtStruct ext;

            ext.hwndMain = hwnd;
            ext.dwWaitMillisecond = 1000;
            ext.IsEnabledHook = IsEnabledHook;

            CreateThread(nullptr, 0, OnExitMainWnd, &ext, 0, nullptr);
        }
        else {  // 用户点击了取消按钮，不执行关闭操作
            // 根据备份的状态恢复按钮
            EnableWindow(hButtonStart, isEnBTStart);
            EnableWindow(hButtonStop, isEnBTStop);
        }
        break;
    }
    case WM_DESTROY: {

        // 关闭背景音乐
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
