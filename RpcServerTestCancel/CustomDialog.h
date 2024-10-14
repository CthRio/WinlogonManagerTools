#pragma once
#ifndef CUSTOMDIALOG_H
#define CUSTOMDIALOG_H

#include "Common.h"

class CustomDialog {
public:
    static INT_PTR CALLBACK DialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);

    static INT_PTR Show(HWND hwndParent, HINSTANCE hInstance);

private:
    static HICON hIconConfirm;

    static BOOL OnInitDialog(HWND hwndDlg);
    static void OnCommand(HWND hwndDlg, WPARAM wParam, LPARAM lParam);
    static void OnDestroy(HWND hwndDlg);
};

HICON CustomDialog::hIconConfirm = NULL;

INT_PTR CustomDialog::Show(HWND hwndParent, HINSTANCE hInstance) {
    return DialogBoxW(hInstance, MAKEINTRESOURCEW(IDD_CUSTOM_DIALOG), hwndParent, DialogProc);
}

INT_PTR CALLBACK CustomDialog::DialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_INITDIALOG:
        return CustomDialog::OnInitDialog(hwndDlg);

    case WM_COMMAND:
        CustomDialog::OnCommand(hwndDlg, wParam, lParam);
        return TRUE;

    case WM_CLOSE:
        EndDialog(hwndDlg, IDCANCEL);
        return TRUE;

    case WM_DESTROY:
        CustomDialog::OnDestroy(hwndDlg);
        return TRUE;
    }
    return FALSE;
}

BOOL CustomDialog::OnInitDialog(HWND hwndDlg) {

    SetWindowLongW(hwndDlg, GWL_EXSTYLE, GetWindowLongW(hwndDlg, GWL_EXSTYLE) | WS_EX_LAYERED);
    SetLayeredWindowAttributes(hwndDlg, 0, (255 * 90) / 100, LWA_ALPHA);

    // 设置图标
    SendMessageW(hwndDlg, WM_SETICON, ICON_SMALL, (LPARAM)hIconConfirm);
    SendMessageW(hwndDlg, WM_SETICON, ICON_BIG, (LPARAM)hIconConfirm);

    return TRUE;
}

void CustomDialog::OnCommand(HWND hwndDlg, WPARAM wParam, LPARAM lParam) {
    switch (LOWORD(wParam)) {
    case IDOK:
        EndDialog(hwndDlg, IDOK);
        break;

    case IDCANCEL:
        EndDialog(hwndDlg, IDCANCEL);
        break;
    }
}

void CustomDialog::OnDestroy(HWND hwndDlg) {
    // 清理资源
    DestroyIcon(hIconConfirm);
}

#endif // CUSTOMDIALOG_H
