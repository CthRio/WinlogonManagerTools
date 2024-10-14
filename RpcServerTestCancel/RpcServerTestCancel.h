#pragma once
#ifndef __RPCSERVERTESTCANCEL_H__
#define __RPCSERVERTESTCANCEL_H__

#include "Common.h"
#include "ReConfig.h"

#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "Comctl32.lib")
#pragma comment(lib, "dwmapi.lib")

#pragma comment(linker,"\"/manifestdependency:type='win32' "\
						"name='Microsoft.Windows.Common-Controls' "\
						"version='6.0.0.0' processorArchitecture='*' "\
						"publicKeyToken='6595b64144ccf1df' language='*'\"")

#define EXITTHREADDATA      L"ExitMainThread"
#define TOOLAPPTITLENAME    L"Winlogon RpcServerTestCancel Hook"
#define TOOLAPPCLASSNAME    L"WMsgTestCancelHookWindowClass"
#define TOOLABOUTSTRING     L"Winlogon RpcServerTestCancel Hook\nAuthor:\tLianYou516\nVersion:\t1.0.0.3"
#define MAX_THREAD_NAME_LENGTH 256


struct ExtStruct {        // 进程退出处理线程
	HWND hwndMain;
	DWORD dwWaitMillisecond;
	bool IsEnabledHook;
};

enum LogLevel { INFO, KERROR, WARNING };

bool IsRunAsAdmin();
bool EnableDebugPrivilege();

void AppendText(HWND hEdit, const std::wstring& text);
void Log(HWND hEdit, const std::wstring& message, LogLevel level);
bool ModifyFunctionInWinlogon(bool enable, HWND hEdit);
HBITMAP CreateBitmapFromIcon(HICON hIcon, int width, int height);
BOOL SetCurrentProcessVolume(DWORD dwVolume, BOOL IsMixer/*TRUE*/);
void getMusicCodeFromConfig(int* MusicCode, int* MusicVolume);
void PlayBackgroundMusic();
HRESULT MySetThreadDescription(HANDLE hThread, PCWSTR lpThreadDescription);
HRESULT MyGetThreadDescription(HANDLE hThread, PWSTR* ppszThreadDescription);
void MyFreeThreadDescription(PWSTR pszThreadDescription);

#endif