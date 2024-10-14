#pragma once
#include "Common.h"

const wchar_t* MUTEX_NAME = L"Global\\WMHProgramMutex";
const wchar_t* PIPE_NAME = L"\\\\.\\pipe\\StartupManagerPipe";

bool VerifyStartup();
void RunTestCheck();

LRESULT CALLBACK RichEditSubclassProc(HWND hwnd, UINT uMsg, 
	WPARAM wParam, LPARAM lParam, UINT_PTR, DWORD_PTR);

DWORD WINAPI OnExitMainWnd(LPVOID lpThreadParameter);

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);