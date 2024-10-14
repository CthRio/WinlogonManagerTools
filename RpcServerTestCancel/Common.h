#pragma once
#include <windows.h>
#include <windows.h>
#include <tlhelp32.h>
#include <richedit.h>
#include <CommCtrl.h>
#include <mmsystem.h>
#include <dwmapi.h>
#include <unordered_map>
#include <mutex>
#include <string>
#include <iostream>
#include <string>
#include <sstream>
#include <mmdeviceapi.h>
#include <endpointvolume.h>
#include <audiopolicy.h>
#include "resource.h"


static HINSTANCE g_hInstance;
static HWND hRichEdit;
static HWND hButtonStart, hButtonStop, hButtonExit, hStatusbar;