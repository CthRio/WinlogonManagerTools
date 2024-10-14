
// WMsgControllerDlg.cpp: 实现文件
//

#include "pch.h"
#include "framework.h"
#include "WMsgController.h"
#include "WMsgControllerDlg.h"
#include "afxdialogex.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
//protected:
	//DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnShowAbout();
	afx_msg void OnMenuExitApp();
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

//BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
//ON_COMMAND(ID_32775, &CAboutDlg::OnShowAbout)
//ON_COMMAND(ID_32773, &CAboutDlg::OnMenuExitApp)
//END_MESSAGE_MAP()


// CWMsgControllerDlg 对话框



CWMsgControllerDlg::CWMsgControllerDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_WMSGCONTROLLER_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CWMsgControllerDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CWMsgControllerDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_STN_CLICKED(IDC_STATIC10, &CWMsgControllerDlg::OnStnClickedStatic10)
	ON_STN_CLICKED(IDC_STATIC11, &CWMsgControllerDlg::OnStnClickedStatic11)
	ON_COMMAND(ID_32775, &CAboutDlg::OnShowAbout)
	ON_COMMAND(ID_32773, &CAboutDlg::OnMenuExitApp)
	ON_WM_LBUTTONDBLCLK()
	ON_WM_CLOSE()
END_MESSAGE_MAP()


// CWMsgControllerDlg 消息处理程序

BOOL CWMsgControllerDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	m_Menu.LoadMenu(IDR_MENU1);  //  IDR_MENU1
	//设置静态文本字体大小
	m_static.SubclassDlgItem(IDC_STATIC10, this);
	m_editFont.CreatePointFont(120, _T("Times New Roman"));
	m_static.SetFont(&m_editFont);
	
	//获取对话框上图片控件的句柄
	CStatic* pWnd = (CStatic*)GetDlgItem(IDC_STATIC11);
	
	//设置静态控件窗口风格为位图居中显示
	pWnd->ModifyStyle(0xf, SS_BITMAP | SS_CENTERIMAGE);
	
	//显示图片
	pWnd->SetBitmap((HBITMAP)::LoadImage(NULL,
		_T("C:\\Users\\Lenovo\\Desktop\\二维码.bmp"),  //资源号或本地文件名
		IMAGE_BITMAP,       //装载位图 IMAGE_CURSOR光标 IMAGE_ICON图标
		145,                  //宽度 0为默认大小
		145,                  //高度 像素为单位
		LR_CREATEDIBSECTION | LR_DEFAULTSIZE | LR_LOADFROMFILE));

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	SetMenu(&m_Menu);
	ShowWindow(SW_SHOW);

	// TODO: 在此添加额外的初始化代码

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CWMsgControllerDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CWMsgControllerDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CWMsgControllerDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

void CWMsgControllerDlg::OnStnClickedStatic10()
{
	// TODO: 在此添加控件通知处理程序代码
}


void CWMsgControllerDlg::OnStnClickedStatic11()
{
	// TODO: 在此添加控件通知处理程序代码
	
}


void CWMsgControllerDlg::OnLButtonDblClk(UINT nFlags, CPoint point)
{
	// TODO: 在此添加消息处理程序代码和/或调用默认值
// 将点击点转换为屏幕坐标
	ClientToScreen(&point);

	// 获取控件范围
	CRect controlRect;
	CWnd* pControl = GetDlgItem(IDC_STATIC11);
	if (pControl)
	{
		pControl->GetWindowRect(&controlRect);

		// 判断点击点是否在控件范围内
		if (controlRect.PtInRect(point))
		{
			if (IDYES == MessageBoxW(
				L"你确定要打开网页吗？", L"打开网页", 
				MB_YESNO | MB_ICONINFORMATION))
			{
				ShellExecuteW(NULL, L"open",
					L"https://blog.csdn.net/qq_59075481/article/details/135980850",
					NULL, NULL, SW_SHOWNORMAL);
			}
		}
	}

	CDialogEx::OnLButtonDblClk(nFlags, point);

}


void CAboutDlg::OnShowAbout()
{
	// TODO: 在此添加命令处理程序代码
	//ShellAbout(this->m_hWnd, L"扫雷", L"Sunny/tchenpeng_19890924 @ 126.com", NULL);

	CDialog* dlg = new CDialog;
	dlg->Create(MAKEINTRESOURCEW(IDD_ABOUTBOX));   // 红色部分为对应菜单项的ID
	dlg->ShowWindow(SW_SHOW);
}


void CAboutDlg::OnMenuExitApp()
{
	// TODO: 在此添加命令处理程序代码

	if (MessageBoxW(L"确定要退出吗？", L"提示", 
		MB_YESNO | MB_ICONINFORMATION | MB_DEFBUTTON2) == IDYES) {

		PostMessageW(WM_QUIT, 0, 0);
	}
}


void CWMsgControllerDlg::OnClose()
{
	// TODO: 在此添加消息处理程序代码和/或调用默认值
	if (MessageBoxW(L"确定要退出吗？", L"提示", 
		MB_YESNO | MB_ICONINFORMATION | MB_DEFBUTTON2) == IDYES) {

		CDialogEx::OnClose();
	}
	
}
