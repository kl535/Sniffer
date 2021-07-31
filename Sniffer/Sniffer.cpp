// Sniffer.cpp : 定义应用程序的入口点。
//

#include "stdafx.h"
#include "Sniffer.h"


int APIENTRY WinMain(HINSTANCE hInstance,
	HINSTANCE hPrevInstance,
	LPSTR     lpCmdLine,
	int       nCmdShow)
{
	//InitCommonControls();
	// Initialize COM.
	HRESULT comInit = CoInitializeEx(0, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
	WSADATA wsd;
	WSAStartup(MAKEWORD(2, 1), &wsd);
#ifdef _DEBUG
	GUID guid;
	_Module.Init(NULL, hInstance, &guid);
#else
	_Module.Init(NULL, hInstance);
#endif

	CMyWin win;
	win.Create(NULL, CRect(0, 0, 1200, 900), _T("Sniffer"), WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN );
	win.CenterWindow();
	win.ShowWindow(SW_SHOW);
	MSG msg;
	while (GetMessage(&msg, NULL, 0, 0)>0)
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
	_Module.Term();
	WSACleanup();
	// Uninitialize COM.
	if (SUCCEEDED(comInit))
	{
		CoUninitialize();
	}
	return 0;
}
