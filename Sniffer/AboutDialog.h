#pragma once

class CAboutDialog : public CDialogImpl<CAboutDialog>
{
public:
	CAboutDialog();
	~CAboutDialog();

	enum { IDD = IDD_ABOUTBOX };

	BEGIN_MSG_MAP(CAboutDialog)
		MESSAGE_HANDLER(WM_INITDIALOG, OnInitDialog)
		COMMAND_ID_HANDLER(IDOK, OnOK)
		//COMMAND_ID_HANDLER(IDCANCEL, OnCancel)
	END_MSG_MAP()
	LRESULT OnInitDialog(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/);
	LRESULT OnOK(WORD /*wNotifyCode*/, WORD wID, HWND /*hWndCtl*/, BOOL& /*bHandled*/);
};

