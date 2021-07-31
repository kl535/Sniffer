#include "stdafx.h"
#include "AboutDialog.h"


CAboutDialog::CAboutDialog()
{
}


CAboutDialog::~CAboutDialog()
{
}

LRESULT CAboutDialog::OnInitDialog(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/)
{
	return 0;
}

LRESULT CAboutDialog::OnOK(WORD /*wNotifyCode*/, WORD wID, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
{
	EndDialog(wID);
	return 0;
}