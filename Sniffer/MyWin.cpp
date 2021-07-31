#include "stdafx.h"
#include "MyWin.h"
#include "AboutDialog.h"
#include "Firewall.h"

enum list_col
{
	col_id = 0,
	col_proto,
	col_sr,
	col_lport,
	col_rport,
	col_flag,
	col_len,
	col_stamp
};

CMyWin::CMyWin()
{
	m_wLastSend = m_wLastRecv = 0;
}


CMyWin::~CMyWin()
{
}

LRESULT CMyWin::OnCreate(UINT uMsg, WPARAM wp, LPARAM lp, BOOL &b)
{
	PassFirewall();
	m_cap.Init();
	InitCtrl();
	//FindNetAdapter();
	//Sniffer();
	m_bBegin = false;
	return 0;
}

LRESULT CMyWin::OnClose(UINT uMsg, WPARAM wp, LPARAM lp, BOOL &b)
{
	DestroyWindow();
	PostQuitMessage(0);
	return 0;
}

LRESULT CMyWin::OnSize(UINT uMsg, WPARAM wp, LPARAM lp, BOOL &b)
{
	CRect r;
	GetClientRect(&r);
	if(m_tree.IsWindow())
	{
		CRect rTree = r;
		rTree.right = 200;
		m_tree.SetWindowPos(NULL, &rTree, SWP_NOZORDER);
	}
	if (m_list.IsWindow())
	{
		CRect rList = r;
		rList.left = 200;
		rList.bottom = r.bottom / 2;
		m_list.SetWindowPos(NULL, &rList, SWP_NOZORDER);
	}
	if (m_edit.IsWindow())
	{
		CRect rEdit = r;
		rEdit.left = 200;
		rEdit.top = r.bottom / 2;
		m_edit.SetWindowPos(NULL, &rEdit, SWP_NOZORDER);
	}
	return 0;
}

//LRESULT CMyWin::OnCommand(UINT uMsg, WPARAM wp, LPARAM lp, BOOL &b)
//{
//	con << "uMsg=" << uMsg << "  wp=" << wp << "  lp=" << lp << endl;
//	return 0;
//}

LRESULT CMyWin::OnExit(WORD code, WORD id, HWND h, BOOL &b)
{
	PostMessage(WM_CLOSE);
	return 0;
}

LRESULT CMyWin::OnAbout(WORD code, WORD id, HWND h, BOOL &b)
{
	CAboutDialog dlg;
	dlg.DoModal();
	return 0;
}

void CMyWin::InitData()
{
	m_tree.DeleteAllItems();
	m_list.DeleteAllItems();
	m_edit.SetWindowText(_T(""));
	m_nLastID = -1;
}

void CMyWin::InitCtrl()
{
	HICON hIcon = LoadIcon(_Module.m_hInstResource, (LPCTSTR)IDI_SNIFFER);
	SetIcon(hIcon);

	CString str;
	GetWindowText(str);
	str += _T(" - ");
	str += m_cap.HostName;
	SetWindowText(str);

	m_menu.LoadMenu(IDC_SNIFFER);
	SetMenu(m_menu);

	CRect r;
	m_tree.Create(m_hWnd, &r, NULL, WS_CHILD | WS_VISIBLE | WS_BORDER | TVS_HASBUTTONS | TVS_HASLINES | TVS_LINESATROOT | TVS_DISABLEDRAGDROP | TVS_SHOWSELALWAYS, 0, ID_TREEVIEW); // WS_HSCROLL
	m_list.Create(m_hWnd, &r, NULL, WS_CHILD | WS_VISIBLE | WS_BORDER | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS, 0, ID_LISTVIEW);
	m_edit.Create(m_hWnd, &r, NULL, WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE | ES_READONLY | ES_OEMCONVERT);
	m_list.SetExtendedListViewStyle(LVS_EX_FULLROWSELECT);

	LOGFONT logfont;
	memset(&logfont, 0, sizeof(LOGFONT));
	lstrcpy(logfont.lfFaceName, _T("Fixedsys"));
	logfont.lfHeight = 12;
	logfont.lfCharSet = DEFAULT_CHARSET;
	logfont.lfPitchAndFamily = FIXED_PITCH;
	m_hFont = CreateFontIndirect(&logfont);
	m_edit.SetFont(m_hFont);
	
	CString strColumn[] = {_T("ID"), _T("Protocol"), _T("Send | Recv"), _T("Local Port"), _T("Remote Port"), _T("Flag"), _T("Len"), _T("Time Stamp") };
	int i = 0;
	for (auto str : strColumn)
	{
		m_list.InsertColumn(i++, str, 0, 100);
	}

	std::vector<AdapterInfo> vAdapter;
	m_cap.GetAdapters(vAdapter);
	int nIndex = 0;
	m_nAdapterSel = 0;
	CMenuHandle m;
	m.CreatePopupMenu();
	bool bSel = false;
	for (auto adapter : vAdapter)
	{
		str.Format(_T("%s(%s)"), adapter.strName, adapter.strIP);
		m.AppendMenu(MF_BYPOSITION, ID_ADAPTER + nIndex, str);
		if ((!bSel) && adapter.bGate)
		{
			bSel = true;
			m_nAdapterSel = nIndex;
		}
		nIndex++;
	}
	m.CheckMenuItem(ID_ADAPTER + m_nAdapterSel, MF_CHECKED);
	m_menu.ModifyMenu(1, MF_BYPOSITION, m, _T("&Adapters"));

	m_cap.SelectAdapter(m_nAdapterSel);
}

LRESULT CMyWin::OnAdapter(WORD code, WORD id, HWND h, BOOL &b)
{
	int nIndex = id - ID_ADAPTER;
	if (m_nAdapterSel == nIndex)
	{
		return 0;
	}
	CMenuHandle m = m_menu.GetSubMenu(1);
	m.CheckMenuItem(ID_ADAPTER + m_nAdapterSel, MF_UNCHECKED);
	m_nAdapterSel = nIndex;
	m.CheckMenuItem(ID_ADAPTER + m_nAdapterSel, MF_CHECKED);
	m_cap.SelectAdapter(m_nAdapterSel);
	return 0;
}

LRESULT CMyWin::OnBegin(WORD code, WORD id, HWND h, BOOL &b)
{
	CMenuHandle m = m_menu.GetSubMenu(0);
	m.EnableMenuItem(0, MF_BYPOSITION | MF_DISABLED);
	m.EnableMenuItem(1, MF_BYPOSITION | MF_ENABLED);
	InitData();
	m_cap.Begin();
	m_bBegin = true;
	return 0;
}

LRESULT CMyWin::OnStop(WORD code, WORD id, HWND h, BOOL &b)
{
	CMenuHandle m = m_menu.GetSubMenu(0);
	m.EnableMenuItem(0, MF_BYPOSITION | MF_ENABLED);
	m.EnableMenuItem(1, MF_BYPOSITION | MF_DISABLED);
	m.EnableMenuItem(4, MF_BYPOSITION | MF_ENABLED);
	m_cap.Stop();
	CleanData();
	m_cap.GetPackages(m_vPackage);
	LoadData();
	m_bBegin = false;
	return 0;
}

void CMyWin::CleanData()
{
	for (auto pack : m_vPackage)
	{
		delete[]pack.buff;
	}
	m_vPackage.clear();
}

void CMyWin::LoadData()
{
	HTREEITEM hRoot = NULL;
	in_addr localAddr, remoteAddr;
	HTREEITEM hItem = NULL;
	memset(&localAddr, 1, sizeof(in_addr));

	for (auto pack : m_vPackage)
	{
		if (memcmp(&m_cap.m_localAddr, &pack.localAddr, sizeof(in_addr)) == 0)
		{
			if (memcmp(&localAddr, &pack.localAddr, sizeof(in_addr)))
			{
				memset(&remoteAddr, 1, sizeof(in_addr));
				localAddr = pack.localAddr;
				hRoot = m_tree.InsertItem(CString(inet_ntoa(localAddr)), TVI_ROOT, NULL);
				m_tree.SetItemData(hRoot, *(DWORD*)&localAddr);
			}
			if (memcmp(&remoteAddr, &pack.remoteAddr, sizeof(in_addr)))
			{
				remoteAddr = pack.remoteAddr;
				hItem = m_tree.InsertItem(CString(inet_ntoa(remoteAddr)), hRoot, TVI_LAST);
				m_tree.SetItemData(hItem, *(DWORD*)&remoteAddr);
			}
		}
	}
	memset(&localAddr, 1, sizeof(in_addr));
	for (auto pack : m_vPackage)
	{
		if (memcmp(&m_cap.m_localAddr, &pack.localAddr, sizeof(in_addr)) != 0)
		{
			if (memcmp(&localAddr, &pack.localAddr, sizeof(in_addr)))
			{
				memset(&remoteAddr, 1, sizeof(in_addr));
				localAddr = pack.localAddr;
				hRoot = m_tree.InsertItem(CString(inet_ntoa(localAddr)), TVI_ROOT, NULL);
				m_tree.SetItemData(hRoot, *(DWORD*)&localAddr);
			}
			if (memcmp(&remoteAddr, &pack.remoteAddr, sizeof(in_addr)))
			{
				remoteAddr = pack.remoteAddr;
				hItem = m_tree.InsertItem(CString(inet_ntoa(remoteAddr)), hRoot, TVI_LAST);
				m_tree.SetItemData(hItem, *(DWORD*)&remoteAddr);
			}
		}
	}
}

LRESULT CMyWin::OnLoad(WORD code, WORD id, HWND h, BOOL &b)
{
	if (m_bBegin)
	{
		BOOL b;
		OnStop(0, 0, 0, b);
	}
	TCHAR szFile[MAX_PATH] = { 0 };
	OPENFILENAME ofn;
	memset(&ofn, 0, sizeof(OPENFILENAME));
	ofn.lStructSize = sizeof(OPENFILENAME);
	ofn.hwndOwner = m_hWnd;
	ofn.lpstrFilter = _T("Sniffer Files(*.snf)\0*.snf\0\0");
	ofn.lpstrFile = szFile;
	ofn.nMaxFile = sizeof(szFile);
	ofn.lpstrDefExt = _T("snf");
	ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
	if (GetOpenFileName(&ofn))
	{
		//con << szFile << "\n";
		USES_CONVERSION;
		std::string str(T2A(szFile));
		std::ifstream istm(str, std::ios::binary);
		if (istm.is_open())
		{
			CleanData();
			InitData();

			int nLen;
			istm.read((char*)&nLen, sizeof(int));
			for (int i = 0; i < nLen; i++)
			{
				RawPackage pack;
				istm.read((char*)&pack, sizeof(RawPackage)-sizeof(BYTE *));
				pack.buff = new BYTE[pack.buffLen];
				istm.read((char*)pack.buff, pack.buffLen);
				m_vPackage.push_back(pack);
			}
			istm.close();

			LoadData();
		}
	}
	return 0;
}

LRESULT CMyWin::OnSave(WORD code, WORD id, HWND h, BOOL &b)
{
	if (m_bBegin)
	{
		BOOL b;
		OnStop(0, 0, 0, b);
	}
	TCHAR szFile[MAX_PATH] = {0};
	OPENFILENAME ofn;
	memset(&ofn, 0, sizeof(OPENFILENAME));
	ofn.lStructSize = sizeof(OPENFILENAME);
	ofn.hwndOwner = m_hWnd;
	ofn.lpstrFilter = _T("Sniffer Files(*.snf)\0*.snf\0\0");
	ofn.lpstrFile = szFile;
	ofn.nMaxFile = sizeof(szFile);
	ofn.lpstrDefExt = _T("snf");
	ofn.Flags = OFN_OVERWRITEPROMPT;
	if (GetSaveFileName(&ofn))
	{
		//con << szFile << "\n";
		USES_CONVERSION;
		std::string str(T2A(szFile));
		std::ofstream ostm(str, std::ios::binary|std::ios::ate);
		if (ostm.is_open())
		{
			int nLen = m_vPackage.size();
			ostm.write((char*)&nLen, sizeof(int));
			for (auto pack : m_vPackage)
			{
				ostm.write((char*)&pack, sizeof(RawPackage)- sizeof(BYTE *));
				ostm.write((char*)pack.buff, pack.buffLen);
			}
			ostm.close();
		}
	}

	return 0;
}

LRESULT CMyWin::OnTreeview(int cID, LPNMHDR pNMH, BOOL &b)
{
	HTREEITEM hItem = m_tree.GetSelectedItem();
	if (hItem)
	{
		HTREEITEM hParent = m_tree.GetParentItem(hItem);
		if (hParent)
		{
			m_list.DeleteAllItems();

			CString str;
			int nItem = -1;
			DWORD dwData1 = m_tree.GetItemData(hItem);
			DWORD dwData2 = m_tree.GetItemData(hParent);
			std::for_each(m_vPackage.begin(), m_vPackage.end(), [&](RawPackage &pack)
			{
				if ((memcmp(&dwData1, &pack.remoteAddr, sizeof(DWORD)) == 0)
					&& (memcmp(&dwData2, &pack.localAddr, sizeof(DWORD)) == 0))
				{
					//CString strColumn[] = { _T("Protocol"), _T("Send / Recv"), _T("Local Port"), _T("Remote Port"), _T("Flag"), _T("Len"), _T("Time Stamp") };
					LPIP pIP = (LPIP)pack.buff;
					int iplen = (pIP->HdrLen & 0xf) * 4;
					LPTCP pTCP = (LPTCP)((LPBYTE)pIP + iplen);

					bool bFilter = false;
					if (pack.bSend)
					{
						if (m_wLastSend == pIP->ID)
						{
							bFilter = true;
						}
						else
						{
							m_wLastSend = pIP->ID;
						}
					}
					else
					{
						if (m_wLastRecv == pIP->ID)
						{
							bFilter = true;
						}
						else
						{
							m_wLastRecv = pIP->ID;
						}
					}

					if (!bFilter)
					{
						// Protocol
						str.Format(_T("%d"), pack.nID);
						nItem = m_list.InsertItem(nItem + 1, str);
						m_list.SetItemData(nItem, pack.nID);

						// protocol
						str = ProtocolStr(pIP->Protocol);
						m_list.SetItemText(nItem, col_proto, str);

						// Send / Recv
						if (pack.bSend)
						{
							str = _T("  📤");
						}
						else
						{
							str = _T("            📥");
						}
						m_list.SetItemText(nItem, col_sr, str);

						// port and flag and length
						int tcplen = 0;
						switch (pIP->Protocol)
						{
						case IPPROTO_TCP:
						{
							str.Empty();
							BYTE f = pTCP->Flags;
							int mask[] = { 1, 2, 4, 8, 16, 32, 64, 128 };
							CString strFlag[] = { _T("FIN"), _T("SYN"), _T("RST"), _T("PSH"), _T("ACK"), _T("URG"), _T("ECE"), _T("CWR") };
							for (int i = 7; i >= 0; i--)
							{
								if (f & mask[i])
								{
									if (str.GetLength() > 0)
									{
										str += _T("/");
									}
									str += strFlag[i];
								}
							}
							m_list.SetItemText(nItem, col_flag, str);
							tcplen = (pTCP->DataOff >> 4) * 4;
						}
						case IPPROTO_UDP:
						{
							CString strHostPort, strRemotePort;
							if (pack.bSend)
							{
								strHostPort.Format(_T("%d"), ntohs(pTCP->SrcPort));
								strRemotePort.Format(_T("%d"), ntohs(pTCP->DstPort));
							}
							else
							{
								strHostPort.Format(_T("%d"), ntohs(pTCP->DstPort));
								strRemotePort.Format(_T("%d"), ntohs(pTCP->SrcPort));
							}
							m_list.SetItemText(nItem, col_lport, strHostPort);
							m_list.SetItemText(nItem, col_rport, strRemotePort);
							break;
						}
						default:
						{

							break;
						}
						}
						if (pIP->Protocol == IPPROTO_UDP)
						{
							tcplen = sizeof(UDP);
						}
						// length
						int nTotalLen = ntohs(pIP->TotalLen);
						iplen += tcplen;
						if (nTotalLen - iplen > 0)
						{
							str.Format(_T("%d+%d"), iplen, nTotalLen - iplen);
						}
						else
						{
							str.Format(_T("%d"), nTotalLen);
						}
						m_list.SetItemText(nItem, col_len, str);

						// time stamp
						str.Format(_T("%.3f"), pack.nTimestamp * 1.0f / CLOCKS_PER_SEC);
						m_list.SetItemText(nItem, col_stamp, str);
					}
				}
			});
		}
	}
	return 0;
}

LRESULT CMyWin::OnListview(int cID, LPNMHDR pNMH, BOOL &b)
{
	//con << pNMH->code << "\n";
	int nItem = m_list.GetSelectedIndex();
	if (nItem >= 0)
	{
		int nID = m_list.GetItemData(nItem);
		if (m_nLastID != nID)
		{
			m_nLastID = nID;
			std::for_each(m_vPackage.begin(), m_vPackage.end(), [&](RawPackage &pack)
			{
				if (pack.nID == nID)
				{
					CString str = PackString(pack.buff);
					m_edit.SetWindowText(str);
				}
			});
		}
	}
	return 0;
}