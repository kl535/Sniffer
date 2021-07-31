#pragma once
#include "RawCap.h"

class CMyWin : public CWindowImpl<CMyWin>
{
public:
	CMyWin();
	~CMyWin();

	BEGIN_MSG_MAP(CMyWin)
		MESSAGE_HANDLER(WM_CREATE, OnCreate)
		MESSAGE_HANDLER(WM_CLOSE, OnClose)
		MESSAGE_HANDLER(WM_SIZE, OnSize)

		// menu
		COMMAND_ID_HANDLER(ID_BEGIN, OnBegin)
		COMMAND_ID_HANDLER(ID_STOP, OnStop)
		COMMAND_ID_HANDLER(ID_LOAD, OnLoad)
		COMMAND_ID_HANDLER(ID_SAVE, OnSave)
		COMMAND_ID_HANDLER(IDM_EXIT, OnExit)
		COMMAND_ID_HANDLER(IDM_ABOUT, OnAbout)
		COMMAND_RANGE_HANDLER(ID_ADAPTER, ID_ADAPTER+100, OnAdapter)
		NOTIFY_HANDLER(ID_TREEVIEW, TVN_SELCHANGED, OnTreeview)
		NOTIFY_HANDLER(ID_LISTVIEW, LVN_ITEMCHANGED, OnListview)
		//MESSAGE_HANDLER(WM_COMMAND, OnCommand)
		//MESSAGE_HANDLER(WM_ERASEBKGND, OnEraseBkgnd)
		//MESSAGE_HANDLER(WM_MOUSEMOVE, OnMouseMove)
		//MESSAGE_HANDLER(WM_MOUSELEAVE, OnMouseLeave)
		//MESSAGE_HANDLER(WM_LBUTTONDOWN, OnLButtonDown)
		//MESSAGE_HANDLER(WM_LBUTTONUP, OnLButtonUp)
	END_MSG_MAP()

	LRESULT OnCreate(UINT uMsg, WPARAM wp, LPARAM lp, BOOL &b);
	LRESULT OnClose(UINT uMsg, WPARAM wp, LPARAM lp, BOOL &b);
	LRESULT OnSize(UINT uMsg, WPARAM wp, LPARAM lp, BOOL &b);


	//LRESULT OnCommand(UINT uMsg, WPARAM wp, LPARAM lp, BOOL &b);
	LRESULT OnBegin(WORD code, WORD id, HWND h, BOOL &b);
	LRESULT OnStop(WORD code, WORD id, HWND h, BOOL &b);
	LRESULT OnLoad(WORD code, WORD id, HWND h, BOOL &b);
	LRESULT OnSave(WORD code, WORD id, HWND h, BOOL &b);
	LRESULT OnExit(WORD code, WORD id, HWND h, BOOL &b);
	LRESULT OnAbout(WORD code, WORD id, HWND h, BOOL &b);
	LRESULT OnAdapter(WORD code, WORD id, HWND h, BOOL &b);
	LRESULT OnTreeview(int cID, LPNMHDR pNMH, BOOL &b);
	LRESULT OnListview(int cID, LPNMHDR pNMH, BOOL &b);

	void CleanData();
	void LoadData();

	CMenu m_menu;
	CTreeViewCtrl m_tree;
	CListViewCtrl m_list;
	CEdit m_edit;
	HFONT m_hFont;

	CRawCap m_cap;
	int m_nAdapterSel;
	int m_nLastID;
	bool m_bBegin;
	std::vector<RawPackage> m_vPackage;
	WORD m_wLastSend;
	WORD m_wLastRecv;

	void InitCtrl();
	void InitData();
};

