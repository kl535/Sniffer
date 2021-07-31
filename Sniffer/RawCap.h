#pragma once

class CRawCap
{
public:
	CRawCap();
	~CRawCap();

	bool Init();
	void Begin();
	void Stop();
	//void Clear();

	void GetAdapters(std::vector<AdapterInfo> &vAdapter);
	void SelectAdapter(int nAdapter);

	void Sniff();
	void GetIP();
	void GetPackages(std::vector<RawPackage> &vPackage);
	void GetPackageData();

	static DWORD WINAPI Thread_Sniff(LPVOID lp);

	char HostName[DEFAULT_NAMELEN];
	hostent *m_local;
	SOCKET s;
	in_addr m_localAddr;

	std::vector<RawPackage> m_vPackage;
	std::vector<AdapterInfo> m_vAdapter;
	HANDLE m_hThread;

	void ParseHeader();
};

