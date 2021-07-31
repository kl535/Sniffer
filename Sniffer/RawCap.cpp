#include "stdafx.h"
#include "RawCap.h"


CRawCap::CRawCap()
{
	s = 0;
	m_local = NULL;
	m_hThread = NULL;
}

CRawCap::~CRawCap()
{
}

DWORD CRawCap::Thread_Sniff(LPVOID lp)
{
	CRawCap *pThis = (CRawCap*)lp;
	pThis->Sniff();
	return 0;
}

void CRawCap::Begin()
{
	DWORD dwThreadID;
	m_hThread = CreateThread(NULL, 0, Thread_Sniff, this, 0, &dwThreadID);
}

void CRawCap::Stop()
{
	closesocket(s);
	WaitForSingleObject(m_hThread, INFINITE);
	CloseHandle(m_hThread);
}

//void CRawCap::Clear()
//{
//	for (auto pack : m_vPackage)
//	{
//		delete[]pack.buff;
//	}
//}

bool CRawCap::Init()
{
	std::vector<AdapterInfo> vAdapter;
	ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
	PIP_ADAPTER_INFO pAdapterInfo = NULL;

	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW)
	{
		//delete pAdapterInfo;
		int arrlen = ulOutBufLen / sizeof(IP_ADAPTER_INFO);
		if (ulOutBufLen % sizeof(IP_ADAPTER_INFO))
		{
			arrlen++;
		}
		pAdapterInfo = new IP_ADAPTER_INFO[arrlen];
		if (pAdapterInfo == NULL)
		{
			return false;
		}
	}

	PIP_ADAPTER_INFO pAdapter = NULL;
	DWORD dwRetVal = 0;
	if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR)
	{
		pAdapter = pAdapterInfo;
		while (pAdapter)
		{
			AdapterInfo ai;
			ai.strName = pAdapter->Description;
			ai.strIP = pAdapter->IpAddressList.IpAddress.String;
			if (lstrcmpA(pAdapter->GatewayList.IpAddress.String, "0.0.0.0") == 0)
			{
				ai.bGate = false;
			}
			else
			{
				ai.bGate = true;
			}
			vAdapter.push_back(ai);
			pAdapter = pAdapter->Next;
		}
	}
	if (pAdapterInfo)
	{
		delete[]pAdapterInfo;
	}

	int nRes = gethostname(HostName, sizeof(HostName));
	m_local = gethostbyname(HostName);
	int i = 0;
	while (m_local->h_addr_list[i] != 0)
	{
		in_addr addr;
		addr.s_addr = *(u_long *)m_local->h_addr_list[i++];
		CString strIP = inet_ntoa(addr);
		for (auto ai : vAdapter)
		{
			if (ai.strIP == strIP)
			{
				m_vAdapter.push_back(ai);
				break;
			}
		}
	}
	return true;
}

void CRawCap::GetAdapters(std::vector<AdapterInfo> &vAdapter)
{
	vAdapter = m_vAdapter;
}

void CRawCap::SelectAdapter(int nAdapter)
{
	memcpy(&m_localAddr, m_local->h_addr_list[nAdapter], sizeof(in_addr));
}

void CRawCap::Sniff()
{
	s = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
	if (s == -1)
	{
		//con << "create socket error: " << WSAGetLastError() << "\n";
		return;
	}

	m_vPackage.clear();
	sockaddr_in localAddr, remoteAddr;
	memset(&localAddr, 0, sizeof(localAddr));
	memcpy(&localAddr.sin_addr.S_un.S_addr, &m_localAddr, sizeof(in_addr));
	localAddr.sin_family = AF_INET;
	localAddr.sin_port = 0;

	int res = bind(s, (sockaddr *)&localAddr, sizeof(localAddr));
	DWORD OptIn = 1;
	//DWORD dwBufferLen[10];
	DWORD OptOut = 1;
	DWORD dwBytesLen = 0;
	res = WSAIoctl(s, SIO_RCVALL, &OptIn, sizeof(OptIn), &OptOut, sizeof(OptOut), &dwBytesLen, NULL, NULL);

	//BYTE vInBuffer[102400] = { 0 };
	//DWORD cbInBuffer = 0;
	//BYTE vOutBuffer[102400] = { 0 };
	//DWORD cbOutBuffer = 0;
	//DWORD dwBytesLen = 0;
	//res = WSAIoctl(s, SIO_RCVALL, vInBuffer, cbInBuffer, vOutBuffer, cbOutBuffer, &dwBytesLen, NULL, NULL);


	char recvbuf[DEFAULT_BUFLEN];
	int recvLen = 0;
	int addrlen = sizeof(sockaddr_in);
	clock_t t0 = clock();
	int nID = 0;
	do
	{
		//接收数据
		recvLen = recvfrom(s, recvbuf, DEFAULT_BUFLEN, 0, (sockaddr *)&remoteAddr, &addrlen);
		if (recvLen > 0)
		{
			LPIP pHeader = (LPIP)recvbuf;
			//con << pHeader->SrcAddr << " -> " << pHeader->DstAddr << "，len=" << recvLen << ".\n";
			RawPackage pack;
			pack.nID = nID++;
			//pack.nLen = recvLen;
			pack.nTimestamp = clock() - t0;
			pack.buffLen = recvLen;
			pack.buff = new BYTE[recvLen];
			memcpy(pack.buff, recvbuf, recvLen);
			m_vPackage.push_back(pack);
		}
		else
		{
			int err = WSAGetLastError();
			//con << "recvfrom failed with error: " << err << "\n";
			switch (err)
			{
			case WSAEINTR:
			case WSAENOTSOCK:
				break;
			default:
				//con << "recvfrom failed with error: " << err << "\n";
				break;
			}
		}
	} while (recvLen > 0);
	//con << "Stop\n";
	ParseHeader();
}

void CRawCap::ParseHeader()
{
	std::for_each(m_vPackage.begin(), m_vPackage.end(), [&](RawPackage &pack)
	{
		LPIP pHeader = (LPIP)pack.buff;
		//if (memcmp(&m_localAddr, &pHeader->SrcAddr, sizeof(in_addr)) == 0)
		//{
		//	pack.bSend = true;
		//	memcpy(&pack.localAddr, &pHeader->SrcAddr, sizeof(in_addr));
		//	memcpy(&pack.remoteAddr, &pHeader->DstAddr, sizeof(in_addr));
		//}
		//else 
		if (memcmp(&m_localAddr, &pHeader->DstAddr, sizeof(in_addr)) == 0)
		{
			//con << pHeader->DstAddr << " <- " << pHeader->SrcAddr << "\n";
			pack.bSend = false;
			memcpy(&pack.localAddr, &pHeader->DstAddr, sizeof(in_addr));
			memcpy(&pack.remoteAddr, &pHeader->SrcAddr, sizeof(in_addr));
		}
		else
		{
			//con << pHeader->SrcAddr << " -> " << pHeader->DstAddr << "\n";
			pack.bSend = true;
			memcpy(&pack.localAddr, &pHeader->SrcAddr, sizeof(in_addr));
			memcpy(&pack.remoteAddr, &pHeader->DstAddr, sizeof(in_addr));
		}
		//con << pack.remoteAddr << "\n";
	});
}

void CRawCap::GetPackages(std::vector<RawPackage> &vPackage)
{
	vPackage.assign(m_vPackage.begin(), m_vPackage.end());
	std::sort(vPackage.begin(), vPackage.end());
}
