#pragma once

#include <winsock2.h>
#include <iphlpapi.h>
#pragma comment(lib, "IPHLPAPI.lib")
#pragma comment(lib, "Ws2_32.lib")

#define SIO_RCVALL  (IOC_IN|IOC_VENDOR|1)//定义网卡为混杂模式

#define DEFAULT_BUFLEN  65535
#define DEFAULT_NAMELEN 100
#define ID_TREEVIEW     31000
#define ID_LISTVIEW	    31001


typedef struct s_AdapterInfo
{
	CString strName;
	CString strIP;
	bool bGate;
}AdapterInfo;

typedef struct s_RawPackage
{
	int nID;
	in_addr localAddr;
	in_addr remoteAddr;
	bool bSend;
	clock_t nTimestamp;
	int buffLen;
	BYTE *buff;

	bool operator <(s_RawPackage &rh)
	{
		int c = memcmp(&this->localAddr, &rh.localAddr, sizeof(in_addr));
		if (c < 0)
		{
			return true;
		}
		else if (c == 0)
		{
			c = memcmp(&this->remoteAddr, &rh.remoteAddr, sizeof(in_addr));
			if (c < 0)
			{
				return true;
			}
			else if (c == 0)
			{
				if (this->nID < rh.nID)
				{
					return true;
				}
			}
		}
		return false;
	}
}RawPackage;

//#pragma pack(push,1)
typedef struct s_IP
{
	union{
		BYTE Version;	//版本
		BYTE HdrLen;	//IHL
	};

	BYTE ServiceType;	//服务类型
	WORD TotalLen;		//总长
	WORD ID;			//标识

	union {
		WORD Flags;		//标志
		WORD FragOff;	//分段偏移
	};

	BYTE TimeToLive;	//生命期
	BYTE Protocol;		//协议 IPPROTO_TCP
	WORD HdrChksum;		//头校验和
	in_addr SrcAddr;	//源地址
	in_addr DstAddr;	//目的地址
	//BYTE Options;		//选项
}IP;
typedef IP *LPIP;
typedef IP UNALIGNED *ULPIP;

typedef struct s_TCP {
	WORD SrcPort;		// 源端口 
	WORD DstPort;		// 目的端口 
	DWORD SeqNum;		// 顺序号 
	DWORD AckNum;		// 确认号 
	BYTE DataOff;		// TCP头长 
	BYTE Flags;			// 标志（URG、ACK等） 
	WORD Window;		// 窗口大小 
	WORD Chksum;		// 校验和 
	WORD UrgPtr;		// 紧急指针 
} TCP;
typedef TCP *LPTCP;
typedef TCP UNALIGNED * ULPTCP;

typedef struct s_UDP
{
	WORD SrcPort;		// 源端口
	WORD DstPort;		// 目的端口
	WORD DataOff;		// UDP头长
	WORD Chksum;		// 校验和
}UDP;
typedef UDP *LPUDP;
typedef UDP UNALIGNED * ULPUDP;

typedef struct s_ICMP {
	BYTE Type;
	BYTE Code; /* type sub code */
	WORD Cksum;
	WORD Id;
	WORD Seq;
	WORD Timestamp;
}ICMP;
typedef ICMP *LPICMP;
typedef ICMP UNALIGNED * ULPICMP;

typedef struct s_IGMP3 {
	BYTE Type;
	BYTE MaxRespCode;
	WORD Cksum;
	DWORD GroupAddr;
	BYTE SQRV;
	BYTE QQIC;
	WORD SourceNum;
}IGMP3;
typedef IGMP3 *LPIGMP3;
typedef IGMP3 UNALIGNED * ULPIGMP3;
//#pragma pack(pop) 


static CString ProtocolStr(BYTE protocol)
{
	CString str;
	switch (protocol)
	{
	case IPPROTO_TCP:
		str = _T("TCP");
		break;
	case IPPROTO_UDP:
		str = _T("UDP");
		break;
	case IPPROTO_IGMP:
		str = _T("IGMP");
		break;
	case IPPROTO_ICMP:
		str = _T("ICMP");
		break;
	default:
		str.Format(_T("proto=%d"), protocol);
		break;
	}
	return str;
}

static CString Buff2String(LPBYTE pBuff, int nLen)
{
	CString strRet;
	if (nLen > 0)
	{
		CString strHex, strBuff;
		int nLeftLen = nLen;
		LPBYTE p = pBuff;
		do
		{
			int nLineLen = min(nLeftLen, 16);
			for (int i = 0; i < nLineLen; i++)
			{
				strHex.AppendFormat(_T("%.2X "), *p);
				if (*p < 32)
				{
					strBuff += _T(".");
				}
				else
				{
					strBuff += *p;
				}
				if ((i + 1) % 4 == 0)
				{
					strHex += _T(" ");
				}
				p++;
			}
			strRet += strHex;
			int nBlank = 3;
			nBlank += 52 - strHex.GetLength();
			for (int i = 0; i < nBlank; i++)
			{
				strRet += _T(" ");
			}
			strRet += strBuff;
			nLeftLen -= 16;
			strHex.Empty();
			strBuff.Empty();
			if (nLeftLen > 0)
			{
				strRet += _T("\r\n");
			}
		} while (nLeftLen > 0);
	}
	return strRet;
}

static CString PackString(LPBYTE pBuff)
{
	LPBYTE p = pBuff;
	CString str;
	// IP头部
	LPIP pIP = (LPIP)p;
	int nLen = ntohs(pIP->TotalLen);
	int nHeaderLen = (pIP->HdrLen & 0xf) * 4;
	str = Buff2String(p, nHeaderLen);

	p += nHeaderLen;
	nLen -= nHeaderLen;

	// TCP头
	if (pIP->Protocol == IPPROTO_TCP)
	{
		LPTCP pTCP = (LPTCP)p;
		int nTcpHeaderLen = (pTCP->DataOff>>4) * 4;
		str += _T("\r\n");
		str += Buff2String((LPBYTE)p, nTcpHeaderLen);

		p += nTcpHeaderLen;
		nLen -= nTcpHeaderLen;
	}
	else if (pIP->Protocol == IPPROTO_UDP)
	{
		LPUDP pUDP = (LPUDP)p;
		int nUdpHeaderLen = sizeof(UDP);
		str += _T("\r\n");
		str += Buff2String(p, nUdpHeaderLen);

		p += nUdpHeaderLen;
		nLen -= nUdpHeaderLen;
	}

	// data
	str += _T("\r\n\r\n");
	str += Buff2String(p, nLen);
	return str;
}