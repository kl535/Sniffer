#pragma once

#include <winsock2.h>
#include <iphlpapi.h>
#pragma comment(lib, "IPHLPAPI.lib")
#pragma comment(lib, "Ws2_32.lib")

#define SIO_RCVALL  (IOC_IN|IOC_VENDOR|1)//��������Ϊ����ģʽ

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
		BYTE Version;	//�汾
		BYTE HdrLen;	//IHL
	};

	BYTE ServiceType;	//��������
	WORD TotalLen;		//�ܳ�
	WORD ID;			//��ʶ

	union {
		WORD Flags;		//��־
		WORD FragOff;	//�ֶ�ƫ��
	};

	BYTE TimeToLive;	//������
	BYTE Protocol;		//Э�� IPPROTO_TCP
	WORD HdrChksum;		//ͷУ���
	in_addr SrcAddr;	//Դ��ַ
	in_addr DstAddr;	//Ŀ�ĵ�ַ
	//BYTE Options;		//ѡ��
}IP;
typedef IP *LPIP;
typedef IP UNALIGNED *ULPIP;

typedef struct s_TCP {
	WORD SrcPort;		// Դ�˿� 
	WORD DstPort;		// Ŀ�Ķ˿� 
	DWORD SeqNum;		// ˳��� 
	DWORD AckNum;		// ȷ�Ϻ� 
	BYTE DataOff;		// TCPͷ�� 
	BYTE Flags;			// ��־��URG��ACK�ȣ� 
	WORD Window;		// ���ڴ�С 
	WORD Chksum;		// У��� 
	WORD UrgPtr;		// ����ָ�� 
} TCP;
typedef TCP *LPTCP;
typedef TCP UNALIGNED * ULPTCP;

typedef struct s_UDP
{
	WORD SrcPort;		// Դ�˿�
	WORD DstPort;		// Ŀ�Ķ˿�
	WORD DataOff;		// UDPͷ��
	WORD Chksum;		// У���
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
	// IPͷ��
	LPIP pIP = (LPIP)p;
	int nLen = ntohs(pIP->TotalLen);
	int nHeaderLen = (pIP->HdrLen & 0xf) * 4;
	str = Buff2String(p, nHeaderLen);

	p += nHeaderLen;
	nLen -= nHeaderLen;

	// TCPͷ
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