/*
*  author: amit tank
*  module : network traffic analyzer
*  file : frameparser
*/


#include "stdafx.h"

/************************************************************************


FrameParser.h



				Data Link Frame
						|
						|
						|
						|
		-------------------------------------
		|									|
		|									|
	IEEE Frames 						Ethernet Frame
	(non-ethernet frames)						|
		|										|
		|										|
	RawIPX										|

									IPv4,  ARP, RARP, IPX
									  |
									  |
									  |
							-----------------------------
							|		|			|		|
							TCP	   UDP		  ICMP	  IGMP




*************************************************************************/


#define BASECODE 2525


#define IPV4_ADDRESS_SIZE				4
#define IPV6_ADDRESS_SIZE				16
#define IPX_ADDRESS_SIZE				10
#define ETHERNET_ADDRESS_SIZE			6


#define DATALINKFRAME_IDENTIFICATION_OFFSET				12
#define RAWIPXFRAME_IDENTIFICATION_OFFSET				14

#define ETHERNET_NETWORKPROTOCOL_IDENTIFICATION_OFFSET	12
#define IEEE_NETWORKPROTOCOL_IDENTIFICATION_OFFSET		20


#define TRANSPORT_PROTOCOL_IDENTIFICATION_OFFSET	9
#define IP_SRCADDRESS_IDENTIFICATION_OFFSET			12
#define IP_DESTADDRESS_IDENTIFICATION_OFFSET		IP_SRCADDRESS_IDENTIFICATION_OFFSET+IPV4_ADDRESS_SIZE


#define ETHERNET_DATA_OFFSET 14
#define IEEE_DATA_OFFSET 22



#define	IEEE_FRAME_RANGE 0x05EE			// decimal value = 1518

#define IPV4_PROTOCOL_STAMP				0x800			// decimal value = 2048
#define ARP_PROTOCOL_STAMP				0x806			// decimal value = 2054
#define RARP_PROTOCOL_STAMP				0x8035			// decimal value = 32821
#define RAWIPX_PROTOCOL_STAMP			0xFFFF		// decimal value = 65535
#define IPX_ETHERNET_PROTOCOL_STAMP		0x8137
#define IPX_IEEE_PROTOCOL_STAMP			0xEO

#define NETBIOS_NAMEQUERY_STAMP			0x0A
#define NETBIOS_STATUSQUERY_STAMP		0x03
#define NETBIOS_DATAGRAM_STAMP			0x08


#define TCP_PROTOCOL_STAMP				6
#define UDP_PROTOCOL_STAMP				17
#define ICMP_PROTOCOL_STAMP				1
#define IGMP_PROTOCOL_STAMP				2



#define UNKNOWN_FRAMETYPE							BASECODE+50
#define ETHERNET_FRAME								BASECODE+51
#define IEEE_FRAME									BASECODE+52

#define NETWORKPROTOCOL_IPV4						BASECODE+53
#define NETWORKPROTOCOL_ARP							BASECODE+54
#define NETWORKPROTOCOL_RARP						BASECODE+55
#define NETWORKPROTOCOL_IPX_ETHERNET				BASECODE+56
#define NETWORKPROTOCOL_IPX_IEEE					BASECODE+57
#define NETWORKPROTOCOL_RAWIPX						BASECODE+58
#define NETWORKPROTOCOL_NETBIOS						BASECODE+59


#define TRANSPORTPROTOCOL_TCP						BASECODE+60
#define TRANSPORTPROTOCOL_UDP						BASECODE+61
#define TRANSPORTPROTOCOL_ICMP						BASECODE+62
#define TRANSPORTPROTOCOL_IGMP						BASECODE+63

#define NETWORKPROTOCOL_NETBIOS_NAMEQUERY			BASECODE+64
#define NETWORKPROTOCOL_NETBIOS_STATUSQUERY			BASECODE+65
#define NETWORKPROTOCOL_NETBIOS_DATAGRAM			BASECODE+66


typedef struct _PROTOCOL_TREE
{
	UINT DataLink_ProtocolID;
	UINT Network_ProtocolID;
	UINT Transport_ProtocolID;

	
}PROTOCOL_TREE,*PPROTOCOL_TREE;

typedef struct _CURRENT_FRAME
{
  ULONG					ulSourceAddress; 
  ULONG					ulDestinationAddress; 
  UINT					uiSourcePort;
  UINT					uiDestinationPort;
  PROTOCOL_TREE         ProtocolTree;
  
}CURRENT_FRAME,*PCURRENT_FRAME;


INT ParseFrame(PUCHAR CurrentFrame_p, UINT CurrentFrameLength,PCURRENT_FRAME FrameAttributes_p,PCHAR/*last parameter is temporary*/);

INT ParseAtNetworkLayer(PUCHAR CurrentFrame_p, UINT uiOffset, PCURRENT_FRAME FrameAttributes_p);
INT ParseAtTransportLayer(PUCHAR CurrentFrame_p, UINT uiOffset, PCURRENT_FRAME FrameAttributes_p);

INT GetIntFromWord(PUCHAR TmpFrame_p, INT Offset);
INT GetIntFromByte(PUCHAR TmpFrame_p, INT Offset);

//INT GetIPAddressForIPv4(PUCHAR CurrentFrame_p,PCURRENT_FRAME FrameAttributes_p);
INT GetIPAddressForIPv4(PUCHAR CurrentFrame_p,UINT uiOffset, PCURRENT_FRAME FrameAttributes_p);

INT FormTCPPacket(PUCHAR CurrentFrame_p, UINT uiOffset ,PCURRENT_FRAME FrameAttributes_p);
INT FormUDPPacket(PUCHAR CurrentFrame_p, UINT uiOffset ,PCURRENT_FRAME FrameAttributes_p);

INT ExtractPacketContents(PUCHAR CurrentFrame_p, PCURRENT_FRAME FrameAttributes_p);

/****************************************************/
//TEMPORARY
VOID DebugPrintOutput(PCHAR TmpString,PCURRENT_FRAME FrameAttributes_p);
/****************************************************/
