/*
*  author: amit tank
*  module : network traffic analyzer
*  file : frameparser
*/

#include <stdafx.h>


/************************************************************************


FrameParser.c



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

INT ParseFrame(PUCHAR CurrentFrame_p, UINT CurrentFrameLength, PCURRENT_FRAME FrameAttributes_p,PCHAR TestingString/*last parameter is temporary*/)
{

INT DataLinkFrameType,NetworkFrameType,TransportFrameType, RawIPXFrameType,TransportProtocolType;
INT uiOffset=0;

TransportProtocolType = RawIPXFrameType = DataLinkFrameType = NetworkFrameType = TransportFrameType = UNKNOWN_FRAMETYPE;

DataLinkFrameType = GetIntFromWord(CurrentFrame_p,DATALINKFRAME_IDENTIFICATION_OFFSET);

	if((DataLinkFrameType > 0) && (DataLinkFrameType < IEEE_FRAME_RANGE))
		{
			RawIPXFrameType = GetIntFromWord(CurrentFrame_p,RAWIPXFRAME_IDENTIFICATION_OFFSET);

			if(RawIPXFrameType == RAWIPX_PROTOCOL_STAMP)
			{
				FrameAttributes_p->ProtocolTree.DataLink_ProtocolID = ETHERNET_FRAME;
				FrameAttributes_p->ProtocolTree.Network_ProtocolID  = NETWORKPROTOCOL_RAWIPX;
			}
			else
				{
					FrameAttributes_p->ProtocolTree.DataLink_ProtocolID = IEEE_FRAME;
					uiOffset = IEEE_DATA_OFFSET;
				}
		}
	else
		{
			FrameAttributes_p->ProtocolTree.DataLink_ProtocolID = ETHERNET_FRAME;
			uiOffset = ETHERNET_DATA_OFFSET;
		}

	
ParseAtNetworkLayer(CurrentFrame_p,uiOffset,FrameAttributes_p);

//	wsprintf(TestingString,"\r\n IP Header Length		:	 %d",FormTCPPacket(CurrentFrame_p, FrameAttributes_p));
//						lstrcat(TmpString,TmpStr);
//	wsprintf(TestingString,"\r\n Byte : %02x",GetIntFromByte(CurrentFrame_p,0));
	DebugPrintOutput(TestingString,FrameAttributes_p);
	return 0;
}


INT GetIntFromWord(PUCHAR TmpFrame_p, INT Offset)
{
	INT iValue;

	iValue = (INT) (0xff & (INT)*(TmpFrame_p + Offset)); //(BYTE)(TmpFrame_p + Offset);
	iValue = iValue << 8;
	iValue = iValue + ((INT) (0xff & (INT)*(TmpFrame_p + Offset+1)));

	return iValue;
}

INT GetIntFromByte(PUCHAR TmpFrame_p, INT Offset)
{
	INT iValue;

	iValue = (INT) (0x000000ff & (INT)*(TmpFrame_p + Offset)); //(BYTE)(TmpFrame_p + Offset);
//	iValue = iValue << 8;
//	iValue = iValue + ((INT) (0xff & (INT)*(TmpFrame_p + Offset+1)));

	return iValue;
}


VOID DebugPrintOutput(PCHAR TmpString,PCURRENT_FRAME FrameAttributes_p)
{
CHAR TmpStr[256];

IN_ADDR	tmpAdd;

lstrcpy(TmpString,"   Packet Details\r\n");
	if(FrameAttributes_p->ProtocolTree.DataLink_ProtocolID == ETHERNET_FRAME)
	{
		lstrcat(TmpString,"\r\n Data-Link Layer Frame Type     :	 Ethernet Frame");
	}
	else if(FrameAttributes_p->ProtocolTree.DataLink_ProtocolID == IEEE_FRAME)
	{
			lstrcat(TmpString,"\r\n Data-Link Layer Frame Type	:	 IEEE 802.3 Frame");
	}
		
		if(FrameAttributes_p->ProtocolTree.Network_ProtocolID == NETWORKPROTOCOL_IPV4)
		{
				lstrcat(TmpString,"\r\n Network Layer Protocol Type    :	 IP Packet");
			if(FrameAttributes_p->ProtocolTree.Transport_ProtocolID != UNKNOWN_FRAMETYPE)
			{

				if(FrameAttributes_p->ProtocolTree.Transport_ProtocolID == TRANSPORTPROTOCOL_TCP)
				{
						lstrcat(TmpString,"\r\n Transport Layer Protocol Type  :	 TCP Protocol");
						//INT FormTCPPacket(CurrentFrame_p, FrameAttributes_p)
//						wsprintf(TmpStr,"\r\n IP Header Length		:	 %d",FormTCPPacket(CurrentFrame_p, FrameAttributes_p));
//						lstrcat(TmpString,TmpStr);
						wsprintf(TmpStr,"\r\n Source Port			:	 %d",FrameAttributes_p->uiSourcePort);
						lstrcat(TmpString,TmpStr);
						wsprintf(TmpStr,"\r\n Destination Port		:	 %d",FrameAttributes_p->uiDestinationPort);
						lstrcat(TmpString,TmpStr);


				}

				if(FrameAttributes_p->ProtocolTree.Transport_ProtocolID == TRANSPORTPROTOCOL_UDP)
				{
						lstrcat(TmpString,"\r\n Transport Layer Protocol Type  :	 UDP Protocol");

						wsprintf(TmpStr,"\r\n Source Port			:	 %d",FrameAttributes_p->uiSourcePort);
						lstrcat(TmpString,TmpStr);
						wsprintf(TmpStr,"\r\n Destination Port		:	 %d",FrameAttributes_p->uiDestinationPort);
						lstrcat(TmpString,TmpStr);
						
				}

				if(FrameAttributes_p->ProtocolTree.Transport_ProtocolID == TRANSPORTPROTOCOL_ICMP)
						lstrcat(TmpString,"\r\n Transport Layer Protocol Type  :	 ICMP Protocol");

				if(FrameAttributes_p->ProtocolTree.Transport_ProtocolID == TRANSPORTPROTOCOL_IGMP)
						lstrcat(TmpString,"\r\n Transport Layer Protocol Type  :	 IGMP Protocol");
			
			tmpAdd.S_un.S_addr = FrameAttributes_p->ulSourceAddress;
			wsprintf(TmpStr,"\r\n Source IP Address		:	 %s",inet_ntoa(tmpAdd));
			lstrcat(TmpString,TmpStr);

			tmpAdd.S_un.S_addr = FrameAttributes_p->ulDestinationAddress;
			wsprintf(TmpStr,"\r\n Destination IP Address		:	 %s",inet_ntoa(tmpAdd));
			lstrcat(TmpString,TmpStr);


			}
			else
				lstrcat(TmpString,"\r\n Transport Layer Protocol Type  :   Unknown Type");
		}

		if(FrameAttributes_p->ProtocolTree.Network_ProtocolID == NETWORKPROTOCOL_ARP)
					lstrcat(TmpString,"\r\n Network Layer Protocol Type    :	 ARP Packet");

		if(FrameAttributes_p->ProtocolTree.Network_ProtocolID == NETWORKPROTOCOL_RARP)
					lstrcat(TmpString,"\r\n Network Layer Protocol Type    :	 RARP Packet");

		if(FrameAttributes_p->ProtocolTree.Network_ProtocolID == IPX_ETHERNET_PROTOCOL_STAMP)
					lstrcat(TmpString,"\r\n Network Layer Protocol Type    :	 IPX Packet");

	
/*		else
		{
		if(FrameAttributes_p->ProtocolTree.DataLink_ProtocolID == IEEE_FRAME)
			lstrcat(TmpString,"\r\n Data-Link Layer Frame Type  :    Non Ethernet Frame");
		}*/
	
		if(FrameAttributes_p->ProtocolTree.Network_ProtocolID == NETWORKPROTOCOL_NETBIOS_NAMEQUERY)
					lstrcat(TmpString,"\r\n Network Layer Protocol Type    :	 NetBIOS Name Query");
		if(FrameAttributes_p->ProtocolTree.Network_ProtocolID == NETWORKPROTOCOL_NETBIOS_STATUSQUERY)
					lstrcat(TmpString,"\r\n Network Layer Protocol Type    :	 NetBIOS Status Query");
		if(FrameAttributes_p->ProtocolTree.Network_ProtocolID == NETWORKPROTOCOL_NETBIOS_DATAGRAM)
					lstrcat(TmpString,"\r\n Network Layer Protocol Type    :	 NetBIOS Datagram");



	return;
}


INT GetIPAddressForIPv4(PUCHAR CurrentFrame_p,UINT uiOffset, PCURRENT_FRAME FrameAttributes_p)
{

	PIP_HEADER TmpIPHeader;

	TmpIPHeader = (IP_HEADER *) (CurrentFrame_p + uiOffset);

	FrameAttributes_p->ulSourceAddress = TmpIPHeader->ulSourceIP;
	FrameAttributes_p->ulDestinationAddress = TmpIPHeader->ulDestinationIP;

return 0;
}

INT FormTCPPacket(PUCHAR CurrentFrame_p, UINT uiOffset, PCURRENT_FRAME FrameAttributes_p)
{
	PTCP_HEADER TmpTCPHeader;

	INT IPHeaderLength;

	IPHeaderLength = (0x0000000F & GetIntFromByte(CurrentFrame_p,uiOffset)) * 4;

	TmpTCPHeader = (TCP_HEADER *) (CurrentFrame_p + ETHERNET_DATA_OFFSET + IPHeaderLength);

	FrameAttributes_p->uiDestinationPort = ntohs(TmpTCPHeader->DestinationPortNumber);
	FrameAttributes_p->uiSourcePort = ntohs(TmpTCPHeader->SourcePortNumber);

return 0;
}

INT FormUDPPacket(PUCHAR CurrentFrame_p,UINT uiOffset,PCURRENT_FRAME FrameAttributes_p)
{
	PUDP_HEADER TmpUDPHeader;

	INT IPHeaderLength;

	IPHeaderLength = (0x0000000F & GetIntFromByte(CurrentFrame_p,uiOffset)) * 4;

	TmpUDPHeader = (UDP_HEADER *) (CurrentFrame_p + ETHERNET_DATA_OFFSET + IPHeaderLength);

	FrameAttributes_p->uiDestinationPort = ntohs(TmpUDPHeader->DestinationPortNumber);
	FrameAttributes_p->uiSourcePort = ntohs(TmpUDPHeader->SourcePortNumber);

return 0;
}

INT ExtractPacketContents(PUCHAR CurrentFrame_p, PCURRENT_FRAME FrameAttributes_p)
{


	return 0;
}


/********************


*********************/


INT ParseAtNetworkLayer(PUCHAR CurrentFrame_p, UINT uiOffset, PCURRENT_FRAME FrameAttributes_p)
{

INT NetworkProtocolType;

if(FrameAttributes_p->ProtocolTree.DataLink_ProtocolID == ETHERNET_FRAME)
{
	NetworkProtocolType = GetIntFromWord(CurrentFrame_p,ETHERNET_NETWORKPROTOCOL_IDENTIFICATION_OFFSET);
}
	else if(FrameAttributes_p->ProtocolTree.DataLink_ProtocolID == IEEE_FRAME)
	{
		NetworkProtocolType = GetIntFromByte(CurrentFrame_p,IEEE_NETWORKPROTOCOL_IDENTIFICATION_OFFSET+1);	//test
		
			if(NetworkProtocolType = NETBIOS_NAMEQUERY_STAMP)
				{
					FrameAttributes_p->ProtocolTree.Network_ProtocolID = NETWORKPROTOCOL_NETBIOS_NAMEQUERY;
				}
			else if(NetworkProtocolType = NETBIOS_STATUSQUERY_STAMP)
				{
					FrameAttributes_p->ProtocolTree.Network_ProtocolID = NETWORKPROTOCOL_NETBIOS_STATUSQUERY;
				}
			else if(NetworkProtocolType = NETBIOS_DATAGRAM_STAMP)
				{
					FrameAttributes_p->ProtocolTree.Network_ProtocolID = NETWORKPROTOCOL_NETBIOS_DATAGRAM;
				}

	}

			if(NetworkProtocolType == IPV4_PROTOCOL_STAMP)
				{
					FrameAttributes_p->ProtocolTree.Network_ProtocolID = NETWORKPROTOCOL_IPV4;
					ParseAtTransportLayer(CurrentFrame_p,uiOffset,FrameAttributes_p);
				}

			if(NetworkProtocolType == ARP_PROTOCOL_STAMP)
				{
					FrameAttributes_p->ProtocolTree.Network_ProtocolID = NETWORKPROTOCOL_ARP;
				}

			if(NetworkProtocolType == RARP_PROTOCOL_STAMP)
				{
					FrameAttributes_p->ProtocolTree.Network_ProtocolID = NETWORKPROTOCOL_RARP;
				}

			if(NetworkProtocolType == IPX_ETHERNET_PROTOCOL_STAMP)
				{
					FrameAttributes_p->ProtocolTree.Network_ProtocolID = NETWORKPROTOCOL_IPX_ETHERNET;
				}

return 0;
}


INT ParseAtTransportLayer(PUCHAR CurrentFrame_p, UINT uiOffset, PCURRENT_FRAME FrameAttributes_p)
{
INT TransportProtocolType;

		TransportProtocolType = GetIntFromByte(CurrentFrame_p,uiOffset+TRANSPORT_PROTOCOL_IDENTIFICATION_OFFSET);

		if(FrameAttributes_p->ProtocolTree.Network_ProtocolID == NETWORKPROTOCOL_IPV4)		
		{
				GetIPAddressForIPv4(CurrentFrame_p,uiOffset,FrameAttributes_p);

				if(TransportProtocolType == TCP_PROTOCOL_STAMP)
					{
						FrameAttributes_p->ProtocolTree.Transport_ProtocolID = TRANSPORTPROTOCOL_TCP;
						FormTCPPacket(CurrentFrame_p,uiOffset,FrameAttributes_p);
					}

				if(TransportProtocolType == UDP_PROTOCOL_STAMP)
					{
						FrameAttributes_p->ProtocolTree.Transport_ProtocolID = TRANSPORTPROTOCOL_UDP;
						FormUDPPacket(CurrentFrame_p,uiOffset,FrameAttributes_p);
						
					}

				if(TransportProtocolType == ICMP_PROTOCOL_STAMP)
					{
						FrameAttributes_p->ProtocolTree.Transport_ProtocolID = TRANSPORTPROTOCOL_ICMP;
					}

				if(TransportProtocolType == IGMP_PROTOCOL_STAMP)
					{
						FrameAttributes_p->ProtocolTree.Transport_ProtocolID = TRANSPORTPROTOCOL_IGMP;
					}
		
		
		}

return 0;
}































/**********************************
INT ParseFrame(PUCHAR CurrentFrame_p, UINT CurrentFrameLength, PCURRENT_FRAME FrameAttributes_p,PCHAR TestingString )
{

INT DataLinkFrameType,NetworkFrameType,TransportFrameType, RawIPXFrameType,TransportProtocolType;

TransportProtocolType = RawIPXFrameType = DataLinkFrameType = NetworkFrameType = TransportFrameType = UNKNOWN_FRAMETYPE;

DataLinkFrameType = GetIntFromWord(CurrentFrame_p,DATALINKFRAME_IDENTIFICATION_OFFSET);

	if((DataLinkFrameType > 0) && (DataLinkFrameType < IEEE_FRAME_RANGE))
		{
			RawIPXFrameType = GetIntFromWord(CurrentFrame_p,RAWIPXFRAME_IDENTIFICATION_OFFSET);

			if(RawIPXFrameType == RAWIPX_PROTOCOL_STAMP)
			{
				FrameAttributes_p->ProtocolTree.DataLink_ProtocolID = ETHERNET_FRAME;
				FrameAttributes_p->ProtocolTree.Network_ProtocolID  = NETWORKPROTOCOL_RAWIPX;
			}
			else
				{
					FrameAttributes_p->ProtocolTree.DataLink_ProtocolID = IEEE_FRAME;
				}
		}
	else
		{

			if(DataLinkFrameType == IPV4_PROTOCOL_STAMP)
				{
					FrameAttributes_p->ProtocolTree.DataLink_ProtocolID = ETHERNET_FRAME;
					FrameAttributes_p->ProtocolTree.Network_ProtocolID = NETWORKPROTOCOL_IPV4;
				}

			if(DataLinkFrameType == ARP_PROTOCOL_STAMP)
				{
					FrameAttributes_p->ProtocolTree.DataLink_ProtocolID = ETHERNET_FRAME;
					FrameAttributes_p->ProtocolTree.Network_ProtocolID = NETWORKPROTOCOL_ARP;
				}

			if(DataLinkFrameType == RARP_PROTOCOL_STAMP)
				{
					FrameAttributes_p->ProtocolTree.DataLink_ProtocolID = ETHERNET_FRAME;
					FrameAttributes_p->ProtocolTree.Network_ProtocolID = NETWORKPROTOCOL_RARP;
				}
//IPX_ETHERNET_PROTOCOL_STAMP
			if(DataLinkFrameType == IPX_ETHERNET_PROTOCOL_STAMP)
				{
					FrameAttributes_p->ProtocolTree.DataLink_ProtocolID = ETHERNET_FRAME;
					FrameAttributes_p->ProtocolTree.Network_ProtocolID = NETWORKPROTOCOL_IPX_ETHERNET;
				}
//
		}


	if(FrameAttributes_p->ProtocolTree.Network_ProtocolID == NETWORKPROTOCOL_IPV4)
	{
		TransportProtocolType = GetIntFromByte(CurrentFrame_p,ETHERNET_DATA_OFFSET+TRANSPORT_PROTOCOL_IDENTIFICATION_OFFSET);
		
		GetIPAddressForIPv4(CurrentFrame_p,FrameAttributes_p);

		if(TransportProtocolType == TCP_PROTOCOL_STAMP)
			{
				FrameAttributes_p->ProtocolTree.Transport_ProtocolID = TRANSPORTPROTOCOL_TCP;
				FormTCPPacket(CurrentFrame_p,FrameAttributes_p);
			}

		if(TransportProtocolType == UDP_PROTOCOL_STAMP)
			{
				FrameAttributes_p->ProtocolTree.Transport_ProtocolID = TRANSPORTPROTOCOL_UDP;
				FormUDPPacket(CurrentFrame_p,FrameAttributes_p);
				
			}

		if(TransportProtocolType == ICMP_PROTOCOL_STAMP)
			{
				FrameAttributes_p->ProtocolTree.Transport_ProtocolID = TRANSPORTPROTOCOL_ICMP;
			}

		if(TransportProtocolType == IGMP_PROTOCOL_STAMP)
			{
				FrameAttributes_p->ProtocolTree.Transport_ProtocolID = TRANSPORTPROTOCOL_IGMP;
			}


	}
	


//	wsprintf(TestingString,"\r\n IP Header Length		:	 %d",FormTCPPacket(CurrentFrame_p, FrameAttributes_p));
//						lstrcat(TmpString,TmpStr);
//	wsprintf(TestingString,"\r\n Byte : %02x",GetIntFromByte(CurrentFrame_p,0));
	DebugPrintOutput(TestingString,FrameAttributes_p);
	return 0;
}
***********************************/
