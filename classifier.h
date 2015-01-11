
/*
*  author: amit tank
*  module : network traffic analyzer
*  file :  analyze app entry point. main UI.
*/


#include "stdafx.h"


/***********************************************************************************/
// structures present in Array.h.... temporarily placed here in classifier.h

typedef struct _ARRAY *PUDT_ARRAY;

typedef struct _UDT_NODE *PUDT_NODE;

typedef struct _UDT_NODE //Node Structure Contains Properties for a Class 
{
	UINT    uiClassID;

	ULONG	UlSourceIP;
	ULONG	UlDestinationIP; 
	UINT	UiSourcePort; 
	UINT	UiDestinationPort;
	ULONG	UlSourceSubnetMask;
	ULONG	UlDestinationSubnetMask;
	UINT	UiProtocolID;

	UINT    FieldFlag;
	
	PUDT_ARRAY  pudtSubArray;
	BOOLEAN     bSubArrayFlag;

//	BOOLEAN	UiElementCompareFlags[TOTAL_NODE_ATTRIBUTES];

	UINT	UiDirection;
	UINT    UiQueueNumber;
	UINT    UiPriority;

	LONG	dwlTotalByteCount;
	LONG	wTotalClassHits;
	UINT	uiCurrentPacketSize;


}UDT_NODE;


typedef struct _ARRAY	// Array Structure which Contain properties
{
	PUDT_NODE	udtNode;
	UINT		uiTotalSize;
	UINT		uiFreeElements;

}UDT_ARRAY,**PPUDT_ARRAY;



/***********************************************************************************/
/// 


typedef struct _ETHERNET_HEADER
{
	UCHAR ReceiverEthAddress[6];  // Ethernet Address of the Receiver
	UCHAR SenderEthAddress[6];    // Ethernet Address of the Sender 
	UCHAR ProtocolType[2];        // Type of Protocol Identifier 

}ETHERNET_HEADER,*PETHERNET_HEADER;


