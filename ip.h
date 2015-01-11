/*
IP_HEADER : Structure which will hold the IP header of the packet coming from the TCP/IP
Layer (the one which is supplied to MPSendPackets()
*/

typedef struct _IP_HEADER
	{
		UCHAR VersionNHeaderLength;    //This byte contains the version number and header length
		UCHAR TypeOfService;           // This byte stores the TOS bits of IP header
		UCHAR TotalLength[2];           
		UCHAR Identification[2];
		UCHAR FlagsNFragmentOffset[2]; // This word contains 3 bits of flags and the   
		                               // remaining bits for fragment offset 
		UCHAR TTL;                     // Time To Live Field 
		UCHAR ProtocolIdentifier;      // eg. 1->ICMP,17->UDP,6->TCP
		UCHAR ChkSum[2];               // IpHeader Checksum
		ULONG ulSourceIP;             // Source IP Address 
		ULONG ulDestinationIP;           // Destination IP Address 
    }IP_HEADER,*PIP_HEADER;
