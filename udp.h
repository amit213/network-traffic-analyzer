
typedef struct _UDP_HEADER
{
     USHORT  SourcePortNumber;      // Source Port Number
     USHORT  DestinationPortNumber; // Destination Port Number
     UCHAR   UDPLength[2];          // Length of Header plus data  
	 UCHAR   UDPChecksum[2];        // CheckSum of Header plus data    
	 

}UDP_HEADER,*PUDP_HEADER;


/*
This structure is used in classification.
This structure is used in getting Ports of UDP Packets. 
*/
typedef struct _IP_UDP
{
	IP_HEADER  IpHeader;  // IP Header
    UDP_HEADER UdpHeader; // Udp header

}IP_UDP,*PIP_UDP;
