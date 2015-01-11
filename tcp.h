
/*
TCPHEADER : Structure which will hold the TCP header of the packet
 coming from the TCP/IP Layer (the one which is supplied to MPSendPackets()
*/ 
typedef struct _TCP_HEADER
{
     USHORT  SourcePortNumber;      //(16 bits)   The source port number.
     USHORT  DestinationPortNumber; //(16 bits)  The destination port number. 
	 UCHAR  SequenceNumber[4];        // The sequence number of the first data octet in this
				                      // segment (except when SYN is present). If SYN is 
				                      //present the sequence number is the initial sequence
				                      //number and the first data octet is ISN+1.

	 UCHAR  AcknowledgementNumber[4]; //If the ACK control bit is set this field contains 
                                      //the value of the next sequence number the sender 
				                      //of the segment is expecting to receive.   

     UCHAR  HeaderLength;             // First 4 bytes of octet
                                      //This indicates where the data begins. 
	 UCHAR  Flags;                    //Last six bytes of octet are flags 
     UCHAR  WindowSize[2];            //The number of data octets beginning with the one
				                      //indicated in the acknowledgment field which the 
				                      //sender of this segment is willing to accept  
	 UCHAR  TCPChecksum[2];           // (16 bits) Checksum
		                          
	 UCHAR  UrgentPointer[2];         //Valid only if URG flag is set

}TCP_HEADER,*PTCP_HEADER;


/*
This structure is used in classification.
This structure is used in getting Ports of TCP Packets. 
*/
typedef struct _IP_TCP
{
 
	IP_HEADER  IpHeader;   // IP Header
    TCP_HEADER TcpHeader;  // UDP Header

}IP_TCP,*PIP_TCP;
