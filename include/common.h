/*
*  author: amit tank
*  module : network traffic analyzer
*  file :  common util routines.
*/




#define PARTITION_SIZE 10000
#define MAX_PARTITION_NUMBERS 20



INT PacketPosition[MAX_PARTITION_NUMBERS];
INT PacketIndex[MAX_PARTITION_NUMBERS];
INT PartionPositionArray[20];
INT CurrentPartition=0;

ULONG TotalPacketCount=0;

INT GetSearchPartition(INT PacketIndex);
INT GetSearchPosition(INT PacketIndex);
INT GetSearchIndex(INT PacketIndex);

struct PktHeader {
	ULARGE_INTEGER PktTimeStamp;
	UINT PktPacketSize;
};

/*
void CloseDumpFile();
BOOLEAN OpenDumpFile();
void DumpPacketContent(PUCHAR,ULONG);
BOOLEAN bDumpFlag = FALSE;
*/

HANDLE hPktDumpFile = NULL;
BOOLEAN DUMPFILEOPEN = FALSE;
DWORD dwFileSizeHigh;
DWORD BytesWritten;
char DumpFilePath[256];


void ErrorCheck(){

LPVOID lpMsgBuf;

FormatMessage( 
    FORMAT_MESSAGE_ALLOCATE_BUFFER | 
    FORMAT_MESSAGE_FROM_SYSTEM | 
    FORMAT_MESSAGE_IGNORE_INSERTS,
    NULL,
    GetLastError(),
    MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
    (LPTSTR) &lpMsgBuf,
    0,
    NULL 
);
// Display the string.
MessageBox( NULL, (LPCTSTR)lpMsgBuf, "Error", MB_OK | MB_ICONINFORMATION );
// Free the buffer.
LocalFree( lpMsgBuf );

}

void PacketToHex(PCHAR PacketHoldBuffer,PUCHAR BytesReadFromFile,LONG BytesRead) {

		
		char TempStr[15];
		int Count=0;
		int PrintBufferLength=0;//16;//1514;
		int nCounter=0;

		lstrcpy(PacketHoldBuffer,"\0");

		PrintBufferLength = BytesRead;
		while(nCounter<PrintBufferLength){
			
				if((nCounter%16)==0){
					wsprintf(TempStr,"\r\n %08d :  ",Count);
					lstrcat(PacketHoldBuffer,TempStr);
					Count++;
				}

				if((nCounter%8)==0)
						lstrcat(PacketHoldBuffer,"    ");
			wsprintf(TempStr," %02x",(BYTE)*(BytesReadFromFile+nCounter));	
			//wsprintf(TempStr,"%c",(unsigned char)*(BytesReadFromFile+nCounter));	
			//wsprintf(TempStr,"0E ");	
			lstrcat(PacketHoldBuffer,TempStr);
			nCounter++;
			}
			
		//wsprintf(TempStr,"******%d",lstrlen(buffer));
		//lstrcat(buffer,TempStr);
		lstrcat(PacketHoldBuffer,"\0");


		return;
}

void CopyPacketContent(char * str) {
char buffer[8000];
char TempStr[15];
int Count=0;
int PrintBufferLength=1514;
int nCounter=0;

lstrcpy(buffer,"\0");

while(nCounter<PrintBufferLength){
	
		if((nCounter%16)==0){
			wsprintf(TempStr,"\r\n %08d :  ",Count);
			lstrcat(buffer,TempStr);
			Count++;
		}

		if((nCounter%8)==0)
				lstrcat(buffer," ");
	//wsprintf(TempStr," %02x",(BYTE)*(PrintBuffer+nCounter));	
	wsprintf(TempStr,"0E ");	
	lstrcat(buffer,TempStr);
	nCounter++;
	}
	
//wsprintf(TempStr,"******%d",lstrlen(buffer));
//lstrcat(buffer,TempStr);
lstrcat(buffer,"\0");

strcpy(str,buffer);
return;
}


BOOLEAN OpenDumpFile() {

	PCHAR SummaryFileName = DumpFilePath;//"e:\\pktdump.txt";

//	char  lpFileBuffer[600];
//	char TempBuffer[20];

	hPktDumpFile = CreateFile(
					SummaryFileName,
					GENERIC_READ,
					FILE_SHARE_READ,
					NULL,
					OPEN_EXISTING,
					FILE_ATTRIBUTE_NORMAL,
					NULL
					);

	if(hPktDumpFile == INVALID_HANDLE_VALUE)
				return FALSE;

	SetFilePointer(
		hPktDumpFile,
		0,//GetFileSize(hPktDumpFile,&dwFileSizeHigh),
		NULL,
		FILE_BEGIN
	);



//WriteFile(hPktDumpFile,lpFileBuffer,lstrlen(lpFileBuffer),&BytesWritten,NULL);//strlen(lpFileBuffer),NULL,NULL);
//ErrorCheck();


	return TRUE;
}

ULONG GetDumpContent(int Index,PCHAR PacketHoldBuffer, PUCHAR tmpRawPktFrame, PUINT tmpRawPktFrameLength) {

ULONG BytesToRead,BytesRead;
char str[50];
UCHAR FileHoldBuffer[MAX_PANE_SIZE];
struct PktHeader *PacketHeader;
int PacketCounter=0;
INT StartSearchIndex =0;
INT StartSearchPosition =0;

//StartSearchIndex = GetSearchIndex(Index);
//StartSearchPosition = GetSearchPosition(Index);
//PacketCounter = StartSearchIndex;


	SetFilePointer(
		hPktDumpFile,
		StartSearchPosition,//GetFileSize(hPktDumpFile,&dwFileSizeHigh),
		NULL,
		FILE_BEGIN
	);

	


		do {
			BytesToRead = sizeof(struct PktHeader);
			ReadFile(hPktDumpFile,FileHoldBuffer,BytesToRead,&BytesRead,NULL);
			//ErrorCheck();

			PacketHeader = (struct PktHeader*)FileHoldBuffer;

			BytesToRead = PacketHeader->PktPacketSize;

			ReadFile(hPktDumpFile,FileHoldBuffer,BytesToRead,&BytesRead,NULL);
			
			//SetFilePointer(hPktDumpFile,(long)BytesToRead,NULL,FILE_CURRENT);
			
			PacketCounter++;
		}
		while(PacketCounter <= Index);

	/***********************************/
	//lstrcpy((LPSTR)tmpRawPktFrame,(LPSTR)FileHoldBuffer);
	memcpy(tmpRawPktFrame,FileHoldBuffer,BytesRead);
	*tmpRawPktFrameLength = BytesRead;

	/***********************************/
	
	PacketToHex(PacketHoldBuffer,FileHoldBuffer,BytesRead);

	wsprintf(str,"\r\n\r\n\r\n");
	lstrcat(PacketHoldBuffer,str);
	wsprintf(str,"Total Packet Size : %d",BytesRead);
	lstrcat(PacketHoldBuffer,str);

	
//	wsprintf(str,"\nPane Buffer Size : %d",lstrlen(PacketHoldBuffer));
//	lstrcat(PacketHoldBuffer,str);

	
	return -1;
}


		ULONG GetDumpPacketCount() {

			ULONG BytesToRead,BytesRead,TotalBytesRead=0;
			char FileHoldBuffer[8000];
			struct PktHeader *PacketHeader;
			int TempPacketCount=0;
			int nLower, nUpper;
			UINT ONE_TENTH;
			UINT nLoop=1;
			UINT TotalFileSize=0;
			CWinApp * tmpWinApp = AfxGetApp();

			CDialog *tmpMainWnd = (CDialog*)tmpWinApp->GetMainWnd();
			CProgressCtrl *tmpProgBar = (CProgressCtrl*)tmpMainWnd->GetDlgItem(IDC_PROGRESS);

			TotalFileSize = GetFileSize(hPktDumpFile,&dwFileSizeHigh);

			ONE_TENTH = (TotalFileSize)/1000;
			tmpProgBar->SetRange32(0,TotalFileSize);
			tmpProgBar->GetRange( nLower, nUpper );
			//tmpProgBar->SetStep((TotalFileSize)/10);
			tmpProgBar->SetStep(ONE_TENTH);


				SetFilePointer(
					hPktDumpFile,
					0,//GetFileSize(hPktDumpFile,&dwFileSizeHigh),
					NULL,
					FILE_BEGIN
				);

					do {
						BytesToRead = sizeof(struct PktHeader);
						ReadFile(hPktDumpFile,FileHoldBuffer,BytesToRead,&BytesRead,NULL);
						//ErrorCheck();
						if(BytesRead == 0)
							break;
						
						TotalBytesRead = TotalBytesRead + BytesRead; 

						PacketHeader = (struct PktHeader*)FileHoldBuffer;

						BytesToRead = PacketHeader->PktPacketSize;

						ReadFile(hPktDumpFile,FileHoldBuffer,BytesToRead,&BytesRead,NULL);
						TempPacketCount++;

						TotalBytesRead = TotalBytesRead + BytesRead;

						if(TempPacketCount == ( PARTITION_SIZE * (CurrentPartition+1)) )
						{
							CurrentPartition++;
							PacketIndex[CurrentPartition] = TempPacketCount+1;					
							PacketPosition[CurrentPartition] = TotalBytesRead;
							PartionPositionArray[CurrentPartition] = TotalBytesRead;
						}
					
						if(TotalBytesRead >= (ONE_TENTH * nLoop))
						{
							tmpProgBar->StepIt();
							nLoop++;
						}
					
					}
					while(BytesRead != 0);

			//tmpProgBar->SetPos(0);	

			return TempPacketCount;
		}


INT GetSearchPartition(INT PacketIndex)
{

	return ((PacketIndex) / PARTITION_SIZE);
}

INT GetSearchPosition(INT PacketIndex)
{
INT TmpIndex = GetSearchPartition(PacketIndex);

return PacketPosition[TmpIndex];
}

INT GetSearchIndex(INT PacketIndex)
{

INT TmpIndex = GetSearchPartition(PacketIndex);

//PacketIndex[0] =0;
//PacketIndex[CurrentPartition] = TmpIndex;					

return PartionPositionArray[TmpIndex];
}
