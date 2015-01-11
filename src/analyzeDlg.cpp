// analyzeDlg.cpp : implementation file
//
/*
*  author: amit tank
*  module : network traffic analyzer
*  file :  analyze app entry point. main UI.
*/


#include "stdafx.h"
#include "analyze.h"
#include "analyzeDlg.h"
#include "common.h"



#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// CAnalyzeDlg dialog
void WrapperPraseFrame(PUCHAR Frame, UINT FrameLength, PCHAR TmpString);


CAnalyzeDlg::CAnalyzeDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CAnalyzeDlg::IDD, pParent)
{
	//{{AFX_DATA_INIT(CAnalyzeDlg)
	m_pktContent = _T("");
	//}}AFX_DATA_INIT
	// Note that LoadIcon does not require a subsequent DestroyIcon in Win32
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CAnalyzeDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CAnalyzeDlg)
	DDX_Control(pDX, IDC_LSTPKTLIST, m_pktList);
	DDX_Text(pDX, IDC_TXTPKTCONTENT, m_pktContent);
	DDV_MaxChars(pDX, m_pktContent, MAX_PANE_SIZE);
	//}}AFX_DATA_MAP
}

BEGIN_MESSAGE_MAP(CAnalyzeDlg, CDialog)
	//{{AFX_MSG_MAP(CAnalyzeDlg)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_LBN_SETFOCUS(IDC_LSTPKTLIST, OnSetfocusLstpktlist)
	ON_LBN_SELCHANGE(IDC_LSTPKTLIST, OnSelchangeLstpktlist)
	ON_BN_CLICKED(IDC_BROWSE, OnBrowse)
	ON_BN_CLICKED(IDOK, OnExit)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CAnalyzeDlg message handlers

BOOL CAnalyzeDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon
	
	// TODO: Add extra initialization here
	
	return TRUE;  // return TRUE  unless you set the focus to a control
}

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CAnalyzeDlg::OnPaint() 
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, (WPARAM) dc.GetSafeHdc(), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

// The system calls this to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CAnalyzeDlg::OnQueryDragIcon()
{
	return (HCURSOR) m_hIcon;
}


void CAnalyzeDlg::OnSetfocusLstpktlist() 
{
	// TODO: Add your control notification handler code here
	
}

void CAnalyzeDlg::OnSelchangeLstpktlist() 
{
	// TODO: Add your control notification handler code here
	
	char Content[MAX_PANE_SIZE];
	char TmpString[512];
	UCHAR Frame[ETHERNET_FRAME_SIZE];
	UINT FrameLength;

	

//	memset(Frame,'*',ETHERNET_FRAME_SIZE);
   
//	wsprintf(str,"%d",m_pktList.GetCurSel());
	
//	MessageBox(NULL,str,MB_OK);
//	CopyPacketContent(Content);

	GetDumpContent(m_pktList.GetCurSel(),Content,Frame, &FrameLength);

	m_pktContent = Content;

	m_pktContent.MakeUpper();
	UpdateData(FALSE);


	WrapperPraseFrame(Frame, FrameLength, TmpString	);
//	wsprintf(TmpString,"Length is : %d ",lstrlen(TmpString));
	this->m_pktContent = this->m_pktContent + "\r\n --::"+ TmpString;
	UpdateData(FALSE);



}

void CAnalyzeDlg::OnBrowse() 
{

char str[10];
CFileDialog FDlg(TRUE,NULL,"*.dmp",OFN_EXPLORER | OFN_READONLY ,
				"Packet Dump Files (*.dmp)||",
				NULL);


		if(FDlg.DoModal() == IDOK) {

						lstrcpy(DumpFilePath,FDlg.GetPathName());

								if(hPktDumpFile != NULL){
									
									CloseHandle(hPktDumpFile);

								}
								
						OpenDumpFile();
						DUMPFILEOPEN = TRUE;
						TotalPacketCount = GetDumpPacketCount();
						
						

						m_pktList.ResetContent();
						m_pktContent.Empty();

						for(UINT nCount=0;nCount < TotalPacketCount;nCount++) {

										wsprintf(str,"%08d",nCount+1);
									
										m_pktList.InsertString(nCount,str);
										UpdateData(FALSE);
						}


						UpdateData(FALSE); 

						//(((AfxGetApp())->GetMainWnd())->GetDlgItem(IDC_PROGRESS))->SetPos(0);
						//GetDlgItem(IDC_PROGRESS)
						CWinApp * tmpWinApp = AfxGetApp();
						CDialog *tmpMainWnd = (CDialog*)tmpWinApp->GetMainWnd();
						CProgressCtrl *tmpProgBar = (CProgressCtrl*)tmpMainWnd->GetDlgItem(IDC_PROGRESS);
						tmpProgBar->SetPos(0);
		}
	
}

void CAnalyzeDlg::OnExit() 
{


	if(hPktDumpFile != NULL)
		CloseHandle(hPktDumpFile);

	CAnalyzeDlg::OnOK();
	
}


void WrapperPraseFrame(PUCHAR Frame, UINT FrameLength, PCHAR TmpString)
{
CURRENT_FRAME CurrentPacket;

	ParseFrame(Frame,FrameLength, &CurrentPacket,TmpString);

	return;
}
