// analyzeDlg.h : header file
//
//{{AFX_INCLUDES()
#include "commondialog.h"
//}}AFX_INCLUDES

#if !defined(AFX_ANALYZEDLG_H__EA505107_28F3_11D5_8765_0050BA8EE547__INCLUDED_)
#define AFX_ANALYZEDLG_H__EA505107_28F3_11D5_8765_0050BA8EE547__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

/////////////////////////////////////////////////////////////////////////////
// CAnalyzeDlg dialog

class CAnalyzeDlg : public CDialog
{
// Construction
public:
	CAnalyzeDlg(CWnd* pParent = NULL);	// standard constructor

// Dialog Data
	//{{AFX_DATA(CAnalyzeDlg)
	enum { IDD = IDD_ANALYZE_DIALOG };
	CListBox	m_pktList;
	CString	m_pktContent;

	//}}AFX_DATA

	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CAnalyzeDlg)
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:
	HICON m_hIcon;

	// Generated message map functions
	//{{AFX_MSG(CAnalyzeDlg)
	virtual BOOL OnInitDialog();
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	afx_msg void OnSetfocusLstpktlist();
	afx_msg void OnSelchangeLstpktlist();
	afx_msg void OnBrowse();
	afx_msg void OnExit();
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_ANALYZEDLG_H__EA505107_28F3_11D5_8765_0050BA8EE547__INCLUDED_)
