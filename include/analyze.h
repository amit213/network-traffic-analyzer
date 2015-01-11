// analyze.h : main header file for the ANALYZE application
//

#if !defined(AFX_ANALYZE_H__EA505105_28F3_11D5_8765_0050BA8EE547__INCLUDED_)
#define AFX_ANALYZE_H__EA505105_28F3_11D5_8765_0050BA8EE547__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#ifndef __AFXWIN_H__
	#error include 'stdafx.h' before including this file for PCH
#endif

#include "resource.h"		// main symbols

/////////////////////////////////////////////////////////////////////////////
// CAnalyzeApp:
// See analyze.cpp for the implementation of this class
//


class CAnalyzeApp : public CWinApp
{
public:


	CAnalyzeApp();

// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CAnalyzeApp)
	public:
	virtual BOOL InitInstance();
	//}}AFX_VIRTUAL

// Implementation

	//{{AFX_MSG(CAnalyzeApp)
		// NOTE - the ClassWizard will add and remove member functions here.
		//    DO NOT EDIT what you see in these blocks of generated code !
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};


/////////////////////////////////////////////////////////////////////////////

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_ANALYZE_H__EA505105_28F3_11D5_8765_0050BA8EE547__INCLUDED_)
