#if !defined(AFX_PKTLIST_H__EA50510F_28F3_11D5_8765_0050BA8EE547__INCLUDED_)
#define AFX_PKTLIST_H__EA50510F_28F3_11D5_8765_0050BA8EE547__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000
// PktList.h : header file
//
/*
*  author: amit tank
*  module : network traffic analyzer
*  file : packetlist 
*/


/////////////////////////////////////////////////////////////////////////////
// CPktList window

class CPktList : public CListBox
{
// Construction
public:
	CPktList();

// Attributes
public:

// Operations
public:

// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CPktList)
	//}}AFX_VIRTUAL

// Implementation
public:
	virtual ~CPktList();

	// Generated message map functions
protected:
	//{{AFX_MSG(CPktList)
		// NOTE - the ClassWizard will add and remove member functions here.
	//}}AFX_MSG

	DECLARE_MESSAGE_MAP()
};

/////////////////////////////////////////////////////////////////////////////

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_PKTLIST_H__EA50510F_28F3_11D5_8765_0050BA8EE547__INCLUDED_)
