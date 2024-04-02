#ifndef __READDLG_H__
#define __READDLG_H__
#pragma once

//#include "OPCUAClientMPLDlg.h"
#include "ClientSession.h"
#include "CustomDataType.h"
#include "LogComm.h"

// CReadDlg dialog

class CReadDlg : public CDialogEx
{
	DECLARE_DYNAMIC(CReadDlg)

public:
	CReadDlg(CWnd* pParent/* = NULL*/,
           AnsiCStackQuickstart::ClientSession* psession/* = NULL*/,
           const AnsiCStackQuickstart::BrowseResult* pbr/* = NULL*/,
           WORD& wDlgCounter);   // standard constructor
	~CReadDlg();

  //COPCUAClientMPLDlg m_parentDlg;
  AnsiCStackQuickstart::ClientSession* m_psession;
  AnsiCStackQuickstart::BrowseResult m_nodeInfo;

// Dialog Data
	enum { IDD = IDD_DIALOGREAD };

protected:
  // Generated message map functions
  virtual BOOL OnInitDialog();
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
public:
  afx_msg void OnBnClickedButtonRead();
  DWORD m_dwScanTime;
  CString m_strValue;

private:
  static DWORD WINAPI ThreadProc(LPVOID pvParam);
  DWORD Run(void);
  HRESULT StartThread(void);
  void StopThread(void);
  BOOL IsThreadRunning(void) const { return m_hThread != NULL; };
  HRESULT CReadDlg::ExecuteRead();
  HANDLE m_hThread;
  HANDLE m_hEvtShutDown;
  DWORD m_dwThreadId;
  BOOL m_bStopThread;
  CCriticalSection m_cs;
  WORD& m_wDlgCounter;
  static CLogComm stLog;

public:
  afx_msg void OnClose();
  afx_msg void OnCancel();
  afx_msg void OnBnClickedOk();
  afx_msg void OnNcDestroy();
};

#endif