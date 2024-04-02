// OPCUAClientMPLDlg.h : header file
//
#ifndef __OPCUACLIENTMPLDLG_H__
#define __OPCUACLIENTMPLDLG__
#pragma once
#include "ClientApplication.h"
#include "ClientSession.h"
#include "StatusCodeException.h"
#include "CustomDataType.h"
#include <map>
#include <set>

typedef std::vector<AnsiCStackQuickstart::EndpointDescription> TVecEndpoints;
typedef std::vector<OpcUa_DataValue> TVecDataValue;
typedef std::vector<AnsiCStackQuickstart::BrowseResult> TVecBrowseResult;
typedef std::vector<AnsiCStackQuickstart::ServerDescription> TVecServerDescription;
typedef std::map<CString, AnsiCStackQuickstart::BrowseResult> TMapBrowseResults;

// COPCUAClientMPLDlg dialog
class COPCUAClientMPLDlg : public CDialogEx
{
// Construction
public:
  COPCUAClientMPLDlg(CWnd* pParent = NULL);	// standard constructor
  ~COPCUAClientMPLDlg();

// Dialog Data
  enum { IDD = IDD_OPCUACLIENTMPL_DIALOG };

  protected:
  virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support


// Implementation
private:
  HICON m_hIcon;
  AnsiCStackQuickstart::ClientApplication m_application;
  AnsiCStackQuickstart::ClientSession m_session;
  TVecEndpoints m_endpoints;
  CString m_strAddress;
  CListBox m_cListBoxLog;
  CComboBox m_cComboEndpoints;
  CTreeCtrl m_cTreeNodes;
  TMapBrowseResults m_mapBrowseResults;
  CCriticalSection m_csLock;
  CImageList m_imgList;
  WORD m_wDlgCounter;

protected:
  // Generated message map functions
  virtual BOOL OnInitDialog();
  afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
  afx_msg void OnPaint();
  afx_msg HCURSOR OnQueryDragIcon();
  DECLARE_MESSAGE_MAP()
public:
  afx_msg void OnBnClickedButtonFindServers();
  void LogAndMessageBox(LPCTSTR);
  void Log(LPCTSTR, ...);

  afx_msg void OnBnClickedButtonConnect();
  CListBox m_cListBoxServers;
  afx_msg void OnDblclkTreenodes(NMHDR *pNMHDR, LRESULT *pResult);
  afx_msg void OnItemExpandingTreenodes(NMHDR *pNMHDR, LRESULT *pResult);
  afx_msg void OnClose();
  afx_msg void OnCancel();
  afx_msg void OnBnClickedOk();
private:
  void SafeCloseSession(void);
  BOOL IsThereChildOpened(void);
};

#endif