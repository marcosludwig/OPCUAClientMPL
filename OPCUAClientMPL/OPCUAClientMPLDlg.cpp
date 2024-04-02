
// OPCUAClientMPLDlg.cpp : implementation file
//

#include "stdafx.h"
#include "OPCUAClientMPL.h"
#include "OPCUAClientMPLDlg.h"
#include "afxdialogex.h"
#include "ReadDlg.h"
#include "UIHelpers.h"

#define APP_NAME (_T("OPCUA Client MPL"))

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

using namespace AnsiCStackQuickstart;
using namespace UIHelpers;

namespace
{
  LPCTSTR DUMMYNODE = _T("DUMMYNODE");
  
  const int IDX_ICONOBJECT   = 0;
  const int IDX_ICONVARIABLE = 1;

  const int stIcons[] =
  {
    IDI_ICONOBJECT,
    IDI_ICONVARIABLE,
  };
}
// CAboutDlg dialog used for App About

class CAboutDlg : public CDialogEx
{
public:
  CAboutDlg();

// Dialog Data
  enum { IDD = IDD_ABOUTBOX };

  protected:
  virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

// Implementation
protected:
  DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
  CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// COPCUAClientMPLDlg dialog

COPCUAClientMPLDlg::COPCUAClientMPLDlg(CWnd* pParent /*=NULL*/)
  : CDialogEx(COPCUAClientMPLDlg::IDD, pParent),
  m_strAddress("localhost"),
  m_session(&m_application),
  m_wDlgCounter(0)
{
  m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

COPCUAClientMPLDlg::~COPCUAClientMPLDlg()
{
}

BOOL COPCUAClientMPLDlg::IsThereChildOpened(void)
{
  if (m_wDlgCounter > 0)
  {
    MessageBox("You should close all Node windows before procceed with this operation.", APP_NAME, MB_ICONWARNING);
    return TRUE;
  }

  return FALSE;
}

void COPCUAClientMPLDlg::SafeCloseSession(void)
{
  if (m_session.IsActive())
  {
    try
    {
      m_session.Close();
    }
    catch (...)
    {
      Log("Could not close session.");
    }
    Log("Session closed!");
  }
}

void COPCUAClientMPLDlg::DoDataExchange(CDataExchange* pDX)
{
  CDialogEx::DoDataExchange(pDX);
  DDX_Text(pDX, IDC_EDITADDRESS, m_strAddress);
  //  DDX_LBString(pDX, IDC_LISTLOG, m_strContent);
  DDX_Control(pDX, IDC_LISTLOG, m_cListBoxLog);
  DDX_Control(pDX, IDC_COMBOENDPOINTS, m_cComboEndpoints);
  DDX_Control(pDX, IDC_TREENODES, m_cTreeNodes);
  //  DDX_Control(pDX, IDC_LISTSERVERS, m_cListServers);
  DDX_Control(pDX, IDC_LISTSERVERS, m_cListBoxServers);
}

BEGIN_MESSAGE_MAP(COPCUAClientMPLDlg, CDialogEx)
  ON_WM_SYSCOMMAND()
  ON_WM_PAINT()
  ON_WM_QUERYDRAGICON()
  ON_BN_CLICKED(IDC_BUTTONSERVERS, &COPCUAClientMPLDlg::OnBnClickedButtonFindServers)
  ON_BN_CLICKED(IDC_BUTTONCONNECT, &COPCUAClientMPLDlg::OnBnClickedButtonConnect)
  //ON_NOTIFY(TVN_SELCHANGED, IDC_TREENODES, &COPCUAClientMPLDlg::OnTvnSelchangedTreenodes)
  ON_NOTIFY(NM_DBLCLK, IDC_TREENODES, &COPCUAClientMPLDlg::OnDblclkTreenodes)
  ON_NOTIFY(TVN_ITEMEXPANDING, IDC_TREENODES, &COPCUAClientMPLDlg::OnItemExpandingTreenodes)
  ON_WM_CLOSE()
  ON_BN_CLICKED(IDOK, &COPCUAClientMPLDlg::OnBnClickedOk)
END_MESSAGE_MAP()


// COPCUAClientMPLDlg message handlers

BOOL COPCUAClientMPLDlg::OnInitDialog()
{
  CDialogEx::OnInitDialog();

  // Add "About..." menu item to system menu.

  // IDM_ABOUTBOX must be in the system command range.
  ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
  ASSERT(IDM_ABOUTBOX < 0xF000);

  CMenu* pSysMenu = GetSystemMenu(FALSE);
  if (pSysMenu != NULL)
  {
    BOOL bNameValid;
    CString strAboutMenu;
    bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
    ASSERT(bNameValid);
    if (!strAboutMenu.IsEmpty())
    {
      pSysMenu->AppendMenu(MF_SEPARATOR);
      pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
    }
  }

  // Set the icon for this dialog.  The framework does this automatically
  //  when the application's main window is not a dialog
  SetIcon(m_hIcon, TRUE);     // Set big icon
  SetIcon(m_hIcon, FALSE);    // Set small icon

  // TODO: Add extra initialization here
  m_imgList.Create(16, 16, ILC_COLOR24 | ILC_MASK, 0, 1);
  for (size_t n = 0; n < sizeof(stIcons) / sizeof(stIcons[0]); n++)
    m_imgList.Add(theApp.LoadIcon(MAKEINTRESOURCE(stIcons[n])));

  try
  {
    // set the application identity.
    m_application.SetApplicationName("OPCUAClientMPL");

    m_application.SetProductUri("http://opcfoundation.org/UASDK/Quickstarts/CppClient");

    // initialize the application and the stack.
    m_application.Initialize();

    // initialize security by specifying the client certificate and the location of the trusted certificates.
    m_application.InitializeSecurity(".\\CertificateStore");
  }
	catch (StatusCodeException e)
	{
    CString strExc;
    strExc.Format("ERROR [0x%08X]: %s", e.GetCode(), e.GetMessage());

		LogAndMessageBox((LPCTSTR)strExc);
	}

  return TRUE;  // return TRUE  unless you set the focus to a control
}

void COPCUAClientMPLDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
  if ((nID & 0xFFF0) == IDM_ABOUTBOX)
  {
    CAboutDlg dlgAbout;
    dlgAbout.DoModal();
  }
  else
  {
    CDialogEx::OnSysCommand(nID, lParam);
  }
}

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void COPCUAClientMPLDlg::OnPaint()
{
  if (IsIconic())
  {
    CPaintDC dc(this); // device context for painting

    SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

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
    CDialogEx::OnPaint();
  }
}

// The system calls this function to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR COPCUAClientMPLDlg::OnQueryDragIcon()
{
  return static_cast<HCURSOR>(m_hIcon);
}

void COPCUAClientMPLDlg::LogAndMessageBox(LPCTSTR pszLog)
{
  MessageBox(pszLog, APP_NAME, MB_ICONERROR);
  Log(pszLog);
}

void COPCUAClientMPLDlg::Log(LPCTSTR pszLog, ...)
{
  CSingleLock lock(&m_csLock, TRUE);

  va_list args;
  va_start(args, pszLog);
  CString str;
  str.FormatV(pszLog, args);
  m_cListBoxLog.AddString(str);
  const int nCount = m_cListBoxLog.GetCount();
  if (nCount > 0)
    m_cListBoxLog.SetCurSel(nCount - 1);
  UpdateData(FALSE);
}

void COPCUAClientMPLDlg::OnBnClickedButtonFindServers()
{
  UpdateData(TRUE);
  if (m_strAddress.IsEmpty())
  {
    LogAndMessageBox("Invalid host name address!");
    return;
  }

  // find the servers on the localhost.
  TVecServerDescription servers;
  try
  {
    servers = m_application.FindServers((LPCTSTR)m_strAddress);
  }
  catch (...)
  {
    LogAndMessageBox("Error finding servers!");
    return;
  }

  // prompt user to select a server.
  for (size_t n = 0; n < servers.size(); n++)
  {
    CString strAux;
    strAux.Format("%s (%s)", servers[n].GetServerName().c_str(), servers[n].GetDiscoveryUrl().c_str());
    m_cListBoxServers.AddString((LPCTSTR)strAux);
    UpdateData(FALSE);
    CString strLog("Server found: ");
    strLog += strAux;
    Log((LPCTSTR)strLog);
  }

  // find the endpoints for the servers.
  for (size_t n = 0; n < servers.size(); n++)
  {
    TVecEndpoints endpointsAux;
    try
    {
      endpointsAux = m_application.DiscoverEndpoints(servers[n].GetDiscoveryUrl());
    }
    catch (...)
    {
      Log("Error discovering endpoints for server #%u.", n);
      continue;
    }

    for (TVecEndpoints::iterator it = endpointsAux.begin(); it != endpointsAux.end(); it++)
      m_endpoints.push_back(*it);
  }

  if (m_endpoints.empty())
  {
    LogAndMessageBox("Error discovering endpoints!");
    return;
  }

  EnableDlgItem(this->m_hWnd, IDC_EDITADDRESS, FALSE);
  EnableDlgItem(this->m_hWnd, IDC_BUTTONSERVERS, FALSE);
  
  // prompt user to select an endpoint.
  CString strFirstEndpoint;
  for (size_t n = 0; n < m_endpoints.size(); n++)
  {
    std::string url = m_endpoints[n].GetEndpointUrl();

    if (url.find("opc.tcp") == std::string::npos)
      continue;

    std::string policy = m_endpoints[n].GetSecurityPolicyUri();
    std::string::size_type index = policy.rfind("#");

    if (index == std::string::npos)
      continue;

    policy = policy.substr(index + 1);

    CString strAux;
    strAux.Format("%s (%s - %d)", url.c_str(), policy.c_str(), m_endpoints[n].GetSecurityMode());
    m_cComboEndpoints.AddString((LPCTSTR)strAux);
    const int iIdx = m_cComboEndpoints.GetCount() - 1;
    m_cComboEndpoints.SetItemData(iIdx, n);

    if (strFirstEndpoint.IsEmpty())
    {
      strFirstEndpoint = strAux;
      m_cComboEndpoints.SelectString(0, (LPCTSTR)strFirstEndpoint);
    }
    UpdateData(FALSE);
    CString strLog("Endpoint found: ");
    strLog += strAux;
    Log(strAux);
  }
}


void COPCUAClientMPLDlg::OnBnClickedButtonConnect()
{
  if (m_session.IsActive())
  { // Disconnect...
    if (IsThereChildOpened())
      return;

    SafeCloseSession();
    m_cTreeNodes.DeleteAllItems();
    m_mapBrowseResults.clear();
    
    ::SetDlgItemText(this->m_hWnd, IDC_BUTTONCONNECT, "Connect");
    EnableDlgItem(this->m_hWnd, IDC_COMBOENDPOINTS, TRUE);
    return;
  }

  int nIndex = m_cComboEndpoints.GetCurSel();
  int nCount = m_cComboEndpoints.GetCount();
  if ((nIndex == CB_ERR) || (nCount < 1))
  {
    LogAndMessageBox("There are no Endpoints loaded on this application!");
    return;
  }

  const DWORD dwItemData = m_cComboEndpoints.GetItemData(nIndex);
  if (m_endpoints[dwItemData].GetSecurityMode() != OpcUa_MessageSecurityMode_None)
    m_application.TrustCertificate(m_endpoints[dwItemData].GetServerCertificate());

  try
  {
    m_session.Create(m_endpoints[dwItemData], "OPCUAClientMPL");
  }
  catch (...)
  {
    LogAndMessageBox("Error trying to create session!");
    return;
  }
  try 
  {
    m_session.Activate();
  }
  catch (...)
  {
    SafeCloseSession(); // Close Session...
    LogAndMessageBox("Error trying activate session!");
    return;
  }

  ::SetDlgItemText(this->m_hWnd, IDC_BUTTONCONNECT, "Disconnect");
  EnableDlgItem(this->m_hWnd, IDC_COMBOENDPOINTS, FALSE);

  OpcUa_NodeId objectsFolderId;
  objectsFolderId.IdentifierType = OpcUa_IdentifierType_Numeric;
  objectsFolderId.Identifier.Numeric = OpcUaId_ObjectsFolder;
  objectsFolderId.NamespaceIndex = 0;

  TVecBrowseResult browseResults;
  try
  {
    browseResults = m_session.Browse(objectsFolderId);
  }
  catch (...)
  {
    LogAndMessageBox("Error browsing node!");
    return;
  }

  Log("Browse returned %d items!", browseResults.size());

  m_cTreeNodes.SetImageList(&m_imgList, TVSIL_NORMAL);

  HTREEITEM htParent = m_cTreeNodes.InsertItem("Objects", 0, 0, NULL, NULL);
  for (unsigned int i = 0; i < browseResults.size(); i++)
  {
    const CString strDisplayName(browseResults[i].GetDisplayname().c_str());
    if (m_mapBrowseResults.find(strDisplayName) == m_mapBrowseResults.end())
    {
      Log("Item %d: %s", i, (LPCTSTR)strDisplayName);
      const int iIcon = browseResults[i].GetNodeClass() == OpcUa_NodeClass_Variable ? 1 : 0;
      HTREEITEM htItem = m_cTreeNodes.InsertItem(strDisplayName, iIcon, iIcon, htParent, NULL);
      m_cTreeNodes.InsertItem(DUMMYNODE, 0, 0, htItem, NULL);
      m_mapBrowseResults[strDisplayName] = browseResults[i];
    }
  }
  TreeView_Expand(m_cTreeNodes.m_hWnd, htParent, TVE_EXPAND);
}

void COPCUAClientMPLDlg::OnDblclkTreenodes(NMHDR *pNMHDR, LRESULT *pResult)
{
  LPNMTREEVIEW pNMTreeView = reinterpret_cast<LPNMTREEVIEW>(pNMHDR);
  (void)pNMTreeView; // To avoid not used warning.

  const HTREEITEM htItem = m_cTreeNodes.GetSelectedItem();

  const CString strItem = m_cTreeNodes.GetItemText(htItem);
  if (m_mapBrowseResults.find(strItem) == m_mapBrowseResults.end())
    return;

  BrowseResult br = m_mapBrowseResults[strItem];
  if (br.GetNodeClass() == OpcUa_NodeClass_Object)
    return;

  // Modeless dialog created dynamically which will be deleted from itself.
  CReadDlg* pDlg = new CReadDlg(this, &m_session, &br, m_wDlgCounter);
  if (pDlg != NULL)
  {
    pDlg->Create(CReadDlg::IDD);
    pDlg->ShowWindow(SW_SHOW);
  }

  *pResult = 0;
}


void COPCUAClientMPLDlg::OnItemExpandingTreenodes(NMHDR *pNMHDR, LRESULT *pResult)
{
  LPNMTREEVIEW pNMTreeView = reinterpret_cast<LPNMTREEVIEW>(pNMHDR);
  int action = (int)pNMTreeView->action;
  if (action != TVE_EXPAND)
    return;
  
  TVITEM tvitem = (TVITEM)pNMTreeView->itemNew;
  const HTREEITEM htItem = tvitem.hItem;
  
  const CString strItem = m_cTreeNodes.GetItemText(htItem);
  if (m_mapBrowseResults.find(strItem) == m_mapBrowseResults.end())
    return;

  HTREEITEM htDummy = m_cTreeNodes.GetChildItem(htItem);
  const CString strDummy = m_cTreeNodes.GetItemText(htDummy);
  if (strDummy.CompareNoCase(DUMMYNODE) == 0)
    m_cTreeNodes.DeleteItem(htDummy);

  BrowseResult br = m_mapBrowseResults[strItem];
  OpcUa_NodeId nodeId = br.GetNodeId();

  TVecBrowseResult vBrowseResults;
  try
  {
    vBrowseResults = m_session.Browse(nodeId);
  }
  catch (...)
  {
    LogAndMessageBox("Error browsing node!");
    return;
  }

  if (vBrowseResults.size() > 0)
  {
    Log("Browse returned %d items!", vBrowseResults.size());
    for (unsigned int i = 0; i < vBrowseResults.size(); i++)
    {
      const CString strDisplayName(vBrowseResults[i].GetDisplayname().c_str());
      if (m_mapBrowseResults.find(strDisplayName) == m_mapBrowseResults.end())
      {
        Log("Item %d: %s", i, (LPCTSTR)strDisplayName);
        
        const int iIcon = vBrowseResults[i].GetNodeClass() == OpcUa_NodeClass_Variable ? 1 : 0;
        HTREEITEM ht = m_cTreeNodes.InsertItem((LPCTSTR)strDisplayName, iIcon, iIcon, htItem, NULL);
        m_cTreeNodes.InsertItem(DUMMYNODE, 0, 0, ht, NULL);
        m_mapBrowseResults[(LPCTSTR)strDisplayName] = vBrowseResults[i];
      }
    }
    TreeView_Expand(m_cTreeNodes.m_hWnd, htItem, 0);
  }
  
  *pResult = 0;
}


void COPCUAClientMPLDlg::OnClose()
{
  if (IsThereChildOpened())
    return;

  SafeCloseSession();

  CDialogEx::OnClose();
}

void COPCUAClientMPLDlg::OnCancel()
{
  if (IsThereChildOpened())
    return;

  SafeCloseSession();

  CDialogEx::OnCancel();
}

void COPCUAClientMPLDlg::OnBnClickedOk()
{
  if (IsThereChildOpened())
    return;

  SafeCloseSession();

  CDialogEx::OnOK();
}