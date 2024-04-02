// ReadDlg.cpp : implementation file
//

#include "stdafx.h"
#include "OPCUAClientMPL.h"
#include "ReadDlg.h"
#include "afxdialogex.h"
#include "Utils.h"
#include "UIHelpers.h"

using namespace AnsiCStackQuickstart;
using namespace UIHelpers;

namespace
{
  CString DateTimeToString(OpcUa_DateTime datetime)
  {
    CString strOut;

    FILETIME ft;
    memcpy(&ft, &datetime, sizeof(FILETIME));

    SYSTEMTIME st;
    ::FileTimeToSystemTime(&ft, &st);

    CString strMsg;
    strOut.Format("%04d-%02d-%02d %02d:%02d:%02d.%03d", st.wYear,
                                                        st.wMonth,
                                                        st.wDay,
                                                        st.wHour,
                                                        st.wMinute,
                                                        st.wSecond,
                                                        st.wMilliseconds);
    return strOut;
  }

  CString ValueToString(OpcUa_DataValue& rDataValue)
  {
    CString strOut;

    switch (rDataValue.Value.Datatype)
    {
      case OpcUaType_DateTime:
      {
        strOut = DateTimeToString(rDataValue.Value.Value.DateTime);
      } break;
    
      case OpcUaType_ExtensionObject:
      { // handle binary encoding.
        if (rDataValue.Value.Value.ExtensionObject->Encoding == OpcUa_ExtensionObjectEncoding_Binary)
        {
          strOut = "BinaryEncoded ExtensionObject: ";
          for (int ii = 0; ii < 80 && ii < rDataValue.Value.Value.ExtensionObject->Body.Binary.Length; ii++)
          {
            CString strAux;
            strAux.Format("%02X", rDataValue.Value.Value.ExtensionObject->Body.Binary.Data[ii]);
            strOut += strAux;
          }

          break;
        }
    
        // handle XML encoding.
        if (rDataValue.Value.Value.ExtensionObject->Encoding == OpcUa_ExtensionObjectEncoding_Xml)
        {
          strOut = "XML Encoded ExtensionObject: ";

          // XML data is UTF8 but without the NULL terminator.
          int iLength = rDataValue.Value.Value.ExtensionObject->Body.Xml.Length;
          iLength = (iLength > 80) ? 80 : iLength;

          char sBuffer[MAX_PATH] = { 0 };
          strncpy_s(sBuffer, MAX_PATH, (OpcUa_StringA)rDataValue.Value.Value.ExtensionObject->Body.Xml.Data, iLength);
          sBuffer[iLength] = '\0';
    
          // print a fragment.
          CString strAux;
          strAux.Format("%s", sBuffer);
          strOut += strAux;
          break;
        }

        // handle types known to the stack.
        if (rDataValue.Value.Value.ExtensionObject->Encoding == OpcUa_ExtensionObjectEncoding_EncodeableObject)
        {
          printf("ExtensionObject: %s ", rDataValue.Value.Value.ExtensionObject->Body.EncodeableObject.Type->TypeName);

          // This type is known because it was added to the type table in Application::Initialize
          // The NamespaceIndex was also set to 2 Application::Initialize (implied by the NamespaceURI array). 
          if (rDataValue.Value.Value.ExtensionObject->TypeId.NodeId.IdentifierType == OpcUa_IdentifierType_Numeric && 
            rDataValue.Value.Value.ExtensionObject->TypeId.NodeId.Identifier.Numeric == OpcUaId_CustomDataType_DefaultBinary &&
            rDataValue.Value.Value.ExtensionObject->TypeId.NodeId.NamespaceIndex == 2)
          {
            CustomDataType* pData = (CustomDataType*)rDataValue.Value.Value.ExtensionObject->Body.EncodeableObject.Object;
            strOut.Format(" (%d, %d)", pData->High, pData->Low);
          }
        }
      } break;
    
      case OpcUaType_Boolean:
      {
        strOut.Format("%u", rDataValue.Value.Value.Boolean != false);
      } break;

      case OpcUaType_Byte:
      {
        strOut.Format("%u", rDataValue.Value.Value.Byte);
      } break;

      case OpcUaType_UInt16:
      {
        strOut.Format("%u", rDataValue.Value.Value.UInt16);
      } break;

      case OpcUaType_UInt32:
      {
        strOut.Format("%u", rDataValue.Value.Value.UInt32);
      } break;

      case OpcUaType_UInt64:
      {
        strOut.Format("%u", rDataValue.Value.Value.UInt64);
      } break;

      case OpcUaType_SByte:
      {
        strOut.Format("%d", rDataValue.Value.Value.SByte);
      } break;

      case OpcUaType_Int16:
      {
        strOut.Format("%d", rDataValue.Value.Value.Int16);
      } break;

      case OpcUaType_Int32:
      {
        strOut.Format("%d", rDataValue.Value.Value.Int32);
      } break;

      case OpcUaType_Int64:
      {
        strOut.Format("%d", rDataValue.Value.Value.Int64);
      } break;

      case OpcUaType_Float:
      {
        strOut.Format("%f", rDataValue.Value.Value.Float);
      } break;

      case OpcUaType_Double:
      {
        strOut.Format("%f", rDataValue.Value.Value.Double);
      } break;

      case OpcUaType_String:
      {
        std::string str(Utils::Copy(&rDataValue.Value.Value.String));
        strOut = str.c_str();
      } break;

      default:
      {
        strOut.Format("%d", rDataValue.Value.Datatype);
      } break;
    }
    
    return strOut;
  }

  const DWORD MIN_SCAN = 100;
  const DWORD MAX_SCAN = 86400000;

  //CLogComm stLog;
}

CLogComm CReadDlg::stLog;

// CReadDlg dialog
IMPLEMENT_DYNAMIC(CReadDlg, CDialogEx)

CReadDlg::CReadDlg(CWnd* pParent /*=NULL*/,
                   ClientSession* psession,
                   const BrowseResult* pbr,
                   WORD& wDlgCounter)
  : CDialogEx(CReadDlg::IDD, pParent),
  m_psession(psession),
  m_nodeInfo(*pbr),
  m_dwScanTime(1000),
  m_hThread(NULL),
  m_hEvtShutDown(NULL),
  m_bStopThread(FALSE),
  m_strValue("Value:"),
  m_wDlgCounter(wDlgCounter)
{
  ASSERT(psession != NULL);
  ASSERT(pbr != NULL);
  ++m_wDlgCounter;
}

CReadDlg::~CReadDlg()
{
  StopThread();
  --m_wDlgCounter;
}

BOOL CReadDlg::OnInitDialog()
{
  CDialogEx::OnInitDialog();

  CString strText("Read Node: ");
  strText += m_nodeInfo.GetDisplayname().c_str();
  SetWindowText((LPCTSTR)strText);
  
  return TRUE;
}

void CReadDlg::DoDataExchange(CDataExchange* pDX)
{
  CDialogEx::DoDataExchange(pDX);
  DDX_Text(pDX, IDC_STATICVALUE, m_strValue);
  DDX_Text(pDX, IDC_EDITSCAN, m_dwScanTime);
	DDV_MinMaxUInt(pDX, m_dwScanTime, 100, 86400000);
}


BEGIN_MESSAGE_MAP(CReadDlg, CDialogEx)
  ON_BN_CLICKED(IDC_BUTTONREAD, &CReadDlg::OnBnClickedButtonRead)
  ON_WM_CLOSE()
  ON_BN_CLICKED(IDOK, &CReadDlg::OnBnClickedOk)
  ON_WM_NCDESTROY()
END_MESSAGE_MAP()


// CReadDlg message handlers
void CReadDlg::OnBnClickedButtonRead()
{
  UpdateData(TRUE);
  if (!IsThreadRunning())
  {
    if (m_dwScanTime < MIN_SCAN || m_dwScanTime > MAX_SCAN)
    {
      CString strMsg;
      strMsg.Format("Invalid scan time. Enter value between %u and %u.", MIN_SCAN, MAX_SCAN);
      MessageBox((LPCTSTR)strMsg, "Error", MB_ICONERROR);
      return;
    }
    StartThread();
    ::SetDlgItemText(this->m_hWnd, IDC_BUTTONREAD, "Stop read");
    EnableDlgItem(this->m_hWnd, IDC_EDITSCAN, FALSE);

    return;
  }

  StopThread();
  ::SetDlgItemText(this->m_hWnd, IDC_BUTTONREAD, "Start read");
  EnableDlgItem(this->m_hWnd, IDC_EDITSCAN, TRUE);
}

DWORD WINAPI CReadDlg::ThreadProc(LPVOID pvParam)
{
  ASSERT(pvParam != NULL);
  return (static_cast<CReadDlg*>(pvParam))->Run();
}

DWORD CReadDlg::Run(void)
{
  m_bStopThread = FALSE;

  DWORD dwExpire = ::GetTickCount();
  for (;;)
  {
    if (m_bStopThread)
      break;

    const DWORD dwNow = ::GetTickCount();
    const DWORD dwWaitTime = (dwExpire > dwNow) ? dwExpire - dwNow : 0;

    const DWORD dwRet = ::WaitForSingleObject(m_hEvtShutDown, dwWaitTime);
    if (dwRet == WAIT_TIMEOUT)
    {
      dwExpire = ::GetTickCount() + m_dwScanTime;

      HRESULT hr = ExecuteRead();
      if (FAILED(hr))
        break;
    }
    else /*if (dwRet == WAIT_OBJECT_0)*/
      break;
  }

  if (m_hThread != NULL)
  {
    CloseHandle(m_hThread);
    m_hThread = NULL;
    m_dwThreadId = 0;
  }

  return 0;
}

HRESULT CReadDlg::ExecuteRead()
{
  const std::string strDisplayName = m_nodeInfo.GetDisplayname();

  std::vector<OpcUa_DataValue> vDataValues;
  OpcUa_StatusCode uStatus = OpcUa_Good;

  if (!m_psession->IsActive())
  {
    MessageBox("Session is not active.", "Error", MB_ICONERROR);
    return E_FAIL;
  }

  try
  {
    const DWORD dwBefore = ::GetTickCount();
    uStatus = m_psession->ReadValue(m_nodeInfo.GetNodeId(), vDataValues);
    const DWORD dwAfter = ::GetTickCount();
    if (dwAfter >= dwBefore)
      stLog.LogElapsedTime(strDisplayName.c_str(), dwAfter - dwBefore);
  }
  catch (StatusCodeException e)
  {
    uStatus = e.GetCode();
    std::string strAux = Utils::StatusToString(uStatus);
    
    CString str;
    str.Format("Status: %s", strAux.c_str());
    ::SetDlgItemText(this->m_hWnd, IDC_STATICSTATUS, (LPCTSTR)str);

    return S_OK;
  }

  for (std::vector<OpcUa_DataValue>::iterator it = vDataValues.begin(); it != vDataValues.end(); it++)
  {
    OpcUa_DataValue value = *it;
    CString str;
    CString strStatus;
    if (OpcUa_IsGood(value.StatusCode))
    {
      strStatus = "Good";
      str.Format("Value: %s", (LPCTSTR)ValueToString(value));
      ::SetDlgItemText(this->m_hWnd, IDC_STATICVALUE, (LPCTSTR)str);
      str.Format("Time: %s", (LPCTSTR)DateTimeToString(value.ServerTimestamp));
      ::SetDlgItemText(this->m_hWnd, IDC_STATICTIME, (LPCTSTR)str);
    }
    else
    {
      std::string strAux = Utils::StatusToString(value.StatusCode);
      strStatus.Format("%s", strAux.c_str());
    }
    str.Format("Status: %s", (LPCTSTR)strStatus);
    ::SetDlgItemText(this->m_hWnd, IDC_STATICSTATUS, (LPCTSTR)str);
  }

  return S_OK;
}

HRESULT CReadDlg::StartThread(void)
{
  if (IsThreadRunning())
    return S_OK;

  m_hEvtShutDown = ::CreateEvent(NULL, FALSE, FALSE, NULL);
  if (m_hEvtShutDown == NULL)
    return E_FAIL;
  
  m_hThread = ::CreateThread(NULL, 0, CReadDlg::ThreadProc, this, CREATE_SUSPENDED, &m_dwThreadId);
  if (m_hThread == NULL)
    return E_FAIL;

  ::ResumeThread(m_hThread);

  return S_OK;
}

void CReadDlg::StopThread(void)
{
  if (!IsThreadRunning())
    return;

  CSingleLock lock(&m_cs, TRUE);
  if (m_hEvtShutDown != NULL)
    ::SetEvent(m_hEvtShutDown);

  m_bStopThread = TRUE;
  lock.Unlock();

  ::CloseHandle(m_hEvtShutDown);
  m_hEvtShutDown = NULL;

/*
  if (m_hThread != NULL)
  {
    if (WaitForSingleObject(m_hThread, 1000) == WAIT_TIMEOUT)
      ::TerminateThread(m_hThread, (DWORD)-1000);

    ::CloseHandle(m_hThread);
  }*/
}

void CReadDlg::OnClose()
{
  StopThread();
  DestroyWindow();
}

void CReadDlg::OnCancel()
{
  OnClose();
}

void CReadDlg::OnBnClickedOk()
{
  OnClose();
}

void CReadDlg::OnNcDestroy()
{
  StopThread();
  CDialogEx::OnNcDestroy();

  delete this;
}
