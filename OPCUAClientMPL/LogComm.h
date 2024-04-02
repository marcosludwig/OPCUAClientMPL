#ifndef __LOGCOMM_H__
#define __LOGCOMM_H__
#pragma once

#ifdef _DEBUG
//#define LOGFILENAME _T("C:\\Users\\Marcos\\Documents\\Visual Studio 2010\\Projects\\OPCUAClientMPL\\Debug\\OPCUAClientMPL.log")
#define LOGFILENAME _T("OPCUAClientMPL_d.log")
#else
//#define LOGFILENAME _T("C:\\Users\\Marcos\\Documents\\Visual Studio 2010\\Projects\\OPCUAClientMPL\\Release\\OPCUAClientMPL.log")
#define LOGFILENAME _T("OPCUAClientMPL.log")
#endif

class CLogComm
{
public:
  CLogComm(void);
  ~CLogComm(void);

  CString m_strLog;
  CCriticalSection m_csLockLog;

  void SaveLogComm(void)
  {
    CSingleLock lock(&m_csLockLog, TRUE);
    CFile file;

    char strPathName[_MAX_PATH];
    ::GetModuleFileName(NULL, strPathName, _MAX_PATH);

    // The following code will allow you to get the path.
    CString newPath(strPathName);
    int fpos = newPath.ReverseFind('\\');

    if (fpos != -1)
      newPath = newPath.Left(fpos + 1);

    newPath += LOGFILENAME;

    if (file.Open((LPCTSTR)newPath, CFile::modeReadWrite))
    {
      file.SeekToEnd();
      file.Write((BYTE*)(LPCSTR)m_strLog, (unsigned)m_strLog.GetLength());
      file.Flush();
      file.Close();
    }
  }

  void AppendLog(LPCTSTR pszLog)
  {
    CSingleLock lock(&m_csLockLog, TRUE);
    m_strLog += pszLog;
    m_strLog += "\r\n";
  }

  void LogElapsedTime(LPCTSTR pszName, const DWORD dwElapsedTime)
  {
    CString str;
    str.Format("%s Read:\t(%u,%03u)", pszName, dwElapsedTime / 1000, dwElapsedTime % 1000);
    AppendLog((LPCTSTR)str);
  }

  void LogElapsedTime(const DWORD dwElapsedTime)
  {
    CString str;
    str.Format("%u,%03u", dwElapsedTime / 1000, dwElapsedTime % 1000);
    AppendLog((LPCTSTR)str);
  }
};

#endif