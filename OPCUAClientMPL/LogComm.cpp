#include "stdafx.h"
#include "LogComm.h"


CLogComm::CLogComm(void) : m_strLog("===\r\n")
{
}


CLogComm::~CLogComm(void)
{
  SaveLogComm();
}
