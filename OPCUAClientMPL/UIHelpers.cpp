#include "stdafx.h"
#include "UIHelpers.h"

namespace UIHelpers
{
  void EnableDlgItem(HWND hWnd, int iId, BOOL bEnable = TRUE)
  {
    ASSERT(hWnd != NULL);
    ASSERT(::IsWindow(hWnd));
    HWND hWndItem = ::GetDlgItem(hWnd, iId);
    ASSERT(hWndItem != NULL);
    ASSERT(::IsWindow(hWndItem));

    ::EnableWindow(hWndItem, bEnable);
  }
};