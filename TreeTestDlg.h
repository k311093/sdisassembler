
// TreeTestDlg.h : PROJECT_NAME ���� ���α׷��� ���� �� ��� �����Դϴ�.
//

#pragma once

#ifndef __AFXWIN_H__
	#error "PCH�� ���� �� ������ �����ϱ� ���� 'stdafx.h'�� �����մϴ�."
#endif

#include "resource.h"		// �� ��ȣ�Դϴ�.


// CTreeTestDlgApp:
// �� Ŭ������ ������ ���ؼ��� TreeTestDlg.cpp�� �����Ͻʽÿ�.
//

class CTreeTestDlgApp : public CWinAppEx
{
public:
	CTreeTestDlgApp();

// �������Դϴ�.
	public:
	virtual BOOL InitInstance();

// �����Դϴ�.

	DECLARE_MESSAGE_MAP()
};

extern CTreeTestDlgApp theApp;