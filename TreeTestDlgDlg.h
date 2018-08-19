
// TreeTestDlgDlg.h : ��� ����
//

#pragma once

#include "Types.h"
#include "OpCodeTab.h"
#include "InstructionParser.h"
#include "PeParser.h"
#include "afxcmn.h"


// CTreeTestDlgDlg ��ȭ ����
class CTreeTestDlgDlg : public CDialog
{
// �����Դϴ�.
public:
	CTreeTestDlgDlg(CWnd* pParent = NULL);	// ǥ�� �������Դϴ�.

// ��ȭ ���� �������Դϴ�.
	enum { IDD = IDD_TREETESTDLG_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV �����Դϴ�.

	int TraverseCall(PeParser& peFile, InstructionParser parser, ULONG64 address);

// �����Դϴ�.
protected:
	HICON m_hIcon;

	// ������ �޽��� �� �Լ�
	virtual BOOL OnInitDialog();
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedButton1();
	CTreeCtrl tree;
};
