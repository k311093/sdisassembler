
// TreeTestDlgDlg.h : 헤더 파일
//

#pragma once

#include "Types.h"
#include "OpCodeTab.h"
#include "InstructionParser.h"
#include "PeParser.h"
#include "afxcmn.h"


// CTreeTestDlgDlg 대화 상자
class CTreeTestDlgDlg : public CDialog
{
// 생성입니다.
public:
	CTreeTestDlgDlg(CWnd* pParent = NULL);	// 표준 생성자입니다.

// 대화 상자 데이터입니다.
	enum { IDD = IDD_TREETESTDLG_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 지원입니다.

	int TraverseCall(PeParser& peFile, InstructionParser parser, ULONG64 address);

// 구현입니다.
protected:
	HICON m_hIcon;

	// 생성된 메시지 맵 함수
	virtual BOOL OnInitDialog();
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedButton1();
	CTreeCtrl tree;
};
