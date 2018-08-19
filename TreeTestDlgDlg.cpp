
// TreeTestDlgDlg.cpp : 구현 파일
//

#include "stdafx.h"
#include "TreeTestDlg.h"
#include "TreeTestDlgDlg.h"

#include "Types.h"
#include "OpCodeTab.h"
#include "InstructionParser.h"
#include "PeParser.h"
#include "Mnemonics.h"

#include <iostream>
#include <sstream>
#include <vector>
#include <string>
#include <set>
#include <map>

using namespace std;

set<ULONG64> visited;

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CTreeTestDlgDlg 대화 상자

FILE *fp;


CTreeTestDlgDlg::CTreeTestDlgDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CTreeTestDlgDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CTreeTestDlgDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_TREE1, tree);
}

BEGIN_MESSAGE_MAP(CTreeTestDlgDlg, CDialog)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	//}}AFX_MSG_MAP
	ON_BN_CLICKED(IDC_BUTTON1, &CTreeTestDlgDlg::OnBnClickedButton1)
END_MESSAGE_MAP()

bool malware = false;
bool mfc = false;
bool getdc = false;
bool debug = false;

extern std::map<std::wstring, PeParser*> dllmap;

std::set<pair<int,int> > depthset;

ULONG64 hex2ll(char* hexStr)
{
	ULONG64 ret = 0L;
	size_t index = 0;
	ULONG64 val = 0;

	index = 2;

	while(hexStr[index] != 0)
	{
		ret <<= 4;
		if(hexStr[index] >= '0' && hexStr[index] <= '9') val = hexStr[index]-'0';
		else if(hexStr[index] >= 'a' && hexStr[index] <= 'f') val = hexStr[index]-'a'+10;
		else if(hexStr[index] >= 'A' && hexStr[index] <= 'F') val = hexStr[index]-'A'+10;
		ret |= val;
		++index;
	}

	return ret;
}

TCHAR dllName[1024];
TCHAR dllPath[1024];
char tmpDllName[1024];
char tmp[1024];
char tmpdll[1024];
char funcName[1024];
int depth = 0;
wstringstream graphitem, label;

int CTreeTestDlgDlg::TraverseCall(PeParser& peFile, InstructionParser parser, ULONG64 address)
{
	InstructionParser::ParsedInstruction instr;
	char addrBuf[20] = {0,};
	char tmp[1024];
	char edge[1024];
	char currentItem[1024];
	HTREEITEM inserted = NULL;
	HTREEITEM trueChild = NULL;
	HTREEITEM falseChild = NULL;
	HTREEITEM upChild = NULL;
	bool append = true;
	int ret = 0;
	int funcret = 0;

	
	if(visited.find(address) != visited.end()) {
		return 0;
	}
	

	if (depth > 200) return 2;

	visited.insert(address);

	sprintf(currentItem, "%08llx", address);
	if (depth == 0) sprintf(currentItem, "EntryPoint");

	label.clear();
	label.flush();

	parser.SetOrigin(address);
	parser.SetMachineCode(peFile.GetVirtualMemoryBuffer(parser.GetOrigin()));
	parser.SetCurrentParsingLocation(parser.GetOrigin());

	while (true)
	{
		append = true;
		wstringstream sstream;
		//visited.insert(parser.GetCurrentParsingLocation());
		sprintf(tmp, "%016llx : ", parser.GetCurrentParsingLocation());
		parser.ParseInstruction(instr);

		sstream << tmp;

		sstream << instr.mnemonic << " ";
		if (instr.has_op1) { sstream << instr.op1; }
		if (instr.has_op2) { sstream << ", " << instr.op2; }
		if (instr.has_op3) { sstream << ", " << instr.op3; }

		if (instr.mnemonic_num == MNEMONIC_JMP)
		{

			if(strlen(instr.op1) > 6 && instr.op1[6] == '[') {
				strncpy(addrBuf, instr.op1+7, strlen(instr.op1)-8);
				sstream << "\t; " <<  peFile.callName(hex2ll(addrBuf), funcName);
				if ((sstream.str().find(_T("mfc")) != sstream.str().npos) && (sstream.str().find(_T("ordinal_")) != sstream.str().npos))
					mfc = true;
			}
		}

		else if (instr.IsConditionalBranch())
		{
			if(strlen(instr.op1) > 6 && instr.op1[6] == '[') {
				strncpy(addrBuf, instr.op1+7, strlen(instr.op1)-8);
				sstream << "\t; " <<  peFile.callName(hex2ll(addrBuf), funcName);
			}
		}


		else if (instr.mnemonic_num == MNEMONIC_CALL)
		{
			if(strlen(instr.op1) > 6 && instr.op1[6] == '[') {
				strncpy(addrBuf, instr.op1+7, strlen(instr.op1)-8);
				sstream << "\t; " <<  peFile.callName(hex2ll(addrBuf), funcName);

				if (sstream.str().find(_T("Console")) != sstream.str().npos)
					malware = true;
				if (sstream.str().find(_T("GetDC")) != sstream.str().npos)
					getdc = true;
				if (sstream.str().find(_T("IsDebuggerPresent")) != sstream.str().npos)
					debug = true;

			}
		}

		else {
			append = true;
		}

		if(append) {
			//inserted = tree.InsertItem(sstream.str().c_str(), parent);
			label << sstream.str().c_str() << _T("\\l")<< "\\n";
		}

		if (instr.mnemonic_num == MNEMONIC_JMP)
		{
			if (instr.op1[0] == '0') {
				depth++;
				funcret = TraverseCall(peFile, parser, hex2ll(instr.op1));
				depth--;
				if (funcret == 0) {
			//		tree.DeleteItem(inserted);
				}
				else {
					//sprintf(tmp, "%08llx", hex2ll(instr.op1));
					//sprintf(edge, "edge[label=\"jmp\"] addr_%s; addr_%s -> addr_%s; edge[label=\"\"]", tmp, currentItem, tmp);
					//fprintf(fp, "%s\n", edge);
				}
				ret += funcret;
				break;
			}
			else if(strlen(instr.op1) > 7 && instr.op1[6] == '[' && instr.op1[7] == '0') {
				PeParser* dllFile;
				InstructionParser curparser;
				char *func;
				peFile.callName(hex2ll(addrBuf), funcName);

				if(strcmp(funcName, "none")) {

					strcpy(tmpdll, funcName);
					strcpy(tmpDllName, strtok(tmpdll, "!"));

					func = strtok(NULL, "\0");

					MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, tmpDllName, strlen(tmpDllName)+1, dllName, 1024);

					wsprintf(dllPath, _T("c:\\dlls\\%s"), dllName);

					strncpy(addrBuf, instr.op1+7, strlen(instr.op1)-8);
					strcpy(tmp, addrBuf+2);
					if(depthset.find(std::make_pair(depth, depth+1)) == depthset.end()) {
						depthset.insert(std::make_pair(depth, depth+1));
						sprintf(edge, "depth%d -> depth%d; depth%d -> func%s; func%s[label=\"%s\"]",depth, depth+1, depth+1, tmp, tmp, peFile.callName(hex2ll(addrBuf), funcName));
					}
					else
					{
						sprintf(edge, "depth%d -> func%s; func%s[label=\"%s\"]",depth+1, tmp, tmp, peFile.callName(hex2ll(addrBuf), funcName));
					}
					fprintf(fp, "%s\n", edge);

					if (dllmap.find(dllPath) == dllmap.end()) {OutputDebugString(_T("Cannot Find")); OutputDebugString(dllPath);}
					else {
						dllFile = dllmap[dllPath];


						curparser.SetMachineType(dllFile->GetMachineType());

						depth++;
						funcret = TraverseCall(*dllFile, curparser, dllFile->GetFuncAddr(func)+dllFile->GetImageBase());
						depth--;
						if(funcret == 1) {
							//upChild = tree.GetChildItem(inserted);
							//tree.InsertItem(tree.GetItemText(upChild), parent);
							//tree.DeleteItem(inserted);
						}
						if (funcret == 0) {
							//tree.DeleteItem(inserted);
						}
						ret += funcret;
					}

				}

				ret++;
				break;
			}
		}

		else if (instr.IsConditionalBranch())
		{
			//trueChild = tree.InsertItem(wstring(sstream.str()+_T(" : True")).c_str(), parent);
			//tree.DeleteItem(inserted);
			if (instr.op1[0] == '0') {
				depth++;
				funcret = TraverseCall(peFile, parser, hex2ll(instr.op1));
				depth--;
				if(funcret == 1) {
			//		upChild = tree.GetChildItem(trueChild);
			//		tree.InsertItem(tree.GetItemText(upChild), parent);
			//		tree.DeleteItem(trueChild);
				}
				if (funcret == 0) {
			//		tree.DeleteItem(trueChild);
				}
				else {
// 					sprintf(tmp, "%08llx", hex2ll(instr.op1));
// 					sprintf(edge, "edge[label=\"true\"] addr_%s -> addr_%s; edge[label=\"\"] ", currentItem, tmp);
// 					fprintf(fp, "%s\n", edge);
				}
			//	falseChild = tree.InsertItem(wstring(sstream.str()+_T(" : False")).c_str(), parent);
				ret += funcret;
				depth++;
				funcret = TraverseCall(peFile, parser, parser.GetCurrentParsingLocation());
				depth--;
				if(funcret == 1) {
			//		upChild = tree.GetChildItem(falseChild);
			//		tree.InsertItem(tree.GetItemText(upChild), parent);
			//		tree.DeleteItem(falseChild);
				}
				if (funcret == 0) {
			//		tree.DeleteItem(falseChild);
				}
				else {
// 					sprintf(tmp, "%08llx",  parser.GetCurrentParsingLocation());
// 					sprintf(edge, "edge[label=\"false\"] addr_%s -> addr_%s; edge[label=\"\"]", currentItem, tmp);
// 					fprintf(fp, "%s\n", edge);
				}
				ret += funcret;
				break;
			}
			if(strlen(instr.op1) > 6 && instr.op1[6] == '[') {
				depth++;
				ret = TraverseCall(peFile, parser, parser.GetCurrentParsingLocation());
				depth--;
// 				sprintf(tmp, "%08llx",  parser.GetCurrentParsingLocation());
// 				sprintf(edge, "addr_%s -> addr_%s;", currentItem, tmp);
// 				fprintf(fp, "%s\n", edge);
				break;
			}
		}


		else if (instr.mnemonic_num == MNEMONIC_CALL)
		{
			if (instr.op1[0] == '0') {
				depth++;
				funcret = TraverseCall(peFile, parser, hex2ll(instr.op1));
				depth--;
				if(funcret == 1) {
			//		upChild = tree.GetChildItem(inserted);
			//		tree.InsertItem(tree.GetItemText(upChild), parent);
			//		tree.DeleteItem(inserted);
				}
				if (funcret == 0) {
			//		tree.DeleteItem(inserted);
				}
				else {
// 					sprintf(tmp, "%08llx", hex2ll(instr.op1));
// 					sprintf(edge, "edge[label=\"call\"] addr_%s -> addr_%s; edge[label=\"\"]", currentItem, tmp);
// 					fprintf(fp, "%s\n", edge);
				}
				ret += funcret;
			}
			if(strlen(instr.op1) > 6 && instr.op1[6] == '[' && instr.op1[7] == '0') {
				PeParser* dllFile;
				InstructionParser curparser;
				char *func;
				peFile.callName(hex2ll(addrBuf), funcName);

				if(strcmp(funcName, "none")) {

					strcpy(tmpdll, funcName);
					strcpy(tmpDllName, strtok(tmpdll, "!"));

					func = strtok(NULL, "\0");

					MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, tmpDllName, strlen(tmpDllName)+1, dllName, 1024);

					wsprintf(dllPath, _T("c:\\dlls\\%s"), dllName);

					strncpy(addrBuf, instr.op1+7, strlen(instr.op1)-8);
					strcpy(tmp, addrBuf+2);
					if(depthset.find(std::make_pair(depth, depth+1)) == depthset.end()) {
						depthset.insert(std::make_pair(depth, depth+1));
						sprintf(edge, "depth%d -> depth%d; depth%d -> func%s; func%s[label=\"%s\"]",depth, depth+1, depth+1, tmp, tmp, peFile.callName(hex2ll(addrBuf), funcName));
					}
					else
					{
						sprintf(edge, "depth%d -> func%s; func%s[label=\"%s\"]",depth+1, tmp, tmp, peFile.callName(hex2ll(addrBuf), funcName));
					}
					//sprintf(edge, "depth%d -> addr%s0; addr%s0 -> func%s0; func%s0[label=\"%s\"]",depth, currentItem, currentItem, tmp, tmp, peFile.callName(hex2ll(addrBuf), funcName));
					fprintf(fp, "%s\n", edge);

					if (dllmap.find(dllPath) == dllmap.end()) {OutputDebugString(_T("Cannot Find")); OutputDebugString(dllPath);}
					else {
						dllFile = dllmap[dllPath];
						

						curparser.SetMachineType(dllFile->GetMachineType());

						depth++;
						funcret = TraverseCall(*dllFile, curparser, dllFile->GetFuncAddr(func)+dllFile->GetImageBase());
						depth--;
						if(funcret == 1) {
							//upChild = tree.GetChildItem(inserted);
							//tree.InsertItem(tree.GetItemText(upChild), parent);
							//tree.DeleteItem(inserted);
						}
						if (funcret == 0) {
							//tree.DeleteItem(inserted);
						}
						ret += funcret;
					}

				}
			}
		}

		

		else if (instr.mnemonic_num == MNEMONIC_RETN)
		{
			break;
		}
		else if (instr.mnemonic_num == MNEMONIC_INT)
		{
			break;
		}
	}

	//fprintf(fp, "addr_%s[label=",currentItem);
	//fwprintf(fp, _T("\"%s\"]\n"), label.str().c_str());

	ret = 2;

	return ret;

}

// CTreeTestDlgDlg 메시지 처리기

BOOL CTreeTestDlgDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// 이 대화 상자의 아이콘을 설정합니다. 응용 프로그램의 주 창이 대화 상자가 아닐 경우에는
	//  프레임워크가 이 작업을 자동으로 수행합니다.
	SetIcon(m_hIcon, TRUE);			// 큰 아이콘을 설정합니다.
	SetIcon(m_hIcon, FALSE);		// 작은 아이콘을 설정합니다.

	// TODO: 여기에 추가 초기화 작업을 추가합니다.

	return TRUE;  // 포커스를 컨트롤에 설정하지 않으면 TRUE를 반환합니다.
}

// 대화 상자에 최소화 단추를 추가할 경우 아이콘을 그리려면
//  아래 코드가 필요합니다. 문서/뷰 모델을 사용하는 MFC 응용 프로그램의 경우에는
//  프레임워크에서 이 작업을 자동으로 수행합니다.

void CTreeTestDlgDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 그리기를 위한 디바이스 컨텍스트

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 클라이언트 사각형에서 아이콘을 가운데에 맞춥니다.
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 아이콘을 그립니다.
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

// 사용자가 최소화된 창을 끄는 동안에 커서가 표시되도록 시스템에서
//  이 함수를 호출합니다.
HCURSOR CTreeTestDlgDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


void CTreeTestDlgDlg::OnBnClickedButton1()
{
	// TODO: 여기에 컨트롤 알림 처리기 코드를 추가합니다.
	PeParser peFile;
	InstructionParser parser;

	CFileDialog diag(TRUE, NULL, _T("*.exe;*.aye;*.dll"));
	HTREEITEM rootitem;
	

	diag.DoModal();

	if (peFile.Open(diag.GetPathName()) == E_FAIL) {
		AfxMessageBox(_T("Open Fail"));
	}
	else {
		fp = fopen("test.txt","w");
		fprintf(fp, "digraph g {\nnode[shape=\"record\"]\n");
		//peFile.Test();
		parser.SetMachineType(peFile.GetMachineType());
		visited.clear();
		tree.DeleteAllItems();
		rootitem = tree.InsertItem(diag.GetFileName());
		malware = false;
		mfc = false;
		getdc = false;
		debug = false;
		depthset.clear();
		depth = 0;
		TraverseCall(peFile, parser, peFile.GetEntryPointAddr());
		if(malware) {
			this->SetWindowText(_T("악성이래"));
		}
		else if(debug) {
			this->SetWindowText(_T("디버그본대"));
		}
		else if(mfc) {
			this->SetWindowText(_T("MFC래"));
		}
		else if(getdc) {
			this->SetWindowText(_T("그린대"));
		}
		
		else {
			this->SetWindowText(_T("아니래"));
		}
		fprintf(fp, "}\n");
		fclose(fp);
	}

}
