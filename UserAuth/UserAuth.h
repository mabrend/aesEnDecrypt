// UserAuth.h : UserAuth DLL ����ͷ�ļ�
//

#pragma once

#ifndef __AFXWIN_H__
	#error "�ڰ������ļ�֮ǰ������stdafx.h�������� PCH �ļ�"
#endif

#include "resource.h"		// ������


// CUserAuthApp
// �йش���ʵ�ֵ���Ϣ������� UserAuth.cpp
//

class CUserAuthApp : public CWinApp
{
public:
	CUserAuthApp();

// ��д
public:
	virtual BOOL InitInstance();

	DECLARE_MESSAGE_MAP()
};

