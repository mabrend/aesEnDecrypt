// stdafx.cpp : 只包括标准包含文件的源文件
// UserAuth.pch 将作为预编译头
// stdafx.obj 将包含预编译类型信息

#include "stdafx.h"
#include "AesEncryptor.h"

BOOL ECB_AesEncrypt(const CString& strKey, const CString& strSrcText, CString& strDestText)
{
	USES_CONVERSION;
	CAesEncryptor::m_nMode = 0;
	CAesEncryptor caes;
	std::string key = T2A(strKey);
	std::string src = T2A(strSrcText);
	int nKeyLength = key.length();
	if (!caes.init(key,nKeyLength))
	{
		return FALSE;
	}
	strDestText = caes.encrypt(src).c_str();

	return !strDestText.IsEmpty();
}

BOOL ECB_AesDecrypt(const CString& strKey,const CString& strSrcText, CString& strDestText)
{
	USES_CONVERSION;
	CAesEncryptor::m_nMode = 0;
	CAesEncryptor caes;
	std::string key = T2A(strKey);
	std::string src = T2A(strSrcText);
	int nKeyLength = key.size();

	if (!caes.init(key,nKeyLength))
	{
		return FALSE;
	}
	strDestText = caes.decrypt(src).c_str();

	return !strDestText.IsEmpty();
}

BOOL CBC_AesEncrypt(const CString& strKey, const CString& strIV, CString& strSrcText, CString& strDestText)
{
	USES_CONVERSION;
	CAesEncryptor::m_nMode = 1;
	CAesEncryptor caes;
	std::string key = T2A(strKey);
	std::string src = T2A(strSrcText);
	std::string iv = T2A(strIV);
	int nKeyLength = key.length();
	if (0 == iv.size())
	{
		return false;
	}
	if (!caes.init(key,nKeyLength,iv))
	{
		return false;
	}
	strDestText = caes.encrypt(src).c_str();

	return !strDestText.IsEmpty();
}

BOOL CBC_AesDecrypt(const CString& strKey, const CString& strIV, CString& strSrcText, CString& strDestText)
{
	USES_CONVERSION;
	CAesEncryptor::m_nMode = 1;
	CAesEncryptor caes;
	std::string key = T2A(strKey);
	std::string iv = T2A(strIV);
	std::string src = T2A(strSrcText);
	int nKeyLength = key.length();
	if (0 == iv.size())
	{
		return false;
	}
	if (!caes.init(key, nKeyLength, iv))
	{
		return false;
	}
	strDestText = caes.decrypt(src).c_str();

	return !strDestText.IsEmpty();
}




