#include "StdAfx.h"
#include "AesEncryptor.h"
using namespace std;

int CAesEncryptor::m_nMode = 0;
bool CAesEncryptor::init(const string& key,int nLength, const string& iv) 
{
	/*
    if (key.size() != CryptoPP::AES::DEFAULT_KEYLENGTH || iv.size() != CryptoPP::AES::BLOCKSIZE) 
	{
        return false;
    }

    for(int i = 0; i < CryptoPP::AES::DEFAULT_KEYLENGTH; i++) 
	{
        s_key[i] = key[i];
    }

    for(int i = 0; i < CryptoPP::AES::BLOCKSIZE; i++) 
	{
        s_iv[i] = iv[i];
    }*/
	if (nLength > 32 || nLength < 16 || nLength % 8 != 0)
	{
		return false;
	}
	memset(s_iv, 0, CryptoPP::AES::MAX_KEYLENGTH);
	memset(s_key, 0, CryptoPP::AES::MAX_KEYLENGTH);
	if (!iv.empty())
	{
		if (iv.size() < 16)
		{
			return false;
		}
		else
		{
			for (int i = 0; i < CryptoPP::AES::BLOCKSIZE; i++)
			{
				s_iv[i] = iv[i];
			}
		}
	}
	m_nKeyLength = nLength;
	for (int i = 0; i < nLength; i++)
	{
		s_key[i] = key[i];
	}

	return true;
}


void CAesEncryptor::Byte2Hex(const unsigned char* src, int len, char* dest) 
{
	for (int i=0; i<len; ++i) 
	{
		sprintf_s(dest + i * 2, 2, "%02X", src[i]);    
	}
}

void CAesEncryptor::Hex2Byte(const char* src, int len, char* dest) 
{
	int length = len / 2;
	for (int i=0; i<length; ++i) {
		dest[i] = Char2Int(src[i * 2]) * 16 + Char2Int(src[i * 2 + 1]);
	}
}

int CAesEncryptor::Char2Int(char c) 
{
	if ('0' <= c && c <= '9') {
		return (c - '0');
	}
	else if ('a' <= c && c<= 'f') {
		return (c - 'a' + 10);
	}
	else if ('A' <= c && c<= 'F') {
		return (c - 'A' + 10);
	}
	return -1;
}

int CAesEncryptor::getKeyLength()
{
	return m_nKeyLength;
}

string CAesEncryptor::encrypt(const string& plainText)
{
	string cipherTextHex;
	try
	{
		string cipherText;
		CryptoPP::AES::Encryption aesEncryption(s_key, getKeyLength());
		if (m_nMode == 0)
		{
			CryptoPP::ECB_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption);
			CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(cipherText), CryptoPP::BlockPaddingSchemeDef::PKCS_PADDING);
			stfEncryptor.Put(reinterpret_cast<const unsigned char*>(plainText.c_str()), plainText.length());
			stfEncryptor.MessageEnd();
		}
		else if (m_nMode == 1)
		{
			CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, s_iv);
			CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(cipherText), CryptoPP::BlockPaddingSchemeDef::PKCS_PADDING);
			stfEncryptor.Put(reinterpret_cast<const unsigned char*>(plainText.c_str()), plainText.length());
			stfEncryptor.MessageEnd();

		}		
		
		for (unsigned int i = 0; i < cipherText.size(); i++)
		{
			char ch[3] = { 0 };
			sprintf(ch, "%02x", static_cast<byte>(cipherText[i]));
			cipherTextHex += ch;
		}
	}
	catch (const std::exception &e)
	{
		cipherTextHex = "";
	}

	return cipherTextHex;
}

string CAesEncryptor::decrypt(const string& cipherTextHex)
{
	string cipherText;
	string decryptedText;
/*
	char* pbuffer = new char[cipherTextHex.length()+1];
	memset(pbuffer, 0, cipherTextHex.length());
	Hex2Byte(cipherTextHex.c_str(), cipherTextHex.length(), pbuffer);
	cipherText = pbuffer;
	SAFE_DELETE_OBJECTS(pbuffer);
*/
	char* pbuffer = new char[cipherTextHex.length() + 1];
	memset(pbuffer, 0, cipherTextHex.length());
	strcpy(pbuffer, cipherTextHex.c_str());
	const char* hex_str = pbuffer;
	unsigned int ch;
	for (; std::sscanf(hex_str, "%2x", &ch) == 1; hex_str += 2)
		cipherText += ch;
	SAFE_DELETE_OBJECTS(pbuffer);
	try
	{
		CryptoPP::AES::Decryption aesDecryption(s_key, getKeyLength());
		if (0 == m_nMode)
		{
			CryptoPP::ECB_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption);
			CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(decryptedText), CryptoPP::BlockPaddingSchemeDef::PKCS_PADDING);
			stfDecryptor.Put(reinterpret_cast<const unsigned char*>(cipherText.c_str()), cipherText.size());
			stfDecryptor.MessageEnd();
		}
		else if (1 == m_nMode)
		{
			CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, s_iv);
			CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(decryptedText), CryptoPP::BlockPaddingSchemeDef::PKCS_PADDING);
			stfDecryptor.Put(reinterpret_cast<const unsigned char*>(cipherText.c_str()), cipherText.size());
			stfDecryptor.MessageEnd();
		}
	}
	catch (const std::exception &e) {
		decryptedText = "";
	}

	return decryptedText;
}