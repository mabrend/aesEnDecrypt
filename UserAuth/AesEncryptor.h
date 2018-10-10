#define CRYPTOPP_DEFAULT_NO_DLL
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include "dll.h"
//#pragma comment(lib, "cryptlib.lib")

#define SAFE_DELETE_OBJECTS(p) if(p) {delete[] p;p=NULL;}
class CAesEncryptor 
{
public:
	bool init(const std::string& key, int nLength,const std::string& iv = "");
	std::string encrypt(const std::string& inputPlainText);
	std::string decrypt(const std::string& cipherTextHex);
	void Byte2Hex(const unsigned char* src, int len, char* dest);
	void Hex2Byte(const char* src, int len, char* dest);
	int Char2Int(char c);
	int getKeyLength();
	static int m_nMode;
private:
	byte s_key[CryptoPP::AES::MAX_KEYLENGTH];
	byte s_iv[CryptoPP::AES::MAX_KEYLENGTH];
	int m_nKeyLength;
};
