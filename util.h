#pragma once

extern volatile const UCHAR guz;

inline HRESULT GetLastHr(ULONG dwError = GetLastError())
{
	return dwError ? HRESULT_FROM_WIN32(dwError) : S_OK;
}

inline HRESULT GetLastHr(BOOL fOk)
{
	return fOk ? S_OK : HRESULT_FROM_WIN32(GetLastError());
}

inline ULONG BOOL_TO_ERROR(BOOL f)
{
	return f ? NOERROR : GetLastError();
}

HRESULT GetLastHrEx(ULONG dwError = GetLastError());

inline HANDLE fixH(HANDLE hFile)
{
	return INVALID_HANDLE_VALUE == hFile ? 0 : hFile;
}

template <typename T> 
T HR(HRESULT& hr, T t)
{
	hr = t ? NOERROR : GetLastError();
	return t;
}

struct Bstr 
{
	BSTR _M_bstr;

	Bstr(PCWSTR psz)
	{
		_M_bstr = SysAllocString(psz);
	}

	~Bstr()
	{
		SysFreeString(_M_bstr);
	}

	operator BSTR()
	{
		return _M_bstr;
	}
};

#define ToData(bstr) (PBYTE)bstr, SysStringByteLen(bstr)

inline HRESULT Decode(_In_ PCSTR lpszStructType, _In_ PBYTE pb, _In_ ULONG cb, _Out_ void* ppv, _Out_opt_ PULONG pcb = 0)
{
	return CryptDecodeObjectEx(X509_ASN_ENCODING, lpszStructType, pb, cb,
		CRYPT_DECODE_ALLOC_FLAG|
		CRYPT_DECODE_NOCOPY_FLAG|
		CRYPT_DECODE_NO_SIGNATURE_BYTE_REVERSAL_FLAG|
		CRYPT_DECODE_SHARE_OID_STRING_FLAG, 
		0, ppv, pcb ? pcb : &cb) ? S_OK : HRESULT_FROM_WIN32(GetLastError());
}

inline HRESULT Decode(_In_ PCSTR lpszStructType, _In_ BSTR bstr, _Out_ void* ppv, _Out_opt_ PULONG pcb = 0)
{
	return Decode(lpszStructType, ToData(bstr), ppv, pcb);
}

inline HRESULT Decode(_In_ PCSTR lpszStructType, _In_ PCRYPT_DATA_BLOB pdb, _Out_ void* ppv, _Out_opt_ PULONG pcb = 0)
{
	return Decode(lpszStructType, pdb->pbData, pdb->cbData, ppv, pcb);
}

inline HRESULT Decode(_In_ PCSTR lpszStructType, _In_ PCRYPT_BIT_BLOB pdb, _Out_ void* ppv, _Out_opt_ PULONG pcb = 0)
{
	return Decode(lpszStructType, pdb->pbData, pdb->cbData, ppv, pcb);
}

void DumpRequest_PKCS_10(PBYTE pb, ULONG cb);

inline void DumpRequest_PKCS_10(BSTR request)
{
	DumpRequest_PKCS_10(ToData(request));
}

inline void DumpRequest_PKCS_10(PDATA_BLOB pdb)
{
	DumpRequest_PKCS_10(pdb->pbData, pdb->cbData);
}

void DumpAttributes(DWORD cAttribute, PCRYPT_ATTRIBUTE rgAttribute);

void PrintWA_v(PCWSTR format, ...);

#define DbgPrint(fmt, ...) PrintWA_v(_CRT_WIDE(fmt), __VA_ARGS__ )

void PrintUTF8(PCWSTR pwz, ULONG cch);

inline void PrintUTF8(PCWSTR pwz)
{
	PrintUTF8(pwz, (ULONG)wcslen(pwz));
}

HRESULT PrintError(HRESULT dwError);

void InitPrintf();

void DumpBytesInLine(const UCHAR* pb, ULONG cb, PCSTR prefix /*= ""*/, PCSTR suffix = "\n");

HRESULT BuildPkcs10ForKDC(_Out_ CERTTRANSBLOB* request, 
						  _Out_writes_(cchKeyName) PWSTR pszKeyName,
						  _In_ ULONG cchKeyName);

HRESULT BuildPkcs10ForEA(_Out_ CERTTRANSBLOB* request, 
						 _Out_writes_(cchKeyName) PWSTR pszKeyName,
						 _In_ ULONG cchKeyName);

HRESULT BuildPkcs10ForSL(_Out_ CERTTRANSBLOB* request, _Out_ NCRYPT_KEY_HANDLE* phKey);

HRESULT CreateFakeCRL(_In_ HCERTSTORE hStore, _In_ PCWSTR pszName);

void DumpCMC(BSTR request);

NTSTATUS GetFullUserName(_In_ PCWSTR pszUserName, 
						 _In_ ULONG cbStruct, 
						 _In_ char c, 
						 _Out_ PVOID* ppv, 
						 _Out_ ULONG* pcb,
						 _Out_ PWSTR* pbuf,
						 _Out_ PSID UserSid,
						 _In_ ULONG cbUserSid);

HRESULT IsSrvRunning(_In_ PCWSTR lpServiceName);

NTSTATUS ImpersonateToken(_In_ const TOKEN_PRIVILEGES* RequiredSet);

HRESULT ImpersonateUser(_In_ PVOID pvAuthBuffer, _In_ ULONG cbAuthBuffer, _In_ PSID UserSid);

NTSTATUS RtlRevertToSelf();

HRESULT AddToMyStore(_In_ const BYTE *pbCertEncoded, 
					 _In_ DWORD cbCertEncoded, 
					 _In_ PCWSTR pwszContainerName,
					 _In_ ULONG dwStoreFlags,
					 _In_ ULONG dwKeyFlags);

HRESULT ReadFromFile(_In_ PCWSTR lpFileName, _Out_ BSTR* pbstrString, _In_ ULONG MaxSize = MAXUSHORT, _In_ ULONG MinSize = 0x10);
HRESULT ReadFromFile(_In_ PCWSTR lpFileName, _Out_ PDATA_BLOB pdb, _In_ ULONG MaxSize = MAXUSHORT, _In_ ULONG MinSize = 0x10);

HRESULT SaveToFile(_In_ PCWSTR lpFileName, _In_ const void* lpBuffer, _In_ ULONG nNumberOfBytesToWrite);

inline HRESULT SaveToFile(_In_ PCWSTR lpFileName, _In_ BSTR str)
{
	return SaveToFile(lpFileName, ToData(str));
}

HRESULT ExportToPfx(_In_ PCWSTR pszFile, 
					_In_ NCRYPT_KEY_HANDLE hKey,
					_In_ PCWSTR szPassword,
					_In_ const BYTE *pbCertEncoded, 
					_In_ ULONG cbCertEncoded);

HRESULT SignMsg(_In_ PCCERT_CONTEXT pCertContext,
				_In_ HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hCryptProvOrNCryptKey,
				_In_ ULONG dwKeySpec,
				_In_ CERTTRANSBLOB* Msg, 
				_In_ PCRYPT_ATTR_BLOB RequesterName,
				_Out_ CERTTRANSBLOB* request);

HRESULT ValidateCert(_In_ PCCERT_CONTEXT pCertContext, 
					 _In_ PCERT_CHAIN_PARA pChainPara,
					 _Out_opt_ PCCERT_CHAIN_CONTEXT* ppChainContext = 0);
