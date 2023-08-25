#include "stdafx.h"

#include "util.h"

#if 0
HRESULT GetLastHrEx(ULONG dwError /*= GetLastError()*/)
{
	NTSTATUS status = RtlGetLastNtStatus();
	return RtlNtStatusToDosErrorNoTeb(status) == dwError ? HRESULT_FROM_NT(status) : HRESULT_FROM_WIN32(dwError);
}

void DumpBytesInLine(const UCHAR* pb, ULONG cb, PCSTR prefix /*= ""*/, PCSTR suffix/* = "\n"*/)
{
	if (cb)
	{
		PSTR psz = 0;
		ULONG cch = 0;
		while(CryptBinaryToStringA(pb, cb, CRYPT_STRING_HEXRAW|CRYPT_STRING_NOCRLF, psz, &cch))
		{
			if (psz)
			{
				DbgPrint("%S%S%S", prefix, psz, suffix);
				break;
			}

			psz = (PSTR)alloca(cch);
		}
	}
}
#endif

HRESULT AddToMyStore(_In_ const BYTE *pbCertEncoded, 
					 _In_ DWORD cbCertEncoded, 
					 _In_ PCWSTR pwszContainerName,
					 _In_ ULONG dwStoreFlags,
					 _In_ ULONG dwKeyFlags)
{
	HRESULT hr;

	if (HCERTSTORE hCertStore = HR(hr, CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0, dwStoreFlags, L"MY")))
	{
		if (PCCERT_CONTEXT pCertContext = HR(hr, CertCreateCertificateContext(X509_ASN_ENCODING, pbCertEncoded, cbCertEncoded)))
		{
			CRYPT_KEY_PROV_INFO kpi = {
				const_cast<PWSTR>(pwszContainerName), 
				const_cast<PWSTR>(MS_KEY_STORAGE_PROVIDER), 
				0, 
				dwKeyFlags
			};

			if (HR(hr, CertSetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, 0, &kpi)))
			{
				hr = BOOL_TO_ERROR(CertAddCertificateContextToStore(hCertStore, pCertContext, CERT_STORE_ADD_REPLACE_EXISTING, 0));
			}

			CertFreeCertificateContext(pCertContext);
		}

		CertCloseStore(hCertStore, 0);
	}

	DbgPrint("AddToMyStore = %u\r\n", hr);

	return HRESULT_FROM_WIN32(hr);
}

HRESULT ReadFromFile(_In_ PCWSTR lpFileName, _Out_ BSTR* pbstrString, _In_ ULONG MaxSize/* = MAXUSHORT*/, _In_ ULONG MinSize/* = 0x10*/)
{
	HANDLE hFile = fixH(CreateFileW(lpFileName, FILE_GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0));

	if (!hFile)
	{
		return GetLastHrEx();
	}

	FILE_STANDARD_INFORMATION fsi;
	IO_STATUS_BLOCK iosb;
	NTSTATUS status = NtQueryInformationFile(hFile, &iosb, &fsi, sizeof(fsi), FileStandardInformation);

	if (0 <= status)
	{
		if (fsi.EndOfFile.QuadPart - MinSize > MaxSize)
		{
			status = STATUS_FILE_TOO_LARGE;
		}
		else
		{
			if (BSTR bstrString = SysAllocStringByteLen(0, fsi.EndOfFile.LowPart))//
			{
				if (0 > (status = NtReadFile(hFile, 0, 0, 0, &iosb, bstrString, fsi.EndOfFile.LowPart, 0, 0)))
				{
					SysFreeString(bstrString);
				}
				else
				{
					*pbstrString = bstrString;
				}
			}
			else
			{
				status = STATUS_NO_MEMORY;
			}
		}
	}

	NtClose(hFile);

	return status ? HRESULT_FROM_NT(status) : S_OK;
}

HRESULT ReadFromFile(_In_ PCWSTR lpFileName, _Out_ PDATA_BLOB pdb, _In_ ULONG MaxSize/* = MAXUSHORT*/, _In_ ULONG MinSize/* = 0x10*/)
{
	HANDLE hFile = fixH(CreateFileW(lpFileName, FILE_GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0));

	if (!hFile)
	{
		return GetLastHrEx();
	}

	FILE_STANDARD_INFORMATION fsi;
	IO_STATUS_BLOCK iosb;
	NTSTATUS status = NtQueryInformationFile(hFile, &iosb, &fsi, sizeof(fsi), FileStandardInformation);

	if (0 <= status)
	{
		if (fsi.EndOfFile.QuadPart - MinSize > MaxSize)
		{
			status = STATUS_FILE_TOO_LARGE;
		}
		else
		{
			if (PBYTE pb = (PBYTE)LocalAlloc(LMEM_FIXED, fsi.EndOfFile.LowPart))
			{
				if (0 > (status = NtReadFile(hFile, 0, 0, 0, &iosb, pb, fsi.EndOfFile.LowPart, 0, 0)))
				{
					LocalFree(pb);
				}
				else
				{
					pdb->pbData = pb;
					pdb->cbData = (ULONG)iosb.Information;
				}
			}
			else
			{
				status = STATUS_NO_MEMORY;
			}
		}
	}

	NtClose(hFile);

	return status ? HRESULT_FROM_NT(status) : S_OK;
}

HRESULT SaveToFile(_In_ PCWSTR lpFileName, _In_ const void* lpBuffer, _In_ ULONG nNumberOfBytesToWrite)
{
	UNICODE_STRING ObjectName;

	NTSTATUS status = RtlDosPathNameToNtPathName_U_WithStatus(lpFileName, &ObjectName, 0, 0);

	if (0 <= status)
	{
		HANDLE hFile;
		IO_STATUS_BLOCK iosb;
		OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };

		LARGE_INTEGER AllocationSize = { nNumberOfBytesToWrite };

		status = NtCreateFile(&hFile, FILE_APPEND_DATA|SYNCHRONIZE, &oa, &iosb, &AllocationSize,
			0, 0, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT|FILE_NON_DIRECTORY_FILE, 0, 0);

		RtlFreeUnicodeString(&ObjectName);

		if (0 <= status)
		{
			status = NtWriteFile(hFile, 0, 0, 0, &iosb, const_cast<void*>(lpBuffer), nNumberOfBytesToWrite, 0, 0);
			NtClose(hFile);
		}
	}

	return status ? HRESULT_FROM_NT(status) : S_OK;
}

HRESULT ExportToPfx(_In_ PCWSTR pszFile, 
					_In_ NCRYPT_KEY_HANDLE hKey,
					_In_ PCWSTR szPassword,
					_In_ const BYTE *pbCertEncoded, 
					_In_ ULONG cbCertEncoded)
{
	CERT_KEY_CONTEXT ckc = { sizeof(ckc), { hKey }, CERT_NCRYPT_KEY_SPEC };

	HRESULT hr;

	if (HCERTSTORE hStore = HR(hr, CertOpenStore(sz_CERT_STORE_PROV_MEMORY, 0, 0, 0, 0)))
	{
		PCCERT_CONTEXT pCertContext;

		if (HR(hr, CertAddEncodedCertificateToStore(hStore, X509_ASN_ENCODING, 
			pbCertEncoded, cbCertEncoded, CERT_STORE_ADD_ALWAYS, &pCertContext)))
		{
			if (HR(hr, CertSetCertificateContextProperty(pCertContext, 
				CERT_KEY_CONTEXT_PROP_ID, CERT_STORE_NO_CRYPT_RELEASE_FLAG, &ckc)))
			{
				CRYPT_DATA_BLOB PFX = { cbCertEncoded << 2, new UCHAR[PFX.cbData] };

				if (PFX.pbData)
				{
					if (HR(hr, PFXExportCertStoreEx(hStore, &PFX, szPassword, 0, 
						EXPORT_PRIVATE_KEYS|REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY)))
					{
						hr = SaveToFile(pszFile, PFX.pbData, PFX.cbData);
					}
					delete [] PFX.pbData;
				}
				else
				{
					hr = E_OUTOFMEMORY;
				}
			}

			CertFreeCertificateContext(pCertContext);
		}

		CertCloseStore(hStore, 0);
	}

	return hr;
}
