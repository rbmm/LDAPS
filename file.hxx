#pragma once

HRESULT AddToMyStore(_In_ const BYTE* pbCertEncoded,
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

HRESULT ReadFromFile(_In_ PCWSTR lpFileName, _Out_ PDATA_BLOB pdb, _In_ ULONG MaxSize = MAXUSHORT, _In_ ULONG MinSize = 0x10)
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