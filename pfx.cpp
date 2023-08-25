#include "stdafx.h"

#include "util.h"

//////////////////////////////////////////////////////////////////////////
// SSL certificate

void Cleanup(_In_ PCCERT_CONTEXT pCertContext, _In_ BOOL bInStore)
{
	ULONG cb = 0;

	union {
		PBYTE buf = 0;
		PCRYPT_KEY_PROV_INFO kpi;
	};

	while (CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, buf, &cb))
	{
		if (kpi)
		{
			NCRYPT_PROV_HANDLE hProvider;

			if (NOERROR == NCryptOpenStorageProvider(&hProvider, kpi->pwszProvName, 0))
			{
				NCRYPT_KEY_HANDLE hKey;
				if (NOERROR == NCryptOpenKey(hProvider, &hKey, kpi->pwszContainerName, kpi->dwKeySpec, kpi->dwFlags))
				{
					NCryptDeleteKey(hKey, 0);
				}

				NCryptFreeObject(hProvider);
			}

			break;
		}

		buf = (PBYTE)alloca(cb);
	}

	bInStore ? CertDeleteCertificateFromStore(pCertContext) : CertFreeCertificateContext(pCertContext);
}

PCCERT_CONTEXT CheckCertForKeyOnly(_In_ PCCERT_CONTEXT pCertContext, _Out_ PCCERT_CONTEXT* ppCertContext)
{
	if (pCertContext)
	{
		HRESULT hr;

		ULONG cb = 0;

		if (HR(hr, CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, 0, &cb)))
		{
			*ppCertContext = pCertContext;
			SetLastError(NOERROR);
			return 0;
		}
	}

	return pCertContext;
}

//////////////////////////////////////////////////////////////////////////
// SmartCardLogon certificate

BOOLEAN UserNameToCertHash(_In_ PCWSTR pszUserName,
						   _Out_writes_bytes_opt_(CERT_HASH_LENGTH) PUCHAR rgbHashOfCert)
{
	CRED_MARSHAL_TYPE CredType;

	union {
		PVOID Credential;
		PCERT_CREDENTIAL_INFO pCertCredInfo;
	};

	if (CredUnmarshalCredential(pszUserName, &CredType, &Credential))
	{
		if (CredType == CertCredential && pCertCredInfo->cbSize >= sizeof(CERT_CREDENTIAL_INFO))
		{
			memcpy(rgbHashOfCert, pCertCredInfo->rgbHashOfCert, CERT_HASH_LENGTH);
			pszUserName = 0;
		}

		CredFree(Credential);

		if (!pszUserName)
		{
			return TRUE;
		}
	}

	return FALSE;
}

void Cleanup(_In_ PWSTR pwszUserName)
{
	UCHAR rgbHashOfCert[CERT_HASH_LENGTH];
	CRYPT_HASH_BLOB chb = { sizeof(rgbHashOfCert), rgbHashOfCert };

	if (UserNameToCertHash(pwszUserName, rgbHashOfCert))
	{
		if (HCERTSTORE hCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER, L"MY"))
		{
			if (PCCERT_CONTEXT pCertContext = CertFindCertificateInStore(hCertStore, X509_ASN_ENCODING, 0, CERT_FIND_HASH, &chb, 0))
			{
				Cleanup(pCertContext, TRUE);
			}

			CertCloseStore(hCertStore, 0);
		}
	}

	CredFree(pwszUserName);
}

PCCERT_CONTEXT CheckCertAndGetName(_In_ PCCERT_CONTEXT pCertContext, _Out_ PWSTR *ppwszUserName)
{
	if (!pCertContext)
	{
		return 0;
	}

	HRESULT hr;

	ULONG cb = 0;

	union {
		PBYTE buf = 0;
		PCRYPT_KEY_PROV_INFO kpi;
	};

	while (HR(hr, CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, buf, &cb)))
	{
		if (kpi)
		{
			CERT_CREDENTIAL_INFO cci = { sizeof(cci) };

			PWSTR pwszUserName;

			if (HR(hr, CryptHashCertificate2(BCRYPT_SHA1_ALGORITHM, 0, 0, 
				pCertContext->pbCertEncoded, pCertContext->cbCertEncoded, 
				cci.rgbHashOfCert, &(cb = sizeof(cci.rgbHashOfCert)))) &&
				HR(hr, CredMarshalCredentialW(CertCredential, &cci, &pwszUserName)))
			{
				if (HCERTSTORE hCertStore = HR(hr, CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER, L"MY")))
				{
					hr = BOOL_TO_ERROR(CertAddCertificateContextToStore(hCertStore, pCertContext, CERT_STORE_ADD_REPLACE_EXISTING, 0));

					CertCloseStore(hCertStore, 0);

					if (0 <= hr)
					{
						*ppwszUserName = pwszUserName;
						CertFreeCertificateContext(pCertContext);
						SetLastError(NOERROR);
						return 0;
					}
				}

				CredFree(pwszUserName);
			}

			break;
		}

		buf = (PBYTE)alloca(cb);

	}

	return pCertContext;
}

HRESULT PFXImport(_In_ DATA_BLOB* pPFX, 
				  _In_ PCWSTR szPassword,
				  _Out_ PWSTR *ppwszUserName, 
				  _Out_ PCCERT_CONTEXT* ppCertContext)
{
	HRESULT hr;

	if (HCERTSTORE hStore = HR(hr, PFXImportCertStore(pPFX, szPassword, PKCS12_ALWAYS_CNG_KSP)))
	{
		PCCERT_CONTEXT pCertContext = 0;

		union {
			PVOID pfn;
			PCCERT_CONTEXT (* CheckCert)(_In_ PCCERT_CONTEXT pCertContext, _Out_ PVOID );
			PCCERT_CONTEXT (* CheckCert1)(_In_ PCCERT_CONTEXT pCertContext, _Out_ PWSTR *ppwszUserName);
			PCCERT_CONTEXT (* CheckCert2)(_In_ PCCERT_CONTEXT pCertContext, _Out_ PCCERT_CONTEXT *ppCertContext);
		};

		PVOID pv;

		if (ppwszUserName)
		{
			pv = ppwszUserName;
			CheckCert1 = CheckCertAndGetName;
		}
		else
		{
			pv = ppCertContext;
			CheckCert2 = CheckCertForKeyOnly;
		}

		while (pCertContext = CheckCert(CertEnumCertificatesInStore(hStore, pCertContext), pv))
		{
		}

		hr = GetLastError();
		CertCloseStore(hStore, 0);
	}

	return hr;
}

HRESULT PFXImport(_In_ PCWSTR lpFileName, 
				  _In_ PCWSTR szPassword,
				  _Out_ PWSTR *ppwszUserName, 
				  _Out_ PCCERT_CONTEXT* ppCertContext)
{
	if ((ppCertContext != 0) ^ (ppwszUserName != 0))
	{
		DATA_BLOB db;
		HRESULT hr = ReadFromFile(lpFileName, &db);

		if (0 <= hr)
		{
			PFXImport(&db, szPassword, ppwszUserName, ppCertContext);
			LocalFree(db.pbData);
		}
		return hr;
	}

	return HRESULT_FROM_NT(STATUS_INVALID_PARAMETER_MIX);
}
