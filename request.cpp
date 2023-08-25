#include "StdAfx.h"

#include "util.h"
#include <Http.h>

extern volatile const UCHAR guz = 0;

void PrintCertOp(PCCERT_CONTEXT pCertContext)
{
	WCHAR name[0x400];

	if (CertNameToStrW(X509_ASN_ENCODING, &pCertContext->pCertInfo->Subject, CERT_X500_NAME_STR, name, _countof(name)))
	{
		DbgPrint("CERT: \"%s\"\r\n", name);
	}

	UCHAR hash[20];
	ULONG cb = sizeof(hash);
	if (CryptHashCertificate2(BCRYPT_SHA1_ALGORITHM, 0, 0, pCertContext->pbCertEncoded, pCertContext->cbCertEncoded, hash, &cb))
	{
		DumpBytesInLine(hash, cb, "thumbprint: ");
	}
}

//showmacro(DECLSPEC_IMPORT)
typedef CONST UCHAR *PCUCHAR;
void TestDecode(PCUCHAR pb, ULONG cb);

void DumpName(const CERT_NAME_BLOB* Name, PCWSTR msg);

void InitSacl(LDAP* ld)
{
	PSecPkgInfoW PackageInfo;
	if (SEC_E_OK == QuerySecurityPackageInfoW(const_cast<PWSTR>(L""), &PackageInfo))
	{
		FreeContextBuffer(PackageInfo);
	}

	PWSTR ProfileList;
	ULONG ProfileCount;

	if (SEC_E_OK == SaslEnumerateProfilesW(&ProfileList, &ProfileCount))
	{
		PVOID buf = ProfileList;

		if (ProfileCount)
		{
			do 
			{
				if (SEC_E_OK == SaslGetProfilePackageW(ProfileList, &PackageInfo))
				{
					if (!_wcsicmp(PackageInfo->Name, MICROSOFT_KERBEROS_NAME_W))
					{
						ULONG r = ldap_set_option(ld, LDAP_OPT_SASL_METHOD, &ProfileList);
						DbgPrint("SASL_METHOD(%s)=%x\r\n", ProfileList, r);

						ProfileCount = 1;
					}

					FreeContextBuffer(PackageInfo);
				}

			} while (ProfileList += wcslen(ProfileList) + 1, --ProfileCount);
		}

		FreeContextBuffer(buf);
	}
}

HRESULT PFXImport(_In_ PCWSTR lpFileName, 
				  _In_ PCWSTR szPassword,
				  _Out_ PWSTR *ppwszUserName, 
				  _Out_ PCCERT_CONTEXT* ppCertContext);

void Cleanup(_In_ PWSTR pwszUserName);
void Cleanup(_In_ PCCERT_CONTEXT pCertContext, _In_ BOOL bInStore);

struct LCC 
{
	LCC* next;
	PLDAP Connection;
	PCCERT_CONTEXT pCertContext;

	inline static LCC* _G_first = 0;
	inline static SRWLOCK _G_Lock = {};

	static PCCERT_CONTEXT get(_In_ PLDAP Connection)
	{
		PCCERT_CONTEXT pCertContext = 0;
		
		AcquireSRWLockShared(&_G_Lock);
		
		if (LCC* entry = _G_first)
		{
			do 
			{
				if (Connection == entry->Connection)
				{
					pCertContext = entry->pCertContext;
					break;
				}
			} while (entry = entry->next);
		}

		ReleaseSRWLockShared(&_G_Lock);

		return pCertContext;
	}

	static BOOL Add(_In_ PLDAP Connection, _In_ PCCERT_CONTEXT pCertContext)
	{
		if (LCC* entry = new LCC)
		{
			entry->Connection = Connection;
			entry->pCertContext = pCertContext;

			AcquireSRWLockExclusive(&_G_Lock);
			entry->next = _G_first, _G_first = entry;
			ReleaseSRWLockExclusive(&_G_Lock);

			return TRUE;
		}

		return FALSE;
	}

	static BOOL Remove(_In_ PLDAP Connection)
	{
		LCC* entry = 0;

		AcquireSRWLockExclusive(&_G_Lock);

		if (entry = _G_first)
		{
			LCC** pnext = &_G_first;
			do 
			{
				if (Connection == entry->Connection)
				{
					*pnext = entry->next;
					break;
				}
				
				pnext = &entry->next;

			} while (entry = entry->next);
		}

		ReleaseSRWLockExclusive(&_G_Lock);

		if (entry)
		{
			delete entry;
			return TRUE;
		}

		return FALSE;
	}
};

BOOLEAN _cdecl GetClientCert (_In_ PLDAP Connection,
							   _In_ PSecPkgContext_IssuerListInfoEx trusted_CAs,
							   _Inout_ PCCERT_CONTEXT *ppCertificate)
{
	DbgPrint("GetClientCert:\r\n");

	*ppCertificate = 0;

	if (PCCERT_CONTEXT pCertificate = LCC::get(Connection))
	{
		if (DWORD cIssuers = trusted_CAs->cIssuers)
		{
			PCERT_NAME_BLOB Issuer = &pCertificate->pCertInfo->Issuer;
			PCERT_NAME_BLOB aIssuers = trusted_CAs->aIssuers;

			do 
			{
				if (aIssuers->cbData == Issuer->cbData &&
					!memcmp(aIssuers->pbData, Issuer->pbData, Issuer->cbData))
				{
					*ppCertificate = pCertificate;
					return TRUE;
				}

			} while (aIssuers++, --cIssuers);

			return FALSE;
		}

		*ppCertificate = pCertificate;
		return TRUE;
	}

	return FALSE;
}

BOOLEAN _cdecl VerifyServerCert (
								 _In_ PLDAP /*Connection*/,
								 _In_ PCCERT_CONTEXT* ppServerCert
								 )
{
	PCCERT_CONTEXT pServerCert = *ppServerCert;
	DbgPrint("ServerCert:\r\n");
	PrintCertOp(pServerCert);
	CertFreeCertificateContext(pServerCert);
	*ppServerCert = 0;
	return TRUE;
}

HRESULT LDAPQuery(LDAP* ld, PCWSTR base, PCWSTR filter, const PCWSTR attr[])
{
	ULONG LdapError;
	LDAPMessage* res = 0;

	if (LDAP_SUCCESS == (LdapError = ldap_search_sW(ld, const_cast<PWSTR>(base), LDAP_SCOPE_SUBTREE, 
		const_cast<PWSTR>(filter), const_cast<PZPWSTR>(attr), FALSE, &res)))
	{
		if (PWSTR* vals = ldap_get_valuesW(ld, res, const_cast<PWSTR>(L"cn")))
		{
			DbgPrint("[*]	ldap_get_valuesW\r\n");

			PWSTR psz, *ppsz = vals;
			while (psz = *ppsz++)
			{
				DbgPrint("CN=\"%s\"\r\n", psz);
			}
			ldap_value_freeW(vals);
		}

		if (berval** vals = ldap_get_values_lenW(ld, res, const_cast<PWSTR>(L"cACertificate")))
		{
			berval* p, **pp = vals; 
			while (p = *pp++)
			{
				if (PCCERT_CONTEXT pCertContext = CertCreateCertificateContext(
					X509_ASN_ENCODING, (PBYTE)p->bv_val, p->bv_len))
				{
					DbgPrint("CA cert:\r\n");
					PrintCertOp(pCertContext);
					CertFreeCertificateContext(pCertContext);
				}
			}
			ldap_value_free_len(vals);
		}

		ldap_msgfree(res);
	}

	return LdapError;
}

HRESULT LDAPMain(PCWSTR pszUserName, PCWSTR pszPassword, PCCERT_CONTEXT pCertContext)
{
	if (IsDebuggerPresent())
	{
		__debugbreak();
	}

	HRESULT hr = S_OK;
	ULONG LdapError = LDAP_SUCCESS;
	
	WCHAR DomainName[0x100];

	if (ULONG cch = HR(hr, GetEnvironmentVariableW(L"USERDNSDOMAIN", DomainName, _countof(DomainName) - 1)))
	{
		if (LDAP* ld = pCertContext ? ldap_sslinitW(DomainName, LDAP_SSL_PORT, TRUE) : ldap_initW(DomainName, LDAP_PORT))
		{
			DbgPrint("[*]	ldap_initW\r\n");

			SEC_WINNT_AUTH_IDENTITY_W cred = {
				(USHORT*)pszUserName,
				(USHORT)(pszUserName ? wcslen(pszUserName) : 0),
				(USHORT*)DomainName,
				(USHORT)wcslen(DomainName),
				(USHORT*)pszPassword,
				(USHORT)(pszPassword ? wcslen(pszPassword) : 0),
				SEC_WINNT_AUTH_IDENTITY_UNICODE
			};

			if (pCertContext)
			{
				if (LCC::Add(ld, pCertContext))
				{
					if (LDAP_SUCCESS != (LdapError = ldap_set_optionW(ld, LDAP_OPT_SSL, LDAP_OPT_ON )) ||
						LDAP_SUCCESS != (LdapError = ldap_set_optionW(ld, LDAP_OPT_CLIENT_CERTIFICATE, GetClientCert)) ||
						LDAP_SUCCESS != (LdapError = ldap_set_optionW(ld, LDAP_OPT_SERVER_CERTIFICATE, VerifyServerCert)))
					{
						goto __exit;
					}
				}
			}

			InitSacl(ld);

			if (LDAP_SUCCESS == (LdapError = ldap_connect(ld, 0)))
			{
				DbgPrint("[*]	ldap_connect\r\n");

				if (LDAP_SUCCESS == (LdapError = ldap_bind_sW(ld, 0, pszUserName ? (PWSTR)&cred : 0, LDAP_AUTH_NEGOTIATE)))
				{
					DbgPrint("[*]	ldap_bind_sW\r\n");

					DomainName[cch] = '/';
					DomainName[cch + 1] = 0;

					PWSTR base = 0;
					int len = 0;

					PCWSTR name = DomainName;
					PDS_NAME_RESULTW pResult = 0;
					if (NOERROR == (hr = DsCrackNamesW(0, DS_NAME_FLAG_SYNTACTICAL_ONLY,
						DS_CANONICAL_NAME, DS_FQDN_1779_NAME, 1, &name, &pResult)))
					{
						hr = ERROR_NOT_FOUND;

						if (pResult->cItems)
						{
							PDS_NAME_RESULT_ITEMW rItems = pResult->rItems;
							if (DS_NAME_NO_ERROR == rItems->status)
							{
								while (0 < (len = _snwprintf(base, len, 
									L"CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,%s", 
									rItems->pName)))
								{
									if (base)
									{
										hr = NOERROR;
										DbgPrint("%s\n", base);
										break;
									}

									base = (PWSTR)alloca(++len * sizeof(WCHAR));
								}
							}
						}

						DsFreeNameResult(pResult);
					}

					if (NOERROR == hr)
					{
						static const PCWSTR attr[] = { L"cn", L"cACertificate", 0 };

						LdapError = LDAPQuery(ld, base, 
							L"(&(objectCategory=pKIEnrollmentService)(certificateTemplates=SmartcardLogon))", attr);
					}
				}
			}
__exit:

			if (pCertContext)
			{
				if (!LCC::Remove(ld))
				{
					__debugbreak();
				}
			}

			ldap_unbind_s(ld);
		}
		else
		{
			LdapError = LdapGetLastError();
		}

		if (LdapError)
		{
			hr = LdapMapErrorToWin32(LdapError);

			if (PCWSTR psz = ldap_err2stringW(LdapError))
			{
				DbgPrint("LdapError: %s\r\n", psz);
			}
		}
	}

	return HRESULT_FROM_WIN32(hr);
}

HRESULT cmd(ULONG argc, PWSTR argv[], PCCERT_CONTEXT pCertContext)
{
	HRESULT hr = HRESULT_FROM_NT(STATUS_INVALID_PARAMETER_MIX);

	if (!wcscmp(argv[0], L"user"))
	{
		switch (argc)
		{
		case 1:// *user
			return LDAPMain(0, 0, pCertContext);
		case 3:// *user*name*pass
			return LDAPMain(argv[1], argv[2], pCertContext);
		}
	}
	else if (!wcscmp(argv[0], L"cert"))
	{
		if (3 == argc)
		{
			// *cert*file*pass
			PWSTR pszUserName = 0;

			if (0 <= (hr = PFXImport(argv[1], argv[2], &pszUserName, 0)))
			{
				hr = LDAPMain(pszUserName, L"", pCertContext);

				Cleanup(pszUserName);
			}
		}
	}

	return hr;
}

void WINAPI ep(PWSTR lpCommandLine)
{	
	//initterm();
	InitPrintf();
	HRESULT hr;
	PWSTR argv[9];
	ULONG argc = 0;

	lpCommandLine = GetCommandLineW();

	while (lpCommandLine = wcschr(lpCommandLine, '*'))
	{
		*lpCommandLine++ = 0;

		argv[argc++] = lpCommandLine;

		if (_countof(argv) == argc)
		{
			break;
		}
	}

	if (!argc)
	{
		DbgPrint(
			"The syntax of this command is:\r\n"
			"\r\n"
			"CRT-UT [*ssl*pfx*pass]cmd\r\n"
			"\twhere cmd:\r\n"
			"\t\t*cert*pfx*pass\r\n"
			"\tor\r\n"
			"\t\t*user[*name*pass]\r\n"
			);
		ExitProcess((ULONG)STATUS_INVALID_PARAMETER_MIX);
	}

	// [*ssl*pfx*pass]cmd
	// where cmd:
	// *cert*pfx*pass
	// or
	// *user[*name*pass]

	if (IsDebuggerPresent())__debugbreak();

	hr = HRESULT_FROM_NT(STATUS_INVALID_PARAMETER_MIX);

	if (wcscmp(argv[0], L"ssl"))
	{
		hr = cmd(argc, argv, 0);
	}
	else
	{
		if (3 < argc)
		{
			PCCERT_CONTEXT pCertContext = 0;

			if (0 <= (hr = PFXImport(argv[1], argv[2], 0, &pCertContext)))
			{
				hr = cmd(argc - 3, argv + 3, pCertContext);

				Cleanup(pCertContext, FALSE);
			}
		}
	}

	//destroyterm();
	ExitProcess(PrintError(hr));
}