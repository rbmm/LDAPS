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

BOOLEAN _cdecl GetClientCert (_In_ PLDAP Connection,
							   _In_ PSecPkgContext_IssuerListInfoEx trusted_CAs,
							   _Inout_ PCCERT_CONTEXT *ppCertificate)
{
	DbgPrint("GetClientCert:\r\n");

	*ppCertificate = 0;

	if (PCCERT_CONTEXT pCertificate = *(PCCERT_CONTEXT*)Connection->ld_sb.Reserved2)
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

HRESULT LDAPQuery(_In_ LDAP* ld, _In_ PCWSTR base, _In_ ULONG scope, _In_ PCWSTR filter)
{
	DbgPrint("Query:\r\nbase: %s\r\nfilter: %s\r\nattr:\r\n", base, filter);

	ULONG LdapError;
	LDAPMessage* res = 0;

	if (LDAP_SUCCESS == (LdapError = ldap_search_sW(ld, const_cast<PWSTR>(base), scope, 
		const_cast<PWSTR>(filter), 0, FALSE, &res)))
	{
		if (LDAPMessage* entry = ldap_first_entry(ld, res))
		{
			do 
			{
				BerElement* ptr;

				if (PWCHAR attr = ldap_first_attributeW(ld, entry, &ptr))
				{
					do 
					{
						DbgPrint("[%s]:\r\n", attr);

						if (PWSTR* vals = ldap_get_valuesW(ld, entry, attr))
						{
							DbgPrint("[*]	ldap_get_valuesW\r\n");

							PWSTR psz, *ppsz = vals;
							while (psz = *ppsz++)
							{
								DbgPrint("\t\"%s\"\r\n", psz);
							}

							ldap_value_freeW(vals);
						}

					} while (attr = ldap_next_attributeW(ld, entry, ptr));

					ber_free(ptr, 0);
				}
			} while (entry = ldap_next_entry(ld, entry));
		}

		ldap_msgfree(res);
	}

	return LdapError;
}

HRESULT PFXImport(_In_ PCWSTR lpFileName, 
				  _In_ PCWSTR szPassword,
				  _Out_ PWSTR *ppwszUserName, 
				  _Out_ PCCERT_CONTEXT* ppCertContext,
				  _Out_ NCRYPT_KEY_HANDLE* phKey,
				  _Out_ PULONG pCrc);

ULONG ldap_connect( LDAP *ld, struct l_timeval *timeout, NCRYPT_KEY_HANDLE* phKey, ULONG crc );

HRESULT LDAPMain(_In_ PWSTR DomainName,
				 _In_ PWSTR HostName,
				 _In_ PWSTR Base,
				 _In_ PWSTR Filter,
				 _In_ ULONG scope,
				 _In_ PCWSTR pszUserName, 
				 _In_ PCWSTR pszPassword, 
				 _In_ PCCERT_CONTEXT pCertContext, 
				 _Inout_ NCRYPT_KEY_HANDLE* phKey, 
				 _In_ ULONG crc)
{
	if (IsDebuggerPresent())
	{
		__debugbreak();
	}

	DbgPrint("DN= %s\r\nHost= %s\r\n", DomainName, HostName);

	HRESULT hr = S_OK;
	ULONG LdapError = LDAP_SUCCESS;
	
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

		LDAP_TIMEVAL timeout = {60};//1 min

		if (pCertContext)
		{
			*(PCCERT_CONTEXT*)ld->ld_sb.Reserved2 = pCertContext;// !?

			if (LDAP_SUCCESS != (LdapError = ldap_set_optionW(ld, LDAP_OPT_SSL, LDAP_OPT_ON )) ||
				LDAP_SUCCESS != (LdapError = ldap_set_optionW(ld, LDAP_OPT_CLIENT_CERTIFICATE, GetClientCert)) ||
				LDAP_SUCCESS != (LdapError = ldap_set_optionW(ld, LDAP_OPT_SERVER_CERTIFICATE, VerifyServerCert)))
			{
				goto __exit;
			}
		}

		InitSacl(ld);

		if (HostName)
		{
			ldap_set_optionW(ld, LDAP_OPT_HOST_NAME, &HostName);
		}

		if (LDAP_SUCCESS == (LdapError = phKey ? ldap_connect(ld, &timeout, phKey, crc) : ldap_connect(ld, &timeout)))
		{
			DbgPrint("[*]	ldap_connect\r\n");

			if (LDAP_SUCCESS == (LdapError = ldap_bind_sW(ld, 0, pszUserName ? (PWSTR)&cred : 0, LDAP_AUTH_NEGOTIATE)))
			{
				DbgPrint("[*]	ldap_bind_sW\r\n");

				LdapError = LDAPQuery(ld, Base, scope, Filter);
			}
		}
__exit:

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

	return HRESULT_FROM_WIN32(hr);
}

void SSHtest();
void CloseZombie();
#if 0
ULONG WINAPI Wk(HANDLE hDllHandle)
{
	SSHtest();
	FreeLibraryAndExitThread((HMODULE)hDllHandle, 0);
}

BOOLEAN WINAPI DllMain( HMODULE hDllHandle, DWORD dwReason, LPVOID hThread )
{
	if (IsDebuggerPresent()) __debugbreak();
	if (DLL_PROCESS_ATTACH == dwReason)
	{
		DisableThreadLibraryCalls(hDllHandle);
		if (hThread = CreateThread(0, 0, Wk, hDllHandle, 0, 0))
		{
			NtClose(hThread);
		}
	}
	return TRUE;
}
#endif

//%% -> %
//%* -> #

BOOL UnEscape(_Inout_ PWSTR str)
{
	PWSTR buf = str;
	WCHAR c;
	do
	{
		if ('%' == (c = *str++))
		{
			switch (c = *str++)
			{
			case '*':
				c = '#';
				break;
			case '%':
				break;
			default:
				return FALSE;
			}
		}

		*buf++ = c;

	} while (c);

	return TRUE;
}

PWSTR FormatBase(PWSTR Base, PWSTR Domain)
{
	PWSTR pc = Base, last;
	
	ULONG n = 2, m = 1;
	
	size_t cch = wcslen(Base) + wcslen(Domain);
	
	while (pc = wcschr(1 + (last = pc), '\\'))
	{
		n++;
	}
	
	pc = Domain;

	while (pc = wcschr(pc, '.'))
	{
		n++, m++, *pc++ = 0;
	}
	cch += n * 3 + 1;

	if (PWSTR buf = new WCHAR[cch])
	{
		PWSTR psz = buf;

		for (;;)
		{
			wcscpy(psz = wcscpy(psz, L"CN=") + 3, last + 1);
			psz += wcslen(psz);
			*psz++ = ',';
			if (last == Base) break;
			*last = 0;
			while ('\\' != *--last) ;
		}

		pc = Domain;
		do 
		{
			wcscpy(psz = wcscpy(psz, L"DC=") + 3, pc);
			psz += wcslen(psz);
			pc += wcslen(pc);
			*pc++ = '.';
			*psz++ = ',';
		} while (--m);

		psz[-1] = 0, pc[-1] = 0;
		
		return buf;
	}
	
	return 0;
}

HRESULT cmd(PWSTR lpCommandLine)
{
	if (IsDebuggerPresent())__debugbreak();

	ULONG scope = MAXDWORD;
	PWSTR pszDomain = 0, pszHost = 0, pszUserName = 0, pszPassword = 0, pszScope = 0, 
		pszPfx = 0, pszSslPfx = 0, pszSslPassword = 0, pszBase = 0, pszFilter = 0;

	// cmd   = #param[#param]
	// param = name:value
	// name:
	//		dn:
	//		srv:
	//		base:
	//		flt:
	//		scope: 0|1|2
	//		user: user:pass
	//		pfx: file:pass
	//		ssl: file:pass

	PWSTR pszValue = 0;

	while (lpCommandLine = wcschr(lpCommandLine, '#'))
	{
		*lpCommandLine++ = 0;

		if (pszValue && !UnEscape(pszValue))
		{
			return HRESULT_FROM_NT(STATUS_INVALID_PARAMETER);
		}

		if (pszValue)
		{
			DbgPrint("\"%s\";\r\n", pszValue);
		}
		
		if (!(pszValue = wcschr(lpCommandLine, ':')))
		{
			return HRESULT_FROM_NT(STATUS_INVALID_PARAMETER);
		}

		ULONG crc = RtlComputeCrc32(0, lpCommandLine, RtlPointerToOffset(lpCommandLine, pszValue));
		
		*pszValue++ = 0;

		DbgPrint("case 0x%08X: // %s = ", crc, lpCommandLine);

		lpCommandLine = pszValue;

		switch (crc)
		{
		case 0x6E7EF961: // dn
			if (pszDomain) return HRESULT_FROM_NT(STATUS_INVALID_PARAMETER_MIX);
			pszDomain = pszValue;
			break;
		
		case 0x842768AB: // srv
			if (pszHost) return HRESULT_FROM_NT(STATUS_INVALID_PARAMETER_MIX);
			pszHost = pszValue;
			break;
		
		case 0x554434C0: // base
			if (pszBase) return HRESULT_FROM_NT(STATUS_INVALID_PARAMETER_MIX);
			pszBase = pszValue;
			break;
		
		case 0x55CCB9AD: // flt
			if (pszFilter) return HRESULT_FROM_NT(STATUS_INVALID_PARAMETER_MIX);
			pszFilter = pszValue;
			break;
		
		case 0x2A877344: // scope
			if (pszScope) return HRESULT_FROM_NT(STATUS_INVALID_PARAMETER_MIX);
			pszScope = pszValue;
			break;
		
		case 0x1DD523B7: // user
			if (pszUserName) return HRESULT_FROM_NT(STATUS_INVALID_PARAMETER_MIX);
			pszUserName = pszValue;
			break;
			
		case 0x434BF743: // pfx
			if (pszPfx) return HRESULT_FROM_NT(STATUS_INVALID_PARAMETER_MIX);
			pszPfx = pszValue;
			break;
		
		case 0x8CB6F515: // ssl
			if (pszSslPfx) return HRESULT_FROM_NT(STATUS_INVALID_PARAMETER_MIX);
			pszSslPfx = pszValue;
			break;
		
		default:
			return HRESULT_FROM_NT(STATUS_INVALID_PARAMETER);
		}
	}

	if (!pszValue || !UnEscape(pszValue) || !pszScope)
	{
		return HRESULT_FROM_NT(STATUS_INVALID_PARAMETER);
	}

	DbgPrint("\"%s\";\r\n", pszValue);

	scope = wcstoul(pszScope, &pszScope, 10);
	if (*pszScope || scope > LDAP_SCOPE_SUBTREE) return HRESULT_FROM_NT(STATUS_INVALID_PARAMETER);

	if (!pszBase || !pszFilter || *pszBase != '\\' || ((0 != pszPfx) && (0 != pszUserName)))
	{
		return HRESULT_FROM_NT(STATUS_INVALID_PARAMETER_MIX);
	}

	if (pszUserName)
	{
		if (pszPassword = wcschr(pszUserName, ':'))
		{
			*pszPassword++ = 0;
		}
		else
		{
			return HRESULT_FROM_NT(STATUS_INVALID_PARAMETER);
		}
	}

	if (pszPfx)
	{
		if (pszPassword = wcschr(pszPfx, ':'))
		{
			*pszPassword++ = 0;
		}
		else
		{
			return HRESULT_FROM_NT(STATUS_INVALID_PARAMETER);
		}
	}

	if (pszSslPfx)
	{
		if (pszSslPassword = wcschr(pszSslPfx, ':'))
		{
			*pszSslPassword++ = 0;
		}
		else
		{
			return HRESULT_FROM_NT(STATUS_INVALID_PARAMETER);
		}
	}

	if (!pszDomain)
	{
		ULONG cch = 0;

		while (cch = GetEnvironmentVariable(L"USERDNSDOMAIN", pszDomain, cch))
		{
			if (pszDomain)
			{
				break;
			}

			pszDomain = (PWSTR)alloca(cch * sizeof(ULONG));
		}

		if (!cch)
		{
			return GetLastHr();
		}
	}

	ULONG crc;
	NCRYPT_KEY_HANDLE hKey = 0;
	PCCERT_CONTEXT pCertContext = 0;

	HRESULT hr;

	if (S_OK == (hr = PFXImport(pszSslPfx, pszSslPassword, 0, &pCertContext, &hKey, &crc)))
	{
		if (S_OK == (hr = PFXImport(pszPfx, pszPassword, &pszUserName, 0, 0, 0)))
		{
			if (pszBase = FormatBase(pszBase, pszDomain))
			{
				hr = LDAPMain(pszDomain, pszHost, pszBase, pszFilter, scope, 
					pszUserName, pszPfx ? L"" : pszPassword, pCertContext, &hKey, crc);

				delete [] pszBase;
			}

			if (pszPfx && pszUserName)
			{
				Cleanup(pszUserName);
			}
		}

		if (hKey)
		{
			NCryptFreeObject(hKey);
		}

		if (pCertContext)
		{
			Cleanup(pCertContext, FALSE);
		}
	}

	return hr;
}

void WINAPI ep(void*)
{	
	//if (!GetTickCount())
	//{
	//	CloseZombie();
	//}
	//else
	//{
	//	SSHtest();
	//}
	//initterm();

	InitPrintf();

	//destroyterm();
	ExitProcess(PrintError(cmd(GetCommandLineW())));
}