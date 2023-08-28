#include "stdafx.h"
#include "util.h"

void DumpToken(HANDLE hToken)
{
	union {
		SE_TOKEN_USER tu;
		TOKEN_STATISTICS ts;
		TOKEN_SOURCE tr;
	};

	ULONG cb;

	DbgPrint("DumpToken(%p)\n", hToken);

	if (0 <= NtQueryInformationToken(hToken, TokenStatistics, &ts, sizeof(ts), &cb))
	{
		DbgPrint("{%08x-%08x} %x.%x\n", 
			ts.AuthenticationId.HighPart, ts.AuthenticationId.LowPart, ts.TokenType, ts.ImpersonationLevel);
	}

	if (0 <= NtQueryInformationToken(hToken, TokenSource, &tr, sizeof(tr), &cb))
	{
		DbgPrint("{%08x-%08x} %.8S\n", 
			tr.SourceIdentifier.HighPart, tr.SourceIdentifier.LowPart, tr.SourceName);
	}

	if (0 <= NtQueryInformationToken(hToken, TokenUser, &tu, sizeof(tu), &cb))
	{
		UNICODE_STRING us;
		if (0 <= RtlConvertSidToUnicodeString(&us, tu.User.Sid, TRUE))
		{
			DbgPrint("%wZ\n", &us);
			RtlFreeUnicodeString(&us);
		}
	}
}

BOOL SslGetNameFromCertificate(PCERT_INFO pCertInfo, BOOL bServer, PWSTR * ppszName)
{
	BOOL fOk = FALSE;

	if (PCERT_EXTENSION Extension = CertFindExtension(szOID_SUBJECT_ALT_NAME2, pCertInfo->cExtension, pCertInfo->rgExtension))
	{
		PCERT_ALT_NAME_INFO AltName;
		if (0 <= Decode(X509_ALTERNATE_NAME, &Extension->Value, &AltName))
		{
			if (DWORD cAltEntry = AltName->cAltEntry)
			{
				PCERT_ALT_NAME_ENTRY rgAltEntry = AltName->rgAltEntry;
				do 
				{
					switch (rgAltEntry->dwAltNameChoice)
					{
					case CERT_ALT_NAME_DNS_NAME:
						if (bServer)
						{
							if (*ppszName = _wcsdup(rgAltEntry->pwszDNSName))
							{
								fOk = TRUE;
							}
						}
						break;

					case CERT_ALT_NAME_OTHER_NAME:
						if (!bServer && !strcmp(rgAltEntry->pOtherName->pszObjId, szOID_NT_PRINCIPAL_NAME))
						{
							PCERT_NAME_VALUE PrincipalNameBlob;
							if (0 <= Decode(X509_UNICODE_NAME_VALUE, &rgAltEntry->pOtherName->Value, &PrincipalNameBlob))
							{
								switch (PrincipalNameBlob->dwValueType)
								{
								case CERT_RDN_UNICODE_STRING:
								case CERT_RDN_UTF8_STRING:
									if (*ppszName = _wcsdup((PWSTR)PrincipalNameBlob->Value.pbData))
									{
										fOk = TRUE;
									}
								}
								LocalFree(PrincipalNameBlob);
							}
						}
						break;
					}
				} while (rgAltEntry++, --cAltEntry);
			}
			LocalFree(AltName);
		}
	}

	return fOk;
}

//|ASC_REQ_IDENTIFY
#define ASC_REQ ASC_REQ_REPLAY_DETECT|ASC_REQ_SEQUENCE_DETECT|ASC_REQ_CONFIDENTIALITY|ASC_REQ_ALLOCATE_MEMORY|ASC_REQ_EXTENDED_ERROR|ASC_REQ_STREAM|ASC_REQ_MUTUAL_AUTH
#define ISC_REQ ISC_REQ_REPLAY_DETECT|ISC_REQ_SEQUENCE_DETECT|ISC_REQ_CONFIDENTIALITY|ISC_REQ_ALLOCATE_MEMORY|ISC_REQ_EXTENDED_ERROR|ISC_REQ_STREAM|ISC_REQ_MUTUAL_AUTH

struct __declspec(novtable) SSH 
{
	CredHandle _M_hCred{};
	CtxtHandle _M_hCtx{};
	SSH* _M_pLink = 0;
	PWSTR _M_Name = 0;

	~SSH()
	{
		if (_M_hCtx.dwLower|_M_hCtx.dwUpper) DeleteSecurityContext(&_M_hCtx);
		if (_M_hCred.dwLower|_M_hCred.dwUpper) FreeCredentialsHandle(&_M_hCred);
		if (_M_Name)
		{
			free(_M_Name);
		}
	}

	void SetLink(SSH* pLink)
	{
		_M_pLink = pLink;
	}

	BOOL Init(ULONG fCredentialUse, PCSTR pszHash)
	{
		BOOL fOk = FALSE;
		UCHAR rgbHashOfCert[CERT_HASH_LENGTH];
		CRYPT_HASH_BLOB chb = { sizeof(rgbHashOfCert), rgbHashOfCert };

		if (CryptStringToBinaryA(pszHash, 0, 
			CRYPT_STRING_HEXRAW, rgbHashOfCert, &chb.cbData, 0, 0))
		{
			if (HCERTSTORE hCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0, 
				IsServer() ? CERT_SYSTEM_STORE_LOCAL_MACHINE : CERT_SYSTEM_STORE_CURRENT_USER, L"MY"))
			{
				if (PCCERT_CONTEXT pCertContext = CertFindCertificateInStore(hCertStore, X509_ASN_ENCODING, 0, CERT_FIND_HASH, &chb, 0))
				{
					if (SslGetNameFromCertificate(pCertContext->pCertInfo, IsServer(), &_M_Name))
					{
						DbgPrint("name: %s\n", _M_Name);

						SCHANNEL_CRED sc = {
							SCHANNEL_CRED_VERSION, 1, &pCertContext
						};

						fOk = SEC_E_OK == AcquireCredentialsHandleW(0, const_cast<PWSTR>(SCHANNEL_NAME), 
							fCredentialUse, 0, &sc, 0, 0, &_M_hCred, 0);
					}

					CertFreeCertificateContext(pCertContext);
				}

				CertCloseStore(hCertStore, 0);
			}
		}

		return fOk;
	}

	virtual BOOL IsServer() = 0;

	SECURITY_STATUS Process(PVOID pb, ULONG cb)
	{
		SecBuffer InBuf[2] = {{ cb, SECBUFFER_TOKEN, pb }}, OutBuf = { 0, SECBUFFER_TOKEN }; 

		SecBufferDesc sbd_in = { SECBUFFER_VERSION, 2, InBuf }, sbd_out = { SECBUFFER_VERSION, 1, &OutBuf };

		DWORD ContextAttr;

		PCtxtHandle phContext = 0, phNewContext = 0;

		_M_hCtx.dwLower | _M_hCtx.dwUpper ? phContext = &_M_hCtx : phNewContext = &_M_hCtx;

		SECURITY_STATUS status = IsServer() 
			? AcceptSecurityContext(&_M_hCred, phContext, &sbd_in, ASC_REQ, 0, phNewContext, &sbd_out, &ContextAttr, 0) 
			: InitializeSecurityContextW(&_M_hCred, phContext, _M_pLink->_M_Name, 
			ISC_REQ, 0, 0, &sbd_in, 0, phNewContext, &sbd_out, &ContextAttr, 0);

		if (0 <= status)
		{
			if (OutBuf.cbBuffer)
			{
				_M_pLink->Process(OutBuf.pvBuffer, OutBuf.cbBuffer);
			}

			if (SEC_E_OK == status)
			{
				if (IsServer())
				{
					SecPkgContext_AccessToken at;

					if (SEC_E_OK == QueryContextAttributesW(&_M_hCtx, SECPKG_ATTR_ACCESS_TOKEN, &at))
					{
						DumpToken(at.AccessToken);
					}

					if (SEC_E_OK == QuerySecurityContextToken(&_M_hCtx, &at.AccessToken))
					{
						DumpToken(at.AccessToken);
						NtClose(at.AccessToken);
					}
				}
			}
		}

		return status;
	}
};

struct SSSrv : public SSH 
{
	virtual BOOL IsServer()
	{
		return TRUE;
	}
};

struct SSCli : public SSH 
{
	virtual BOOL IsServer()
	{
		return FALSE;
	}
};

void SSHtest()
{
	SSSrv s;
	SSCli c;
	if (s.Init(SECPKG_CRED_INBOUND, "5ba58cc5bb6bacdd1ddb0d2435786bd676b8ea7e"))
	{
		if (c.Init(SECPKG_CRED_OUTBOUND, "5149a1ab002604e9888a53aac2373e9a3c9ad6c7"))
		{
			s.SetLink(&c);
			c.SetLink(&s);
			c.Process(0, 0);
		}
	}
}

BOOL NeedClose(PLUID LogonSessionList, ULONG LogonSessionCount, HANDLE hToken, ULONG_PTR Value)
{
	TOKEN_STATISTICS ts;

	if (0 <= ZwQueryInformationToken(hToken, TokenStatistics, &ts, sizeof(ts), &ts.DynamicAvailable))
	{
		do 
		{
			if (LogonSessionList->LowPart == ts.AuthenticationId.LowPart &&
				LogonSessionList->HighPart == ts.AuthenticationId.HighPart)
			{
				DbgPrint("!! %p\r\n", Value);

				return TRUE;
			}
		} while (LogonSessionList++, --LogonSessionCount);
	}

	return FALSE;
}

void CloseZombie(PLUID LogonSessionList, ULONG LogonSessionCount)
{
	if (!LogonSessionCount) return;

	HANDLE hMyToken;
	if (OpenProcessToken(NtCurrentProcess(), TOKEN_QUERY, &hMyToken))
	{
		union {
			PVOID buf;
			SYSTEM_HANDLE_INFORMATION_EX* phei;
		};
		ULONG cb = 0x100000;
		NTSTATUS status;
		do 
		{
			status = STATUS_INSUFFICIENT_RESOURCES;
			if (buf  = LocalAlloc(LMEM_FIXED, cb += 0x1000))
			{
				if (0 <= (status = NtQuerySystemInformation(SystemExtendedHandleInformation, buf, cb, &cb)))
				{
					if (ULONG_PTR NumberOfHandles = phei->NumberOfHandles)
					{
						PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles = phei->Handles;
						ULONG dwProcessId = GetCurrentProcessId();
						do 
						{
							if (Handles->UniqueProcessId == dwProcessId &&
								Handles->HandleValue == (ULONG_PTR)hMyToken)
							{
								USHORT ObjectTypeIndex = Handles->ObjectTypeIndex;
								dwProcessId = 0x234;
								NumberOfHandles = phei->NumberOfHandles;
								Handles = phei->Handles;

								BOOLEAN b;
								RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &b);
								if (HANDLE hProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, dwProcessId))
								{
									do 
									{
										if (Handles->UniqueProcessId == dwProcessId &&
											ObjectTypeIndex == Handles->ObjectTypeIndex)
										{
											HANDLE hToken;
											if (DuplicateHandle(hProcess, (HANDLE)Handles->HandleValue, 
												NtCurrentProcess(), &hToken, 0, 0, DUPLICATE_SAME_ACCESS))
											{
												if (NeedClose(LogonSessionList, LogonSessionCount, hToken, Handles->HandleValue))
												{
													DuplicateHandle(hProcess, (HANDLE)Handles->HandleValue, 
														0, 0, 0, 0, DUPLICATE_CLOSE_SOURCE);
												}

												NtClose(hToken);
											}
											else
											{
												DbgPrint("dup(%p)=%x\n", Handles->HandleValue,RtlGetLastNtStatus());
											}
										}
									} while (Handles++, --NumberOfHandles);

									NtClose(hProcess);
								}

								break;
							}
						} while (Handles++, --NumberOfHandles);
					}
				}

				LocalFree(buf);
			}
		} while (STATUS_INFO_LENGTH_MISMATCH == status);

		NtClose(hMyToken);
	}
}

ULONG NormalizeList(PLUID LogonSessionList, ULONG LogonSessionCount)
{
	ULONG n = 0;
	PLUID LogonSessionListTo = LogonSessionList;
	do 
	{
		if (LogonSessionList->LowPart)
		{
			if (LogonSessionListTo != LogonSessionList)
			{
				*LogonSessionListTo++ = *LogonSessionList;
				n++;
			}
		}
	} while (LogonSessionList++, --LogonSessionCount);

	return n;
}

void CloseZombie()
{
	ULONG LogonSessionCount;
	PLUID LogonSessionList;
	if (0 <= LsaEnumerateLogonSessions(&LogonSessionCount, &LogonSessionList))
	{
		if (ULONG n = LogonSessionCount)
		{
			LogonSessionList += LogonSessionCount;
			do 
			{
				PSECURITY_LOGON_SESSION_DATA pLogonSessionData;
				if (0 <= LsaGetLogonSessionData(--LogonSessionList, &pLogonSessionData))
				{
					static const UNICODE_STRING Kelly = RTL_CONSTANT_STRING(L"Kelly");

					if (!RtlEqualUnicodeString(&Kelly, &pLogonSessionData->UserName, FALSE))
					{
						LogonSessionList->LowPart = 0;
						LogonSessionList->HighPart = 0;
					}

					LsaFreeReturnBuffer(pLogonSessionData);
				}
			} while (--LogonSessionCount);

			CloseZombie(LogonSessionList, NormalizeList(LogonSessionList, n));
		}

		LsaFreeReturnBuffer(LogonSessionList);
	}
}