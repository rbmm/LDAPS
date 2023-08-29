#pragma once

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

PCCERT_CONTEXT CheckCertAndGetName(_In_ PCCERT_CONTEXT pCertContext, _Out_ PWSTR* ppwszUserName)
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

//#define _PRINT_CPP_NAMES_
#include "../inc/asmfunc.h"
void aAfterNCryptImportKey()ASM_FUNCTION;

struct NCryptImportKey_Stack
{
	_In_ PVOID ReturnAddress;
	_In_    NCRYPT_PROV_HANDLE hProvider;
	_In_opt_ NCRYPT_KEY_HANDLE hImportKey;
	_In_    PCWSTR pszBlobType;
	_In_opt_ NCryptBufferDesc* pParameterList;
	_Out_   NCRYPT_KEY_HANDLE* phKey;
	_In_ PBYTE pbData;
	_In_    DWORD_PTR   cbData;
	_In_    DWORD   dwFlags;
};

struct ThreadCtx : public TEB_ACTIVE_FRAME
{
	inline static const char FrameName[] = "{0A0659E5-2962-480a-9A6F-01A02C5C043B}";

	ThreadCtx()
	{
		const static TEB_ACTIVE_FRAME_CONTEXT FrameContext = { 0, FrameName };
		Context = &FrameContext;
		Flags = 0;
		RtlPushFrame(this);
	}

	~ThreadCtx()
	{
		RtlPopFrame(this);
	}

	static ThreadCtx* get()
	{
		if (TEB_ACTIVE_FRAME* frame = RtlGetFrame())
		{
			do
			{
				if (frame->Context->FrameName == FrameName)
				{
					return static_cast<ThreadCtx*>(frame);
				}
			} while (frame = frame->Previous);
		}

		return 0;
	}
};

struct ImportKeyCtx : public ThreadCtx
{
	PVOID _M_Address;
	PCWSTR _M_Password;
	NCRYPT_KEY_HANDLE* _M_phMyKey;
	NCRYPT_KEY_HANDLE* _M_phKey = 0;
	PVOID _M_retAddr = 0;
	ULONG _M_dwFlags = 0;
	ULONG _M_crc = 0;

	ImportKeyCtx(PVOID Address, PCWSTR Password, NCRYPT_KEY_HANDLE* phMyKey)
		: _M_Address(Address), _M_Password(Password), _M_phMyKey(phMyKey)
	{
	}

	PCWSTR FixParams(NCryptImportKey_Stack* stack, ULONG crc)
	{
		_M_retAddr = stack->ReturnAddress;
		_M_phKey = stack->phKey;
		_M_dwFlags = stack->dwFlags;

		stack->ReturnAddress = aAfterNCryptImportKey;
		stack->dwFlags &= ~NCRYPT_DO_NOT_FINALIZE_FLAG;
		stack->phKey = _M_phMyKey;

		_M_crc = crc;

		return _M_Password;
	}

	SECURITY_STATUS AfterNCryptImportKey()
	{
		SECURITY_STATUS status;
		NCRYPT_PROV_HANDLE hProvider;
		if (NOERROR == (status = NCryptOpenStorageProvider(&hProvider, MS_KEY_STORAGE_PROVIDER, 0)))
		{
			NCRYPT_KEY_HANDLE hKey;
			status = NCryptCreatePersistedKey(hProvider, &hKey, BCRYPT_RSA_ALGORITHM, 0, 0, 0);
			NCryptFreeObject(hProvider);

			if (NOERROR == status)
			{
				ULONG Length = 0x400;
				NCryptSetProperty(hKey, NCRYPT_LENGTH_PROPERTY, (PBYTE)&Length, sizeof(Length), 0);

				if (!(_M_dwFlags & NCRYPT_DO_NOT_FINALIZE_FLAG))
				{
					status = NCryptFinalizeKey(hKey, NCRYPT_SILENT_FLAG);
				}

				if (NOERROR == status)
				{
					*_M_phKey = hKey;
				}
				else
				{
					NCryptFreeObject(hKey);
				}
			}
		}

		if (NOERROR != status)
		{
			NCryptFreeObject(*_M_phMyKey);
			*_M_phMyKey = 0;
		}

		return status;
	}
};

SECURITY_STATUS __fastcall AfterNCryptImportKey(SECURITY_STATUS status)
{
	CPP_FUNCTION;

	if (ImportKeyCtx* ctx = static_cast<ImportKeyCtx*>(ThreadCtx::get()))
	{
		*(void**)_AddressOfReturnAddress() = ctx->_M_retAddr;

		if (NOERROR == status)
		{
			status = ctx->AfterNCryptImportKey();
		}
	}
	else
	{
		__debugbreak();
	}

	return status;
}

NTSTATUS NTAPI VexImportKey(::PEXCEPTION_POINTERS ExceptionInfo)
{
	if (ImportKeyCtx* ctx = static_cast<ImportKeyCtx*>(ThreadCtx::get()))
	{
		::PEXCEPTION_RECORD ExceptionRecord = ExceptionInfo->ExceptionRecord;
		::PCONTEXT ContextRecord = ExceptionInfo->ContextRecord;

		if (ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP &&
			ExceptionRecord->ExceptionAddress == (PVOID)ctx->_M_Address)
		{
			if (!wcscmp(NCRYPT_PKCS8_PRIVATE_KEY_BLOB, (PWSTR)ContextRecord->R8))
			{
				if (PNCryptBufferDesc ParameterList = (PNCryptBufferDesc)ContextRecord->R9)
				{
					if (ULONG cBuffers = ParameterList->cBuffers)
					{
						PBCryptBuffer pBuffer = ParameterList->pBuffers;

						do
						{
							if (NCRYPTBUFFER_PKCS_KEY_NAME == pBuffer->BufferType)
							{
								PCWSTR Password = ctx->FixParams((NCryptImportKey_Stack*)ContextRecord->Rsp,
									RtlComputeCrc32(0, pBuffer->pvBuffer, pBuffer->cbBuffer));

								ParameterList->cBuffers = 1;
								pBuffer = ParameterList->pBuffers;

								pBuffer->BufferType = NCRYPTBUFFER_PKCS_SECRET;
								pBuffer->pvBuffer = const_cast<PWSTR>(Password);
								pBuffer->cbBuffer = (1 + (ULONG)wcslen(Password)) * sizeof(WCHAR);

								break;
							}

						} while (pBuffer++, --cBuffers);
					}
				}
			}

			ContextRecord->EFlags |= 0x10000;//Resume Flag
			return EXCEPTION_CONTINUE_EXECUTION;
		}
	}

	return EXCEPTION_CONTINUE_SEARCH;
}

HRESULT PFXImport(_In_ DATA_BLOB* pPFX,
	_In_ PCWSTR szPassword,
	_Out_ PWSTR* ppwszUserName,
	_Out_ PCCERT_CONTEXT* ppCertContext,
	_Out_ NCRYPT_KEY_HANDLE* phKey,
	_Out_ PULONG pCrc)
{
	HRESULT hr = E_FAIL;

	HCERTSTORE hStore = 0;
	NCRYPT_KEY_HANDLE hKey = 0;

	if (phKey)
	{
		if (PVOID Handle = RtlAddVectoredExceptionHandler(TRUE, VexImportKey))
		{
			::CONTEXT ctx{};
			if (ctx.Dr3 = (ULONG_PTR)GetProcAddress(GetModuleHandleW(L"ncrypt.dll"), "NCryptImportKey"))
			{
				ctx.Dr6 = 0;
				ctx.Dr7 = 0x440;
				ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

				if (SetThreadContext(NtCurrentThread(), &ctx))
				{
					ImportKeyCtx tctx((PVOID)ctx.Dr3, szPassword, &hKey);

					hStore = HR(hr, PFXImportCertStore(pPFX, szPassword, PKCS12_ALWAYS_CNG_KSP));

					ctx.Dr3 = 0;
					ctx.Dr7 = 0x400;
					SetThreadContext(NtCurrentThread(), &ctx);

					if (0 <= hr)
					{
						*pCrc = tctx._M_crc;
					}
				}
			}

			RtlRemoveVectoredExceptionHandler(Handle);
		}
	}
	else
	{
		hStore = HR(hr, PFXImportCertStore(pPFX, szPassword, PKCS12_ALWAYS_CNG_KSP));
	}

	if (hStore)
	{
		PCCERT_CONTEXT pCertContext = 0;

		union {
			PVOID pfn;
			PCCERT_CONTEXT(*CheckCert)(_In_ PCCERT_CONTEXT pCertContext, _Out_ PVOID);
			PCCERT_CONTEXT(*CheckCert1)(_In_ PCCERT_CONTEXT pCertContext, _Out_ PWSTR* ppwszUserName);
			PCCERT_CONTEXT(*CheckCert2)(_In_ PCCERT_CONTEXT pCertContext, _Out_ PCCERT_CONTEXT* ppCertContext);
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
	else
	{
		if (hKey)
		{
			NCryptFreeObject(hKey);
		}
	}

	if (phKey)
	{
		if (NOERROR == hr)
		{
			*phKey = hKey;
		}
		else
		{
			NCryptFreeObject(hKey);
		}
	}

	return hr;
}

HRESULT PFXImport(_In_ PCWSTR lpFileName,
	_In_ PCWSTR szPassword,
	_Out_ PWSTR* ppwszUserName,
	_Out_ PCCERT_CONTEXT* ppCertContext,
	_Out_ NCRYPT_KEY_HANDLE* phKey,
	_Out_ PULONG pCrc)
{
	if (!lpFileName)
	{
		return S_OK;
	}

	if ((ppCertContext != 0) ^ (ppwszUserName != 0))
	{
		DATA_BLOB db;
		HRESULT hr = ReadFromFile(lpFileName, &db);

		if (0 <= hr)
		{
			PFXImport(&db, szPassword, ppwszUserName, ppCertContext, phKey, pCrc);
			LocalFree(db.pbData);
		}
		return hr;
	}

	return HRESULT_FROM_NT(STATUS_INVALID_PARAMETER_MIX);
}

//////////////////////////////////////////////////////////////////////////
//

struct OpenKeyCtx : public ThreadCtx
{
	PVOID _M_Address;
	NCRYPT_KEY_HANDLE* _M_phKey;
	ULONG _M_crc;

	OpenKeyCtx(PVOID Address, NCRYPT_KEY_HANDLE* phKey, ULONG crc) : _M_Address(Address), _M_crc(crc), _M_phKey(phKey)
	{
	}

	~OpenKeyCtx()
	{
		if (*_M_phKey)
		{
			NCryptFreeObject(*_M_phKey);
			*_M_phKey = 0;
		}
	}
};

NTSTATUS NTAPI VexOpenKey(::PEXCEPTION_POINTERS ExceptionInfo)
{
	if (OpenKeyCtx* ctx = static_cast<OpenKeyCtx*>(ThreadCtx::get()))
	{
		::PEXCEPTION_RECORD ExceptionRecord = ExceptionInfo->ExceptionRecord;
		::PCONTEXT ContextRecord = ExceptionInfo->ContextRecord;

		if (ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP &&
			ExceptionRecord->ExceptionAddress == (PVOID)ctx->_M_Address)
		{
			PCWSTR pszKeyName = (PCWSTR)ContextRecord->R8;

			DbgPrint("NCryptOpenKey(%s)\r\n", pszKeyName);

			if (ctx->_M_crc == RtlComputeCrc32(0, pszKeyName, sizeof(WCHAR) * (1 + (ULONG)wcslen(pszKeyName))))
			{
				*(NCRYPT_KEY_HANDLE*)ContextRecord->Rdx = *ctx->_M_phKey;
				*ctx->_M_phKey = 0;

				ContextRecord->Rip = *(ULONG_PTR*)ContextRecord->Rsp;
				ContextRecord->Rsp += sizeof(ULONG_PTR);
				ContextRecord->Rax = NOERROR;
			}

			ContextRecord->EFlags |= 0x10000;//Resume Flag
			return EXCEPTION_CONTINUE_EXECUTION;
		}
	}

	return EXCEPTION_CONTINUE_SEARCH;
}

ULONG ldap_connect(LDAP* ld, struct l_timeval* timeout, NCRYPT_KEY_HANDLE* phKey, ULONG crc)
{
	ULONG r = LDAP_OTHER;

	if (PVOID Handle = RtlAddVectoredExceptionHandler(TRUE, VexOpenKey))
	{
		::CONTEXT ctx{};
		if (ctx.Dr3 = (ULONG_PTR)GetProcAddress(GetModuleHandleW(L"ncrypt.dll"), "NCryptOpenKey"))
		{
			ctx.Dr6 = 0;
			ctx.Dr7 = 0x440;
			ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

			if (SetThreadContext(NtCurrentThread(), &ctx))
			{
				OpenKeyCtx tctx((PVOID)ctx.Dr3, phKey, crc);

				r = ldap_connect(ld, timeout);

				ctx.Dr3 = 0;
				ctx.Dr7 = 0x400;
				SetThreadContext(NtCurrentThread(), &ctx);
			}
		}

		RtlRemoveVectoredExceptionHandler(Handle);
	}

	return r;
}