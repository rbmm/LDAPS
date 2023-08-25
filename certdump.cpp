#include "stdafx.h"

#include <certenroll.h>
#include "util.h"
typedef CONST UCHAR *PCUCHAR;
void TestDecode(PDATA_BLOB pdb);
void TestDecode(PCUCHAR pb, ULONG cb);

void DumpBytes(const UCHAR* pb, ULONG cb, PCSTR prefix /*= ""*/, PCSTR suffix /*= ""*/)
{
	if (!cb)
	{
		return ;
	}
	DbgPrint("%S<![CDATA[ // %S[%x]\n", prefix, suffix, cb);
	PSTR psz = 0;
	ULONG cch = 0;
	while(CryptBinaryToStringA(pb, cb, CRYPT_STRING_HEXASCIIADDR, psz, &cch))
	{
		if (psz)
		{
			PSTR pc = psz, pd;
			do 
			{
				if (pd = strchr(pc, '\n'))
				{
					*pd = 0;
					DbgPrint("%S%S\n", prefix, pc);
					pc = pd + 1;
				}
				else
				{
					if (*pc) DbgPrint("%S%S\n", prefix, pc);
					break;
				}
			} while (TRUE);

			break;
		}

		psz = new char[cch];
	}
	delete [] psz;
	DbgPrint("%S]]>\n", prefix);
}

void DumpHash(PUCHAR pb, ULONG cb, _In_ PCWSTR pwszCNGHashAlgid = BCRYPT_MD5_ALGORITHM)
{
	UCHAR hash[32];
	ULONG len = sizeof(hash);
	if (CryptHashCertificate2(pwszCNGHashAlgid, 0, 0, pb, cb, hash, &len))
	{
		DumpBytesInLine(hash, len, "\tHash: ");
	}
}

void DumpName(PCSTR pszObjId, DWORD dwValueType, PCERT_RDN_VALUE_BLOB Value)
{
	DbgPrint("\t%S: ", pszObjId);

	switch (dwValueType)
	{
	case CERT_RDN_UNICODE_STRING:
	case CERT_RDN_UTF8_STRING:
		DbgPrint("%.*s\n", Value->cbData / sizeof(WCHAR), Value->pbData);
		break;

	case CERT_RDN_PRINTABLE_STRING:
	case CERT_RDN_IA5_STRING:
	case CERT_RDN_TELETEX_STRING:
		DbgPrint("%.*S\n", Value->cbData, Value->pbData);
		break;

	default: __debugbreak();
	}
}

void DumpName(const CERT_NAME_BLOB* Name, PCWSTR msg)
{
	PrintUTF8(msg);

	PCERT_NAME_INFO pcni;
	if (0 <= Decode(X509_NAME, Name->pbData, Name->cbData, &pcni))
	{
		if (DWORD cRDN = pcni->cRDN)
		{
			PCERT_RDN rgRDN = pcni->rgRDN;

			do 
			{

				if (DWORD cRDNAttr = rgRDN->cRDNAttr)
				{
					PCERT_RDN_ATTR rgRDNAttr = rgRDN->rgRDNAttr;
					do 
					{
						DumpName(rgRDNAttr->pszObjId, rgRDNAttr->dwValueType, &rgRDNAttr->Value);

					} while (rgRDNAttr++, --cRDNAttr);
				}
			} while (rgRDN++, --cRDN);
		}

		LocalFree(pcni);
	}
}

void DumpName(PCERT_OTHER_NAME pOtherName)
{
	PCERT_NAME_VALUE pcnv;

	if (0 <= Decode(X509_UNICODE_ANY_STRING, pOtherName->Value.pbData, pOtherName->Value.cbData, &pcnv))
	{
		DumpName(pOtherName->pszObjId, pcnv->dwValueType, &pcnv->Value);
		LocalFree(pcnv);
	}
}

void DumpAltName(PCERT_ALT_NAME_INFO NameInfo)
{
	DbgPrint("\tSUBJECT_ALT_NAME:\n");

	if (DWORD cAltEntry = NameInfo->cAltEntry)
	{
		PCERT_ALT_NAME_ENTRY rgAltEntry = NameInfo->rgAltEntry;
		do 
		{
			switch (rgAltEntry->dwAltNameChoice)
			{
			case CERT_ALT_NAME_OTHER_NAME:
				DumpName(rgAltEntry->pOtherName);
				break;

			case CERT_ALT_NAME_DNS_NAME:
			case CERT_ALT_NAME_RFC822_NAME:
			case CERT_ALT_NAME_URL:
				DbgPrint("\t%s\n", rgAltEntry->pwszDNSName);
				break;
			case CERT_ALT_NAME_REGISTERED_ID:
				DbgPrint("\t%S\n", rgAltEntry->pszRegisteredID);
				break;
			case CERT_ALT_NAME_DIRECTORY_NAME:
				DumpName(&rgAltEntry->DirectoryName, L"\tDIRECTORY_NAME:\n");
				break;
			}
		} while (rgAltEntry++, --cAltEntry);
	}
}

void DumpKeyUsage(PCRYPT_BIT_BLOB pcbb)
{
	DumpBytesInLine(pcbb->pbData, pcbb->cbData, "\tKEY_USAGE: ");
}

void DumpExchangedKeyUsage(PCERT_ENHKEY_USAGE EnKeyUsage)
{
	DbgPrint("\tENHANCED_KEY_USAGE:\n");
	if (DWORD cUsageIdentifier = EnKeyUsage->cUsageIdentifier)
	{
		PSTR *rgpszUsageIdentifier = EnKeyUsage->rgpszUsageIdentifier;
		do 
		{
			DbgPrint("\t\t%S\n", *rgpszUsageIdentifier++);
		} while (--cUsageIdentifier);
	}
}

void DumpKeyId(PCRYPT_HASH_BLOB KeyId)
{
	DumpBytesInLine(KeyId->pbData, KeyId->cbData, "\tSUBJECT_KEY_IDENTIFIER: ");
}

void ProcessAnyName(PCERT_NAME_VALUE p)
{
	DumpName("*", p->dwValueType, &p->Value);
}

void DumpTemplateV2(PCERT_TEMPLATE_EXT p)
{
	DbgPrint("\t%S %u.%u.%u\r\n", p->pszObjId, p->dwMajorVersion, p->dwMinorVersion, p->fMinorVersion);
}

void DumpPolicyInfo(PCERT_POLICIES_INFO ppi)
{
	if (DWORD cPolicyInfo = ppi->cPolicyInfo)
	{
		CERT_POLICY_INFO *rgPolicyInfo = ppi->rgPolicyInfo;
		do 
		{
			DbgPrint("\tPolicyIdentifier=%S\r\n", rgPolicyInfo->pszPolicyIdentifier);

			if (DWORD cPolicyQualifier = rgPolicyInfo->cPolicyQualifier)
			{
				CERT_POLICY_QUALIFIER_INFO *rgPolicyQualifier = rgPolicyInfo->rgPolicyQualifier;
				do 
				{
					DbgPrint("\t\tPolicyQualifierId=%S\r\n", rgPolicyQualifier->pszPolicyQualifierId);

					PVOID pv;
					if (0 <= Decode(rgPolicyQualifier->pszPolicyQualifierId, &rgPolicyQualifier->Qualifier, &pv))
					{
						__nop();
					}
					else if (0 <= Decode(rgPolicyInfo->pszPolicyIdentifier, &rgPolicyQualifier->Qualifier, &pv))
					{
						__nop();
					}
					else 
					{
						TestDecode(&rgPolicyQualifier->Qualifier);
					}

				} while (rgPolicyQualifier++, --cPolicyQualifier);
			}
		} while (rgPolicyInfo++, --cPolicyInfo);
	}
}

void ProcessExtensionsI(DWORD cExtension, PCERT_EXTENSION rgExtension)
{
	if (cExtension)
	{
		do 
		{
			DbgPrint("\tEXT[<%x> %S]:\n", rgExtension->fCritical, rgExtension->pszObjId);

			PVOID pv;

			union {
				PVOID pvpfn;
				void (*pfn)(void*);
			};

			PCSTR pszObjId = rgExtension->pszObjId;

			PCSTR lpszStructType = pszObjId;

			if (!strcmp(szOID_ENROLL_CERTTYPE_EXTENSION, pszObjId))
			{
				lpszStructType = X509_UNICODE_NAME_VALUE;
				pvpfn = ProcessAnyName;
			}
			else if (!strcmp(szOID_CERTIFICATE_TEMPLATE, pszObjId))
			{
				lpszStructType = X509_CERTIFICATE_TEMPLATE;
				pvpfn = DumpTemplateV2;
			}
			else if (!strcmp(szOID_APPLICATION_CERT_POLICIES, pszObjId))
			{
				lpszStructType = szOID_CERT_POLICIES;
				pvpfn = DumpPolicyInfo;
			}
			else if (!strcmp(szOID_SUBJECT_KEY_IDENTIFIER, pszObjId))
			{
				pvpfn = DumpKeyId;
			}
			else if (!strcmp(szOID_SUBJECT_ALT_NAME2, pszObjId))
			{
				pvpfn = DumpAltName;
			}
			else if (!strcmp(szOID_KEY_USAGE, pszObjId))
			{
				pvpfn = DumpKeyUsage;
			}
			else if (!strcmp(szOID_ENHANCED_KEY_USAGE, pszObjId))
			{
				pvpfn = DumpExchangedKeyUsage;
			}
			else
			{
				TestDecode(&rgExtension->Value);
				continue;
			}
			
			if (0 <= Decode(lpszStructType, &rgExtension->Value, &pv))
			{
				pfn(pv);
				LocalFree(pv);
			}

		} while (rgExtension++, --cExtension);
	}
}

void ProcessExtensions(PCERT_EXTENSIONS pExt)
{
	ProcessExtensionsI(pExt->cExtension, pExt->rgExtension);
}

void PrintclientId(ULONG* pi)
{
	DbgPrint("\tRequestClientInfoClientId=%x\n", *pi);
}

void ProcessCspName(PCERT_NAME_VALUE p)
{
	switch (p->dwValueType)
	{
	case CERT_RDN_ENCODED_BLOB:
		PCRYPT_CSP_PROVIDER CSPProvider;
		if (0 <= Decode(szOID_ENROLLMENT_CSP_PROVIDER, &p->Value, &CSPProvider))
		{
			DbgPrint("dwKeySpec=%x\npwszProviderName=%s\n", CSPProvider->dwKeySpec, CSPProvider->pwszProviderName);
			DumpBytes(CSPProvider->Signature.pbData, CSPProvider->Signature.cbData, "", "sig");
			LocalFree(CSPProvider);
		}
		break;
	default:
		DbgPrint("\t!! dwValueType=%x\n", p->dwValueType);
	}
}

void ProcessOsVersion(PCERT_NAME_VALUE p)
{
	switch (p->dwValueType)
	{
	case CERT_RDN_IA5_STRING:
		DbgPrint("\tOsVersion=%.*S\n", p->Value.cbData, p->Value.pbData);
		break;
	default:
		DbgPrint("\t!! dwValueType=%x\n", p->dwValueType);
	}
}

void ProcessClientInfo(PCRYPT_SEQUENCE_OF_ANY p)
{
	//SEQUENCE {
	//	clientId INTEGER,
	//	MachineName UTF8STRING,
	//	UserName UTF8STRING,
	//	ProcessName UTF8STRING
	//}

	if (DWORD cValue = p->cValue)
	{
		PCRYPT_DER_BLOB rgValue = p->rgValue;
		ULONG i = 0;
		do 
		{
			PCSTR psz="";
			union {
				PVOID pvpfn;
				void (*pfn)(void*);
			};
			switch (i++)
			{
			case 0: 
				psz = X509_INTEGER;
				pvpfn = PrintclientId;
				break;
			case 1: 
			case 2: 
			case 3: 
				psz = X509_UNICODE_NAME_VALUE;
				pvpfn = ProcessAnyName;
				break;
			}
			PVOID pv;
			if (0 <= Decode(psz, rgValue->pbData, rgValue->cbData, &pv))
			{
				pfn(pv);
				LocalFree(pv);
			}
		} while (rgValue++, --cValue);
	}
}

void DumpEVP(PCRYPT_ENROLLMENT_NAME_VALUE_PAIR pcenvp)
{
	DbgPrint("\t\t{ \"%s\" : \"%s\" }\r\n", pcenvp->pwszName, pcenvp->pwszValue);
}

void DumpOID(PCSTR* ppszObjId)
{
	DbgPrint("\t\tOID= \"%S\"\r\n", *ppszObjId);
}

void DumpAttributes(DWORD cAttribute, PCRYPT_ATTRIBUTE rgAttribute)
{
	if (cAttribute)
	{
		do 
		{
			DbgPrint("ATTR=%S:\n", rgAttribute->pszObjId);

			if (DWORD cValue = rgAttribute->cValue)
			{
				PCRYPT_ATTR_BLOB rgValue = rgAttribute->rgValue;
				do 
				{
					PVOID pv;

					union {
						PVOID pvpfn;
						void (*pfn)(void*);
					};

					PCSTR pszObjId = rgAttribute->pszObjId, lpszStructType = pszObjId;

					if (!strcmp(pszObjId, szOID_OS_VERSION))
					{
						pvpfn = ProcessOsVersion;
						lpszStructType = X509_NAME_VALUE;
					}
					else if (!strcmp(pszObjId, szOID_REQUEST_CLIENT_INFO))
					{
						pvpfn = ProcessClientInfo;
						lpszStructType = X509_SEQUENCE_OF_ANY;
					}
					else if (!strcmp(pszObjId, szOID_ENROLLMENT_CSP_PROVIDER))
					{
						pvpfn = ProcessCspName;
						lpszStructType = X509_NAME_VALUE;
					}
					else if (!strcmp(pszObjId, szOID_CERT_EXTENSIONS) ||
						!strcmp(pszObjId, szOID_RSA_certExtensions))
					{
						pvpfn = ProcessExtensions;
						lpszStructType = X509_EXTENSIONS;
					}
					else if (!strcmp(pszObjId, szOID_ENROLLMENT_NAME_VALUE_PAIR))
					{
						pvpfn = DumpEVP;
					}
					else if (!strcmp(pszObjId, szOID_PKCS_9_CONTENT_TYPE))
					{
						pvpfn = DumpOID;
						lpszStructType = X509_OBJECT_IDENTIFIER; // szOID_ECC_PUBLIC_KEY
					}
					else if (!strcmp(pszObjId, szOID_PKCS_9_MESSAGE_DIGEST))
					{
						pvpfn = DumpKeyId;
						lpszStructType = X509_OCTET_STRING; // szOID_SUBJECT_KEY_IDENTIFIER
					}
					else
					{
						DbgPrint("!! unknown attribute\n");
						TestDecode(rgValue);
						continue;
					}

					if (0 <= Decode(lpszStructType, rgValue, &pv))
					{
						pfn(pv);
						LocalFree(pv);
					}
				} while (rgValue++, --cValue);
			}

		} while (rgAttribute++, --cAttribute);
	}
}

void Dump(PCERT_REQUEST_INFO pcri)
{
	PCERT_PUBLIC_KEY_INFO SubjectPublicKeyInfo = &pcri->SubjectPublicKeyInfo;

	DumpHash(SubjectPublicKeyInfo->PublicKey.pbData, SubjectPublicKeyInfo->PublicKey.cbData, BCRYPT_SHA1_ALGORITHM);

	DbgPrint("CERT_REQUEST_INFO:\n\tdwVersion=%x\n\t%S\n", pcri->dwVersion, SubjectPublicKeyInfo->Algorithm.pszObjId);

	char buf[0x100];
	if (CertNameToStrA(X509_ASN_ENCODING, &pcri->Subject, CERT_X500_NAME_STR, buf, _countof(buf)))
	{
		DbgPrint("\t%S\n", buf);
	}

	ULONG cbKey;
	BCRYPT_RSAKEY_BLOB* PublicKey;
	if (0 <= Decode(CNG_RSA_PUBLIC_KEY_BLOB, &SubjectPublicKeyInfo->PublicKey, &PublicKey, &cbKey))
	{
		DumpBytes((PBYTE)PublicKey, cbKey, "", "");
		LocalFree(PublicKey);
	}

	DumpAttributes(pcri->cAttribute, pcri->rgAttribute);
}

void DumpRequest_PKCS_10(PBYTE pb, ULONG cb)
{
	PCERT_REQUEST_INFO pcri;
	PCERT_SIGNED_CONTENT_INFO pcsci;

	if (0 <= Decode(X509_CERT, pb, cb, &pcsci))
	{
		LPSTR pszObjId = pcsci->SignatureAlgorithm.pszObjId;

		DbgPrint("SignatureAlgorithm=%S\n", pszObjId);

		if (0 <= Decode(X509_CERT_REQUEST_TO_BE_SIGNED, 
			pcsci->ToBeSigned.pbData, pcsci->ToBeSigned.cbData, &pcri))
		{
			BCRYPT_PKCS1_PADDING_INFO pi = { };
			
			if (!strcmp(pszObjId, szOID_RSA_SHA256RSA))
			{
				pi.pszAlgId = BCRYPT_SHA256_ALGORITHM;
			}
			else if (!strcmp(pszObjId, szOID_RSA_SHA1RSA))
			{
				pi.pszAlgId = BCRYPT_SHA1_ALGORITHM;
			}
			else if (!strcmp(pszObjId, szOID_RSA_SHA512RSA))
			{
				pi.pszAlgId = BCRYPT_SHA512_ALGORITHM;
			}
			else if (!strcmp(pszObjId, szOID_RSA_SHA384RSA))
			{
				pi.pszAlgId = BCRYPT_SHA384_ALGORITHM;
			}

			NTSTATUS status = STATUS_NOT_IMPLEMENTED;

			if (pi.pszAlgId)
			{
				BCRYPT_KEY_HANDLE hKey;

				if (CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, &pcri->SubjectPublicKeyInfo, 0, 0, &hKey))
				{
					UCHAR hash[32];
					ULONG len = sizeof(hash);
					if (CryptHashCertificate2(pi.pszAlgId, 0, 0, pcsci->ToBeSigned.pbData, pcsci->ToBeSigned.cbData, hash, &len))
					{
						status = BCryptVerifySignature(hKey, &pi, hash, len, 
							pcsci->Signature.pbData, pcsci->Signature.cbData, BCRYPT_PAD_PKCS1);
					}
					else
					{
						status = GetLastHrEx();
					}

					BCryptDestroyKey(hKey);
				}
				else
				{
					status = GetLastHrEx();
				}
			}

			DbgPrint("VerifySignature = %x\n", status);

			Dump(pcri);

			LocalFree(pcri);
		}

		LocalFree(pcsci);
	}
}

//////////////////////////////////////////////////////////////////////////

void DumpCMC_DATA(PCMC_DATA_INFO pcmc)
{
	if (DWORD cTaggedAttribute = pcmc->cTaggedAttribute)
	{
		PCMC_TAGGED_ATTRIBUTE rgTaggedAttribute = pcmc->rgTaggedAttribute;

		do 
		{
			DbgPrint("dwBodyPartID=%x\nOID=%S\n", rgTaggedAttribute->dwBodyPartID, rgTaggedAttribute->Attribute.pszObjId);

			if (!strcmp(szOID_CMC_ADD_ATTRIBUTES, rgTaggedAttribute->Attribute.pszObjId))
			{
				if (ULONG cValue = rgTaggedAttribute->Attribute.cValue)
				{
					PCRYPT_ATTR_BLOB rgValue = rgTaggedAttribute->Attribute.rgValue;

					do 
					{
						PCMC_ADD_ATTRIBUTES_INFO paa;
						if (0 <= Decode(CMC_ADD_ATTRIBUTES, rgValue, &paa))
						{
							DbgPrint("dwCmcDataReference=%x cCertReference=%x\n", paa->dwCmcDataReference, paa->cCertReference);

							DumpAttributes(paa->cAttribute, paa->rgAttribute);

							LocalFree(paa);
						}

					} while (rgValue++, --cValue);
				}
			}

		} while (rgTaggedAttribute++, --cTaggedAttribute);
	}

	if (DWORD cTaggedRequest = pcmc->cTaggedRequest)
	{
		PCMC_TAGGED_REQUEST rgTaggedRequest = pcmc->rgTaggedRequest;
		do 
		{
			if (CMC_TAGGED_CERT_REQUEST_CHOICE == rgTaggedRequest->dwTaggedRequestChoice)
			{
				PCMC_TAGGED_CERT_REQUEST pTaggedCertRequest = rgTaggedRequest->pTaggedCertRequest;

				DbgPrint("dwBodyPartID=%x\n", pTaggedCertRequest->dwBodyPartID);

				DumpRequest_PKCS_10(&pTaggedCertRequest->SignedCertRequest);
			}

		} while (rgTaggedRequest++, --cTaggedRequest);
	}
}

void Dump_PKCS_7(PCRYPT_CONTENT_INFO_SEQUENCE_OF_ANY p)
{
	union {
		PCRYPT_CONTENT_INFO pci;
		PULONG pu;
		PCERT_NAME_VALUE pcnv;
	};

	if (DWORD cValue = p->cValue)
	{
		PCRYPT_DER_BLOB rgValue = p->rgValue;
		PDATA_BLOB pdb;

		ULONG i = 0;
		do 
		{
			switch (i++)
			{
			case 0:
				if (0 <= Decode(X509_INTEGER, rgValue, &pu))
				{
					DbgPrint("\tCMSVersion=%x\r\n", *pu);
					LocalFree(pu);
				}
				break;
			case 1:
				break;
			case 3:
				if (0 <= Decode(X509_NAME_VALUE, rgValue, &pcnv))
				{
					switch (pcnv->dwValueType)
					{
					case CERT_RDN_ENCODED_BLOB:
						TestDecode(&pcnv->Value);
						break;
					default:
						DbgPrint("\t!! dwValueType=%x\n", pcnv->dwValueType);
					}
					LocalFree(pcnv);
				}
				break;
			default:
				TestDecode(rgValue);
				break;
			case 2:
				if (0 <= Decode(PKCS_CONTENT_INFO, rgValue, &pci))
				{
					DbgPrint("\tOID=%S\r\n", pci->pszObjId);

					if (!strcmp(pci->pszObjId, szOID_CT_PKI_DATA) ||
						!strcmp(pci->pszObjId, szOID_PKCS_7_DATA))
					{
						PCMC_DATA_INFO pcmc;

						if (0 <= Decode(X509_OCTET_STRING, &pci->Content, &pdb))
						{
							if (0 <= Decode(CMC_DATA, pdb, &pcmc))
							{
								DumpCMC_DATA(pcmc);
								LocalFree(pcmc);
							}
							else
							{
								DumpRequest_PKCS_10(pdb->pbData, pdb->cbData);
							}
							LocalFree(pdb);
						}
					}

					LocalFree(pci);
				}
				break;
			}

		} while (rgValue++, --cValue);
	}
}

HRESULT ValidateCert(_In_ PCCERT_CONTEXT pCertContext, 
					 _In_ PCERT_CHAIN_PARA pChainPara,
					 _Out_opt_ PCCERT_CHAIN_CONTEXT* ppChainContext /*= 0*/)
{
	PCCERT_CHAIN_CONTEXT pChainContext = 0;

	HRESULT hr;

	if (HR(hr, CertGetCertificateChain(HCCE_LOCAL_MACHINE, pCertContext, 0, 0, pChainPara, 
		CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT, 0, &pChainContext)))
	{
		CERT_CHAIN_POLICY_PARA PolicyPara = { sizeof(PolicyPara) };
		CERT_CHAIN_POLICY_STATUS PolicyStatus = { sizeof(PolicyStatus) };

		if (HR(hr, CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_NT_AUTH, pChainContext, &PolicyPara, &PolicyStatus)))
		{
			if (CRYPT_E_REVOCATION_OFFLINE == (hr = PolicyStatus.dwError))
			{
				hr = S_OK;
			}
		}

		if (0 <= hr && ppChainContext)
		{
			*ppChainContext = pChainContext;
		}
		else
		{
			CertFreeCertificateChain(pChainContext);
		}
	}

	DbgPrint("VerifyCertificate=%x\r\n", hr);

	PrintError(hr);

	return HRESULT_FROM_WIN32(hr);
}

HRESULT ValidateCert(_In_ PCCERT_CONTEXT pCertContext, _In_ PCSTR szUsageIdentifier)
{
	CERT_CHAIN_PARA ChainPara = { 
		sizeof(ChainPara), { USAGE_MATCH_TYPE_AND, { 1, const_cast<PSTR*>(&szUsageIdentifier) } } 
	};

	return ValidateCert(pCertContext, &ChainPara);
}

ULONG ValidateSign(_In_ HCRYPTMSG hCryptMsg, _Inout_ PCMSG_CTRL_VERIFY_SIGNATURE_EX_PARA pcvs, _In_ PCSTR szUsageIdentifier)
{
	HRESULT hr;
	PBYTE pbCertEncoded = 0;
	ULONG cbCertEncoded = 0;

	ULONG dwIndex = --(pcvs->dwSignerIndex);

	while (HR(hr, CryptMsgGetParam(hCryptMsg, CMSG_CERT_PARAM, dwIndex, pbCertEncoded, &cbCertEncoded)))
	{
		if (pbCertEncoded)
		{
			if (PCCERT_CONTEXT pCertContext = CertCreateCertificateContext(CRYPT_ASN_ENCODING, pbCertEncoded, cbCertEncoded))
			{
				pcvs->pvSigner = const_cast<PCERT_CONTEXT>(pCertContext);

				if (HR(hr, CryptMsgControl(hCryptMsg, 0, CMSG_CTRL_VERIFY_SIGNATURE_EX, pcvs)))
				{
					hr = ValidateCert(pCertContext, szUsageIdentifier);
				}

				CertFreeCertificateContext(pCertContext);
			}

			break;
		}

		pbCertEncoded = (PBYTE)alloca(cbCertEncoded);
	}

	return hr;
}

HRESULT GetMsgType(_In_ HCRYPTMSG hCryptMsg, _Out_ PULONG dwMsgType)
{
	ULONG cb = sizeof(ULONG);

	return CryptMsgGetParam(hCryptMsg, CMSG_TYPE_PARAM, 0, dwMsgType, &cb) ? S_OK : GetLastHr();
}

HRESULT IsSignedMessage(HCRYPTMSG hCryptMsg)
{
	ULONG dwMsgType;

	HRESULT hr = GetMsgType(hCryptMsg, &dwMsgType);

	if (0 <= hr)
	{
		return dwMsgType == CMSG_SIGNED ? S_OK : HRESULT_FROM_NT(STATUS_OBJECT_TYPE_MISMATCH);
	}

	return hr;
}

HRESULT GetAttrs(HCRYPTMSG hCryptMsg, DWORD dwSignerIndex)
{
	HRESULT hr;
	ULONG cb = 0;
	union {
		PBYTE pb = 0;
		PCRYPT_ATTRIBUTES pca;
	};
	while (HR(hr, CryptMsgGetParam(hCryptMsg, CMSG_SIGNER_AUTH_ATTR_PARAM, dwSignerIndex, pb, &cb)))
	{
		if (pb)
		{
			DumpAttributes(pca->cAttr, pca->rgAttr);
			break;
		}

		pb = (PBYTE)alloca(cb);
	}

	return hr;
}

HRESULT VerifyCMC(const BYTE* pbEncodedBlob, ULONG cbEncodedBlob, _In_ PCSTR szUsageIdentifier)
{
	HRESULT hr;
	if (HCRYPTMSG hCryptMsg = HR(hr, CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, 0, 0, 0, 0)))
	{
		if (HR(hr, CryptMsgUpdate(hCryptMsg, pbEncodedBlob, cbEncodedBlob, TRUE)))
		{
			if (NOERROR == (hr = IsSignedMessage(hCryptMsg)))
			{
				CMSG_CTRL_VERIFY_SIGNATURE_EX_PARA cvs = { sizeof(cvs), 0, 0, CMSG_VERIFY_SIGNER_CERT };

				ULONG cb;

				if (HR(hr, CryptMsgGetParam(hCryptMsg, CMSG_CERT_COUNT_PARAM, 0, &cvs.dwSignerIndex, &(cb = sizeof(ULONG)))))
				{
					hr = ERROR_NOT_FOUND;

					if (cvs.dwSignerIndex)
					{
						do 
						{
							if (NOERROR == (hr = ValidateSign(hCryptMsg, &cvs, szUsageIdentifier)))
							{
								PBYTE pb = 0;
								cb = 0;

								while (HR(hr, CryptMsgGetParam(hCryptMsg, CMSG_CONTENT_PARAM, 0, pb, &cb)))
								{
									if (pb)
									{
										DumpRequest_PKCS_10(pb, cb);
										GetAttrs(hCryptMsg, cvs.dwSignerIndex);
										break;
									}

									pb = (PBYTE)alloca(cb);
								}

								break;
							}

						} while (cvs.dwSignerIndex);
					}
				}
			}
		}

		CryptMsgClose(hCryptMsg);
	}

	return hr;
}

void DumpCMC(BSTR request)
{
	VerifyCMC(ToData(request), szOID_ENROLLMENT_AGENT);
	PCRYPT_CONTENT_INFO_SEQUENCE_OF_ANY p;

	if (0 <= Decode(PKCS_CONTENT_INFO_SEQUENCE_OF_ANY, request, &p))
	{
		DbgPrint("OID=%S\r\n", p->pszObjId);

		if (!strcmp(p->pszObjId, szOID_PKCS_7_SIGNED))// == szOID_RSA_signedData
		{
			Dump_PKCS_7(p);
		}

		LocalFree(p);
	}
}