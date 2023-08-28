when we use SSL connection to LDAP, inside 
```
DecryptReturnValues
LDAP_REQUEST::Authenticate( // Handle authentication exchange.
    CtxtHandle *        phSslSecurityContext,
    SslSecurityState *  pSslState
    )
  
exist next code, after AcceptSecurityContext(Schannel) return SEC_E_OK

        if ( scRet != SEC_I_CONTINUE_NEEDED ) {

            if ( !m_LdapConnection->GetSslContextAttributes( ) ) {
                return DecryptFailed;
            }
            if (IsSSL()) {
                if (!m_LdapConnection->GetSslClientCertToken( )) {
                    m_LdapConnection->InstallNewSecurityContext();
                    m_LdapConnection->SetUsingSSLCreds();
                }
            }
            *pSslState = Sslbound;
        } else {

            *pSslState = Sslpartialbind;
        }

```
in callstack
```
kerberos.dll!LsaApLogonUserEx2
lsasrv.dll!LsapCallAuthPackageForLogon + 117
lsasrv.dll!LsapAuApiDispatchLogonUser + 36b
lsasrv.dll!SspiExLogonUser + 361
sspisrv.dll!SspirLogonUser + 203
sspicli.dll!SspipLogonUser + 24a
sspicli.dll!LsaLogonUser + 83
// Creates a user token via the Kerberos S4U2Self mechanism.
schannel.dll!long SslTryS4U2Self(_CERT_CHAIN_CONTEXT const *,void * *,unsigned long,unsigned short const *,unsigned short const *) + 318
// Attempt to logon via Kerberos S4U2Self.
schannel.dll!unsigned long SslLocalMapCredential(CCredentialGroup *,void *,unsigned long,void *,unsigned long,void const *,void const *,unsigned short const *,unsigned short const *,unsigned __int64 *) + 10f
schannel.dll!long SslMapCredential(CCredentialGroup *,void *,unsigned long,void *,unsigned long,_CERT_CONTEXT const *,_CERT_CONTEXT const *,unsigned short const *,unsigned short const *,unsigned __int64 *) + 56
schannel.dll!unsigned long DoCertificateMapping(CSsl3TlsServerContext *) + 21a
schannel.dll!unsigned long CSsl3TlsServerContext::ProcessHandshake(unsigned char *,unsigned long,int *)
schannel.dll!virtual unsigned long CSsl3TlsContext::ProcessRecord(eTlsRecordType,unsigned char *,unsigned long) + 101
schannel.dll!virtual unsigned long CSsl3TlsServerContext::ProcessRecord(eTlsRecordType,unsigned char *,unsigned long) + 3c
schannel.dll!unsigned long CSsl3TlsContext::TlsProtocolHandlerWorker(SPBuffer *,SPBuffer *) + 257
schannel.dll!virtual unsigned long CSsl3TlsContext::SslProtocolHandler(SPBuffer *,SPBuffer *) + 41
schannel.dll!SpAcceptLsaModeContext + 290
lsasrv.dll!WLsaAcceptContext + 2aa
lsasrv.dll!LsaDbExtIsDsRunning + 61
sspisrv.dll!SspirProcessSecurityContext + 1ef
sspicli.dll!SeciFreeCallContext + 12e
sspicli.dll!long LsaAcceptSecurityContext(_SecHandle *,_SecHandle *,_SecBufferDesc *,unsigned long,unsigned long,_SecHandle *,_SecBufferDesc *,unsigned long *,_LARGE_INTEGER *) + 1e5
sspicli.dll!AcceptSecurityContext + 137
ntdsai.dll!DecryptReturnValues LDAP_REQUEST::Authenticate(_SecHandle *,SslSecurityState *) + 14b
ntdsai.dll!DecryptReturnValues LDAP_REQUEST::DecryptSSL(void) + 68
ntdsai.dll!void `static detail::intrinsic_charsets<unsigned short>::_get_word_charset::intrinsic_charset & regex::detail::intrinsic_charsets<unsigned short>::_get_word_charset(void)'::`2'::`dynamic atexit destructor for 's_word_charset''(void) + 14504
ntdsai.dll!void LDAP_CONN::IoCompletion(void *,unsigned char *,unsigned long,unsigned long,_OVERLAPPED *,unsigned long) + d5
ntdsai.dll!void LdapCompletionRoutine(void *,unsigned long,unsigned long,_OVERLAPPED *) + 13a
ntdsatq.dll!void AtqpProcessContext(ATQ_CONTEXT *,unsigned long,_OVERLAPPED *,int) + c1
ntdsatq.dll!void AtqpProcessContext(ATQ_CONTEXT *,unsigned long,_OVERLAPPED *,int) + 194
kernel32.dll!BaseThreadInitThunk + 22
ntdll.dll!RtlUserThreadStart + 34

ntdll.dll!ZwCreateTokenEx
lsasrv.dll!LsapCreateTokenObject + 45c
lsasrv.dll!LsapBuildAndCreateToken + 120
lsasrv.dll!LsapAuApiDispatchLogonUser + 558
lsasrv.dll!SspiExLogonUser + 361
sspisrv.dll!SspirLogonUser + 203
sspicli.dll!SspipLogonUser + 24a
sspicli.dll!LsaLogonUser + 83
schannel.dll!long SslTryS4U2Self(_CERT_CHAIN_CONTEXT const *,void * *,unsigned long,unsigned short const *,unsigned short const *) + 318
schannel.dll!unsigned long SslLocalMapCredential(CCredentialGroup *,void *,unsigned long,void *,unsigned long,void const *,void const *,unsigned short const *,unsigned short const *,unsigned __int64 *) + 10f
schannel.dll!long SslMapCredential(CCredentialGroup *,void *,unsigned long,void *,unsigned long,_CERT_CONTEXT const *,_CERT_CONTEXT const *,unsigned short const *,unsigned short const *,unsigned __int64 *) + 56
schannel.dll!unsigned long DoCertificateMapping(CSsl3TlsServerContext *) + 21a
schannel.dll!unsigned long CSsl3TlsServerContext::ProcessHandshake(unsigned char *,unsigned long,int *)
schannel.dll!virtual unsigned long CSsl3TlsContext::ProcessRecord(eTlsRecordType,unsigned char *,unsigned long) + 101
schannel.dll!virtual unsigned long CSsl3TlsServerContext::ProcessRecord(eTlsRecordType,unsigned char *,unsigned long) + 3c
schannel.dll!unsigned long CSsl3TlsContext::TlsProtocolHandlerWorker(SPBuffer *,SPBuffer *) + 257
schannel.dll!virtual unsigned long CSsl3TlsContext::SslProtocolHandler(SPBuffer *,SPBuffer *) + 41
schannel.dll!SpAcceptLsaModeContext + 290
lsasrv.dll!WLsaAcceptContext + 2aa
lsasrv.dll!LsaDbExtIsDsRunning + 61
sspisrv.dll!SspirProcessSecurityContext + 1ef
sspicli.dll!SeciFreeCallContext + 12e
sspicli.dll!long LsaAcceptSecurityContext(_SecHandle *,_SecHandle *,_SecBufferDesc *,unsigned long,unsigned long,_SecHandle *,_SecBufferDesc *,unsigned long *,_LARGE_INTEGER *) + 1e5
sspicli.dll!AcceptSecurityContext + 137
ntdsai.dll!DecryptReturnValues LDAP_REQUEST::Authenticate(_SecHandle *,SslSecurityState *) + 14b
ntdsai.dll!DecryptReturnValues LDAP_REQUEST::DecryptSSL(void) + 68
ntdsai.dll!void LDAP_CONN::ProcessRequestEx(LDAP_REQUEST *,int *,unsigned long)
ntdsai.dll!void LDAP_CONN::IoCompletion(void *,unsigned char *,unsigned long,unsigned long,_OVERLAPPED *,unsigned long) + d5
ntdsai.dll!void LdapCompletionRoutine(void *,unsigned long,unsigned long,_OVERLAPPED *) + 13a
ntdsatq.dll!void AtqpProcessContext(ATQ_CONTEXT *,unsigned long,_OVERLAPPED *,int) + c1
ntdsatq.dll!void AtqpProcessContext(ATQ_CONTEXT *,unsigned long,_OVERLAPPED *,int) + 194
kernel32.dll!BaseThreadInitThunk + 22
ntdll.dll!RtlUserThreadStart + 34

sspicli.dll!QuerySecurityContextToken
ntdsai.dll!int LDAP_SECURITY_CONTEXT::IsSSLMappedUser(void) + 46
ntdsai.dll!long LDAP_CONN::GetSslClientCertToken(char *) + 7b
ntdsai.dll!DecryptReturnValues LDAP_REQUEST::Authenticate(_SecHandle *,SslSecurityState *) + 1ff
ntdsai.dll!DecryptReturnValues LDAP_REQUEST::DecryptSSL(void) + 68
ntdsai.dll!void LDAP_CONN::ProcessRequestEx(LDAP_REQUEST *,int *,unsigned long)
ntdsai.dll!void LDAP_CONN::IoCompletion(void *,unsigned char *,unsigned long,unsigned long,_OVERLAPPED *,unsigned long) + d5
ntdsai.dll!void LdapCompletionRoutine(void *,unsigned long,unsigned long,_OVERLAPPED *) + 13a
ntdsatq.dll!void AtqpProcessContext(ATQ_CONTEXT *,unsigned long,_OVERLAPPED *,int) + c1
ntdsatq.dll!void AtqpProcessContext(ATQ_CONTEXT *,unsigned long,_OVERLAPPED *,int) + 194
kernel32.dll!BaseThreadInitThunk + 22
ntdll.dll!RtlUserThreadStart + 34

authz.dll!AuthzInitializeContextFromToken
ntdsai.dll!void * LDAP_SECURITY_CONTEXT::`scalar deleting destructor'(unsigned int) + 142
ntdsai.dll!GetAuthzContextHandle + 1e
ntdsai.dll!void LDAP_SECURITY_CONTEXT::SetClientType(void) + b9
ntdsai.dll!long LDAP_CONN::GetSslClientCertToken(char *) + 8e
ntdsai.dll!DecryptReturnValues LDAP_REQUEST::Authenticate(_SecHandle *,SslSecurityState *) + 1ff
ntdsai.dll!DecryptReturnValues LDAP_REQUEST::DecryptSSL(void) + 68
ntdsai.dll!void LDAP_CONN::ProcessRequestEx(LDAP_REQUEST *,int *,unsigned long)
ntdsai.dll!void LDAP_CONN::IoCompletion(void *,unsigned char *,unsigned long,unsigned long,_OVERLAPPED *,unsigned long) + d5
ntdsai.dll!void LdapCompletionRoutine(void *,unsigned long,unsigned long,_OVERLAPPED *) + 13a
ntdsatq.dll!void AtqpProcessContext(ATQ_CONTEXT *,unsigned long,_OVERLAPPED *,int) + c1
ntdsatq.dll!void AtqpProcessContext(ATQ_CONTEXT *,unsigned long,_OVERLAPPED *,int) + 194
kernel32.dll!BaseThreadInitThunk + 22
ntdll.dll!RtlUserThreadStart + 34
```
logon via Kerberos S4U2Self mechanism.

but than inside LDAP_CONN::BindRequest

```
ntdll.dll!ZwCreateTokenEx
lsasrv.dll!LsapCreateTokenObject + 45c
lsasrv.dll!LsapCreateTokenEx + 14c
kerberos.dll!long KerbCreateTokenFromTicketEx(int,int,_LUID *,KERB_AP_REQUEST *,KERB_ENCRYPTED_TICKET *,KERB_AUTHENTICATOR *,unsigned long,KERB_ENCRYPTION_KEY *,_UNICODE_STRING *,KERB_ENCRYPTION_KEY *,_LUID *,void * *,void * *,_UNICODE_STRING *,_UNICODE_STRING *,_UNICODE_STRING *,_S4U_DELEGATION_INFO * *,_LARGE_INTEGER *)
kerberos.dll!SpAcceptLsaModeContext
lsasrv.dll!WLsaAcceptContext + 2aa
lsasrv.dll!long NegpDetermineTokenPackage(unsigned __int64,_SecBuffer *,unsigned long *) + 1c6
lsasrv.dll!long NegAcceptLsaModeContext(unsigned __int64,unsigned __int64,_SecBufferDesc *,unsigned long,unsigned long,unsigned __int64 *,_SecBufferDesc *,unsigned long *,_LARGE_INTEGER *,unsigned char *,_SecBuffer *) + 226
lsasrv.dll!LsaDbExtIsDsRunning + 61
sspisrv.dll!SspirProcessSecurityContext + 1ef
sspicli.dll!SeciFreeCallContext + 12e
sspicli.dll!long LsaAcceptSecurityContext(_SecHandle *,_SecHandle *,_SecBufferDesc *,unsigned long,unsigned long,_SecHandle *,_SecBufferDesc *,unsigned long *,_LARGE_INTEGER *) + 1e5
sspicli.dll!AcceptSecurityContext + 137
sspicli.dll!SaslAcceptSecurityContext + 123
ntdsai.dll!long LDAP_SECURITY_CONTEXT::AcceptContext(_SecHandle *,_SecBufferDesc *,unsigned long,unsigned long,sockaddr *,unsigned long,_SecBufferDesc *,unsigned long *,_LARGE_INTEGER *,_LARGE_INTEGER *,unsigned long *)
ntdsai.dll!_enum1 LDAP_CONN::BindRequest(_THSTATE *,LDAP_REQUEST *,LDAPMsg *,AuthenticationChoice *,LDAPString *,LDAPString *)
ntdsai.dll!void LDAP_CONN::ProcessRequestEx(LDAP_REQUEST *,int *,unsigned long)
ntdsai.dll!void LDAP_CONN::IoCompletion(void *,unsigned char *,unsigned long,unsigned long,_OVERLAPPED *,unsigned long) + d5
ntdsai.dll!void LdapCompletionRoutine(void *,unsigned long,unsigned long,_OVERLAPPED *) + 13a
ntdsatq.dll!void AtqpProcessContext(ATQ_CONTEXT *,unsigned long,_OVERLAPPED *,int) + c1
ntdsatq.dll!void AtqpProcessContext(ATQ_CONTEXT *,unsigned long,_OVERLAPPED *,int) + 194
kernel32.dll!BaseThreadInitThunk + 22
ntdll.dll!RtlUserThreadStart + 34


authz.dll!AuthzInitializeContextFromToken
ntdsai.dll!GetAuthzContextInfo
ntdsai.dll!GetAuthzContextHandle + 1e
ntdsai.dll!void LDAP_SECURITY_CONTEXT::SetClientType(void) + b9
ntdsai.dll!long LDAP_SECURITY_CONTEXT::AcceptContext(_SecHandle *,_SecBufferDesc *,unsigned long,unsigned long,sockaddr *,unsigned long,_SecBufferDesc *,unsigned long *,_LARGE_INTEGER *,_LARGE_INTEGER *,unsigned long *)
ntdsai.dll!_enum1 LDAP_CONN::BindRequest(_THSTATE *,LDAP_REQUEST *,LDAPMsg *,AuthenticationChoice *,LDAPString *,LDAPString *)
ntdsai.dll!void LDAP_CONN::ProcessRequestEx(LDAP_REQUEST *,int *,unsigned long)
ntdsai.dll!void LDAP_CONN::IoCompletion(void *,unsigned char *,unsigned long,unsigned long,_OVERLAPPED *,unsigned long) + d5
ntdsai.dll!void LdapCompletionRoutine(void *,unsigned long,unsigned long,_OVERLAPPED *) + 13a
ntdsatq.dll!void AtqpProcessContext(ATQ_CONTEXT *,unsigned long,_OVERLAPPED *,int) + c1
ntdsatq.dll!void AtqpProcessContext(ATQ_CONTEXT *,unsigned long,_OVERLAPPED *,int) + 194
kernel32.dll!BaseThreadInitThunk + 22
ntdll.dll!RtlUserThreadStart + 34


ntdsai.dll!void LDAP_SECURITY_CONTEXT::GetUserNameA(unsigned short * *)
ntdsai.dll!_enum1 LDAP_CONN::SetSecurityContextAtts(LDAP_SECURITY_CONTEXT *,unsigned long,unsigned long,int,LDAPString *) + 35
ntdsai.dll!_enum1 LDAP_CONN::BindRequest(_THSTATE *,LDAP_REQUEST *,LDAPMsg *,AuthenticationChoice *,LDAPString *,LDAPString *)
ntdsai.dll!void LDAP_CONN::ProcessRequestEx(LDAP_REQUEST *,int *,unsigned long)
ntdsai.dll!void LDAP_CONN::IoCompletion(void *,unsigned char *,unsigned long,unsigned long,_OVERLAPPED *,unsigned long) + d5
ntdsai.dll!void LdapCompletionRoutine(void *,unsigned long,unsigned long,_OVERLAPPED *) + 13a
ntdsatq.dll!void AtqpProcessContext(ATQ_CONTEXT *,unsigned long,_OVERLAPPED *,int) + c1
ntdsatq.dll!void AtqpProcessContext(ATQ_CONTEXT *,unsigned long,_OVERLAPPED *,int) + 194
kernel32.dll!BaseThreadInitThunk + 22
ntdll.dll!RtlUserThreadStart + 34


                //
                // Install the new security context that has been built up,
                // as the current active security context.
                //
                InstallNewSecurityContext();

                if (m_pSecurityContext) {
                    code = SetSecurityContextAtts(m_pSecurityContext,
                                                  fContextAttributes,
                                                  dwSecContextFlags,
                                                  pErrorMessage);
```
InstallNewSecurityContext();supersede previous security context from SSL


during search request next stack
```
authz.dll!AuthzAccessCheck
ntdsai.dll!CheckPermissionsAnyClient + 263
ntdsai.dll!FindFirstSearchObject + 3d95
ntdsai.dll!dbMoveToNextSearchCandidate + 48a
ntdsai.dll!dbGetDefaultIndexInfo + 1d5
ntdsai.dll!DirSearchNative + 2a9
ntdsai.dll!DirSearchNative + cc
ntdsai.dll!_enum1 LDAP_CONN::SearchRequest(_THSTATE *,int,int *,LDAP_REQUEST *,unsigned long,LDAPMsg *,Referral_ * *,Controls_ * *,LDAPString *,LDAPString *,unsigned long *,berval * *) + 4c8
ntdsai.dll!void LDAP_REQUEST::ResetSend(void) + 4ed
ntdsai.dll!void LDAP_CONN::IoCompletion(void *,unsigned char *,unsigned long,unsigned long,_OVERLAPPED *,unsigned long) + d5
ntdsai.dll!void LdapCompletionRoutine(void *,unsigned long,unsigned long,_OVERLAPPED *) + 13a
ntdsatq.dll!void AtqpProcessContext(ATQ_CONTEXT *,unsigned long,_OVERLAPPED *,int) + c1
ntdsatq.dll!void AtqpProcessContext(ATQ_CONTEXT *,unsigned long,_OVERLAPPED *,int) + 194
kernel32.dll!BaseThreadInitThunk + 22
ntdll.dll!RtlUserThreadStart + 34
```
the AuthzAccessCheck check client access

AuthzClientContext ( A handle to a structure that represents the client ) init/set in LDAP_SECURITY_CONTEXT::SetClientType

typical call flow with SSL
```
++LDAP_SECURITY_CONTEXT<0000002467876270>(0, 0)
QuerySecurityContextToken<0000002467876270><0000002467875BB0>(0000002466F2ED80)
LDAP_SECURITY_CONTEXT<0000002467876270>::IsSSLMappedUser "AAA\Kelly"
LDAP_SECURITY_CONTEXT<0000002467876270>::SetClientType
authz ctx<00000024683D5620> 0000000000000000 <- 0000002467C1FE30
++LDAP_SECURITY_CONTEXT<0000002467876150>(1, 0)
LDAP_SECURITY_CONTEXT<0000002467876150>::AcceptContext(0)
LDAP_SECURITY_CONTEXT<0000002467876150>::AcceptContext(1)
LDAP_SECURITY_CONTEXT<0000002467876150>::AcceptContext(1)
LDAP_SECURITY_CONTEXT<0000002467876150>::SetClientType
authz ctx<00000024683D5460> 0000000000000000 <- 0000002467C1FE70
LDAP_SECURITY_CONTEXT<0000002467876150>::GetUserName => "AAA\Moc"
--LDAP_SECURITY_CONTEXT<0000002467876270>
AuthzAccessCheck(0000002467C1FE70)
AuthzAccessCheck(0000002467C1FE70)
AuthzAccessCheck(0000002467C1FE70)
AuthzAccessCheck(0000002467C1FE70)
--LDAP_SECURITY_CONTEXT<0000002467876150>
```
(i use SSL certificate for "AAA\Kelly" user and bind as "AAA\Moc" user)

visible that security check was via "AAA\Moc" user

in case no SSL
```
++LDAP_SECURITY_CONTEXT<0000002421BCE160>(1, 0)
LDAP_SECURITY_CONTEXT<0000002421BCE160>::AcceptContext(0)
LDAP_SECURITY_CONTEXT<0000002421BCE160>::AcceptContext(1)
LDAP_SECURITY_CONTEXT<0000002421BCE160>::AcceptContext(1)
LDAP_SECURITY_CONTEXT<0000002421BCE160>::SetClientType
authz ctx<00000024683D5E60> 0000000000000000 <- 0000002467BE07F0
LDAP_SECURITY_CONTEXT<0000002421BCE160>::GetUserName => AAA\Moc
AuthzAccessCheck(0000002467BE07F0)
AuthzAccessCheck(0000002467BE07F0)
AuthzAccessCheck(0000002467BE07F0)
AuthzAccessCheck(0000002467BE07F0)
--LDAP_SECURITY_CONTEXT<0000002421BCE160>
```
so unclear what SSL give/sense (we can also use LDAP_OPT_ENCRYPT - Enables/disables Kerberos encryption prior to binding using the LDAP_AUTH_NEGOTIATE flag. Cannot be used over an SSL connection )

also use SSL lead to token handle and logon session became zombie . every new request add new handle/session.
the schannel close this handles only when FreeCredentialsHandle is called, but ldap server call this only on shutdown..
```
ntdll.dll!NtClose // close "zombie" token and as result logon session, which he hold, destroyed too
schannel.dll!virtual void * CSessionCacheServerItem::`vector deleting destructor'(unsigned int)
schannel.dll!unsigned char CSessionCacheManager::CacheExpireElements(unsigned char,unsigned char)
schannel.dll!void CSessionCacheManager::PurgeCacheForCredentialGroup(CCredentialGroup *) + a4
schannel.dll!SpFreeCredentialsHandle + 4f
lsasrv.dll!void LsapCredentialRundown(_SecHandle *,void *,unsigned long) + 19c
lsasrv.dll!SspiExFreeCredentialsHandle + 222
lsasrv.dll!SspiExFreeCredentialsHandle + f4
sspisrv.dll!SspirFreeCredentialsHandle + 97
rpcrt4.dll!Invoke + 73
rpcrt4.dll!Ndr64pServerUnMarshal + 1261
rpcrt4.dll!NdrServerCallAll + 3c
rpcrt4.dll!DispatchToStubInCNoAvrf + 37
rpcrt4.dll!long RPC_INTERFACE::DispatchToStubWorker(_RPC_MESSAGE *,unsigned int,int,long *) + 190
rpcrt4.dll!void LRPC_SASSOCIATION::HandleRequest(_PORT_MESSAGE *,_PORT_MESSAGE *,void *,unsigned __int64,int,RPCP_ALPC_TOKEN_ATTR *,RPCP_ALPC_HANDLE_ATTR *) + 6ff
rpcrt4.dll!void LRPC_SASSOCIATION::HandleRequest(_PORT_MESSAGE *,_PORT_MESSAGE *,void *,unsigned __int64,int,RPCP_ALPC_TOKEN_ATTR *,RPCP_ALPC_HANDLE_ATTR *) + 3e6
rpcrt4.dll!void LRPC_SASSOCIATION::HandleRequest(_PORT_MESSAGE *,_PORT_MESSAGE *,void *,unsigned __int64,int,RPCP_ALPC_TOKEN_ATTR *,RPCP_ALPC_HANDLE_ATTR *) + 238
rpcrt4.dll!void LrpcIoComplete(_TP_CALLBACK_INSTANCE *,void *,_TP_ALPC *,void *) + 2bd
rpcrt4.dll!void LrpcIoComplete(_TP_CALLBACK_INSTANCE *,void *,_TP_ALPC *,void *) + be
ntdll.dll!TppAlpcpExecuteCallback + 210
ntdll.dll!TppWorkerThread + 888
kernel32.dll!BaseThreadInitThunk + 22
ntdll.dll!RtlUserThreadStart + 34


ntdll.dll!ZwAlpcSendWaitReceivePort + a
rpcrt4.dll!virtual long LRPC_CCALL::SendReceive(_RPC_MESSAGE *) + 169
rpcrt4.dll!NdrClientCall3 + e7d
rpcrt4.dll!NdrClientCall3 + fe
sspicli.dll!SspipFreeCredentialsHandle + f9
sspicli.dll!long LsaFreeCredentialsHandle(_SecHandle *) + 21
sspicli.dll!FreeCredentialsHandle + 64
```
