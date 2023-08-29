#pragma once

extern volatile const UCHAR guz;

template <typename T>
T HR(HRESULT& hr, T t)
{
	hr = t ? NOERROR : GetLastError();
	return t;
}

EXTERN_C
NTSYSAPI
NTSTATUS
NTAPI
RtlSetProtectedPolicy(
	_In_ const GUID* PolicyGuid,
	_In_ ULONG_PTR PolicyValue,
	_Out_ PULONG_PTR OldPolicyValue
);