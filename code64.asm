
; long __cdecl AfterNCryptImportKey(long)
extern ?AfterNCryptImportKey@@YAJJ@Z : PROC

.code

; void __cdecl aAfterNCryptImportKey(void)
?aAfterNCryptImportKey@@YAXXZ proc
	mov ecx,eax
	call ?AfterNCryptImportKey@@YAJJ@Z
	int 3
?aAfterNCryptImportKey@@YAXXZ endp


end