
; long __cdecl NT::AfterNCryptImportKey(long)
extern ?AfterNCryptImportKey@NT@@YAJJ@Z : PROC

.code

; void __cdecl NT::aAfterNCryptImportKey(void)
?aAfterNCryptImportKey@NT@@YAXXZ proc
	mov ecx,eax
	call ?AfterNCryptImportKey@NT@@YAJJ@Z
	int 3
?aAfterNCryptImportKey@NT@@YAXXZ endp

end