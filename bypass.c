#ifndef CXX_PROTECTPROCESSX64_H
#define CXX_PROTECTPROCESSX64_H

#include <ntifs.h>

#define PROCESS_TERMINATE         0x0001  
#define PROCESS_VM_OPERATION      0x0008  
#define PROCESS_VM_READ           0x0010  
#define PROCESS_VM_WRITE          0x0020  

NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObj, IN PUNICODE_STRING pRegistryString);

VOID DriverUnload(IN PDRIVER_OBJECT pDriverObj);

typedef struct _LDR_DATA_TABLE_ENTRY64
{
	LIST_ENTRY64    InLoadOrderLinks;
	LIST_ENTRY64    InMemoryOrderLinks;
	LIST_ENTRY64    InInitializationOrderLinks;
	PVOID            DllBase;
	PVOID            EntryPoint;
	ULONG            SizeOfImage;
	UNICODE_STRING    FullDllName;
	UNICODE_STRING     BaseDllName;
	ULONG            Flags;
	USHORT            LoadCount;
	USHORT            TlsIndex;
	PVOID            SectionPointer;
	ULONG            CheckSum;
	PVOID            LoadedImports;
	PVOID            EntryPointActivationContext;
	PVOID            PatchInformation;
	LIST_ENTRY64    ForwarderLinks;
	LIST_ENTRY64    ServiceTagLinks;
	LIST_ENTRY64    StaticLinks;
	PVOID            ContextInformation;
	ULONG64            OriginalBase;
	LARGE_INTEGER    LoadTime;
} LDR_DATA_TABLE_ENTRY64, * PLDR_DATA_TABLE_ENTRY64;

extern
UCHAR*
PsGetProcessImageFileName(
	__in PEPROCESS Process
);
char*
GetProcessImageNameByProcessID(ULONG ulProcessID);

NTSTATUS ProtectProcess(BOOLEAN Enable);

OB_PREOP_CALLBACK_STATUS
preCall(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInformation);

#endif    

#ifndef CXX_PROTECTPROCESSX64_H
#    include "ProtectProcessx64.h"
#endif
PVOID obHandle;
NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObj, IN PUNICODE_STRING pRegistryString)
{
	NTSTATUS status = STATUS_SUCCESS;
	PLDR_DATA_TABLE_ENTRY64 ldr;
	if (status == STATUS_SUCCESS)
		pDriverObj->DriverUnload = DriverUnload;
	ProtectProcess(TRUE);
	return STATUS_SUCCESS;
}
NTSTATUS ProtectProcess(BOOLEAN Enable)
{
	OB_CALLBACK_REGISTRATION obReg;
	OB_OPERATION_REGISTRATION opReg;
	memset(&obReg, 0, sizeof(obReg));
	obReg.Version = ObGetFilterVersion();
	obReg.OperationRegistrationCount = 1;
	obReg.RegistrationContext = NULL;
	RtlInitUnicodeString(&obReg.Altitude, L"321000");
	memset(&opReg, 0, sizeof(opReg)); 
	opReg.ObjectType = PsProcessType;
	opReg.Operations = OB_OPERATION_HANDLE_CREATE;
	opReg.PreOperation = (POB_PRE_OPERATION_CALLBACK)& preCall;
	obReg.OperationRegistration = &opReg;
	return ObRegisterCallbacks(&obReg, &obHandle);
}
OB_PREOP_CALLBACK_STATUS preCall(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInformation)
{
	HANDLE pid = PsGetProcessId((PEPROCESS)pOperationInformation->Object);
	char szProcName[260] = { 0 };
	UNREFERENCED_PARAMETER(RegistrationContext);
	if(pOperationInformation->ObjectType == PsProcessType)
	{
		strcpy(szProcName, GetProcessImageNameByProcessID((ULONG)pid));
		if (!_stricmp(szProcName, "xxx.exe"))
		{
			pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess |= PROCESS_VM_WRITE;
		}
	}

	return OB_PREOP_SUCCESS;
}
char* GetProcessImageNameByProcessID(ULONG ulProcessID)
{
	NTSTATUS  Status;
	PEPROCESS  EProcess = NULL;
	Status = PsLookupProcessByProcessId((HANDLE)ulProcessID, &EProcess); 
	if (!NT_SUCCESS(Status))
	{
		return FALSE;
	}
	ObDereferenceObject(EProcess);
	return (char*)PsGetProcessImageFileName(EProcess);
}
VOID DriverUnload(IN PDRIVER_OBJECT pDriverObj)
{
	UNREFERENCED_PARAMETER(pDriverObj);
	ObUnRegisterCallbacks(obHandle);
}