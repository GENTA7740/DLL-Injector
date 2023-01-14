#include <iostream>
#include <string>
#include <Windows.h>
#include <TlHelp32.h>
#include <chrono>
#include <Lmcons.h>

inline int64_t GetCurrentTimeInternal() {
    auto duration = std::chrono::system_clock::now().time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
}
char* FormatString(const char* fmt, ...)
{
    char buf[8192];
    va_list arg;
    va_start(arg, fmt);
    vsnprintf(buf, sizeof(buf) - 1, fmt, arg);
    va_end(arg);
    return buf;
}
DWORD GetProcessID(const char* procName)
{
    DWORD procId = 0;
    HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (Snapshot != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 procEntry{ 0 };
        procEntry.dwSize = sizeof(procEntry);

        if (Process32First(Snapshot, &procEntry))
        {
            do
            {
                if (!_stricmp(procEntry.szExeFile, procName))
                {
                    procId = procEntry.th32ProcessID;
                    break;
                }
            } while (Process32Next(Snapshot, &procEntry));
        }
    }
    CloseHandle(Snapshot);
    return procId;
}

std::string GetWinUser()
{
    char username[UNLEN + 1];
    DWORD username_len = UNLEN + 1;
    GetUserName(username, &username_len);
    return std::string(username);
}
int main()
{
    std::string dllPath = "C:\\Users\\" + GetWinUser() + "\\Desktop\\DLL.dll";
    std::string gamePath = "C:\\Users\\" + GetWinUser() + "\\AppData\\Local\\Growtopia\\Growtopia.exe";
    const char* procName = "Growtopia.exe";
    
    DWORD procId = 0;
    int64_t last_time{ 0 };

    /* Start the game */
    if (system(FormatString("start %s", gamePath.c_str())) > 0)
        printf("Open Growtopia.exe manually!\n");
    
    while (!procId)
    {
        procId = GetProcessID(procName);
        if (last_time < GetCurrentTimeInternal()) // Anti spam console...
        {
            last_time = GetCurrentTimeInternal() + static_cast<int64_t>(5 * CLOCKS_PER_SEC); // 5 Second cooldown.
            printf("Waiting %s opened...\n", procName);
        }
        Sleep(30);
    }
    printf("%s opened!\n", procName);
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, 0, procId);

    if (hProc && hProc != INVALID_HANDLE_VALUE)
    {
        void* loc = VirtualAllocEx(hProc, 0, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (loc) WriteProcessMemory(hProc, loc, dllPath.c_str(), strlen(dllPath.c_str()) + 1, 0), printf("Injecting DLL...\n");
        else printf("Failed allocating!\n");
        
        HANDLE hThread = CreateRemoteThread(hProc, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, loc, 0, 0);

        if (hThread)
        {
            printf("DLL Injected!\n");
            CloseHandle(hThread);
        } else printf("Injecting DLL Failed!\n");
    }

    if (hProc)
    {
        CloseHandle(hProc);
    } 
    return EXIT_SUCCESS;
}