#include "pch.h"
#include "Hooks.h"
#include "Options.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        ManualMapping ? Authy::Hooks::Init() : (void)CreateThread(0, 0, (LPTHREAD_START_ROUTINE)Authy::Hooks::Init, 0, 0, 0);
        break;
    }
    return TRUE;
}

