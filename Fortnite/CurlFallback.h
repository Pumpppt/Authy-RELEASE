#pragma once
#include "pch.h"
#include "Options.h"
#include <cstdio>
#include <cstring>
#include <initializer_list>
#include <intrin.h>

// ANSI re-use
#ifndef CLR_RESET
#define CLR_RESET   "\033[0m"
#define CLR_GRAY    "\033[90m"
#define CLR_GREEN   "\033[92m"
#define CLR_WHITE   "\033[97m"
#define CLR_YELLOW  "\033[93m"
#define CLR_MAGENTA "\033[95m"
#endif

// curl_easy_setopt prologue: first 14 bytes — stable across UE5 Fortnite builds.
// Shadow-store spills: MOV [rsp+10h],edx | MOV [rsp+18h],r8 | MOV [rsp+20h],r9
// Used as the identity check for call-site scanning (CurlFallback) and
// prologue scanning (AuthyFinder). The call-site approach (E8 rel32 -> this
// prologue) is inherently trustworthy so 14 bytes is sufficient there.
static const uint8_t g_CurlPrologue[14] = {
    0x89,0x54,0x24,0x10, 0x4C,0x89,0x44,0x24,0x18, 0x4C,0x89,0x4C,0x24,0x20
};

namespace Authy {
namespace CurlFallback {

static constexpr unsigned __int64 CURLOPT_URL_VAL = 10002;
static char g_backend[512] = { 0 };

// Hook records — used by Uninstall() to restore original bytes
struct HookRecord { uintptr_t target; uint8_t* mem; };
static HookRecord g_hookRecords[64] = {};
static int        g_hookCount = 0;

// URL redirect logic
static bool HostShouldRedirect(const char* host, size_t hostLen)
{
    static const char* domains[] = {
        "ol.epicgames.com","ol.epicgames.net","on.epicgames.com",
        "game-social.epicgames.com","ak.epicgames.com",
        "epicgames.dev","superawesome.com"
    };
    for (const char* d : domains) {
        size_t dl = strlen(d);
        if (hostLen >= dl && _strnicmp(host+hostLen-dl, d, dl)==0) return true;
    }
    return false;
}

static void* __cdecl RedirectSetopt(void* handle, unsigned __int64 option, void* value)
{
    __try {
        if (option!=CURLOPT_URL_VAL||!value) return value;
        const char* url=(const char*)value;
        const char* sep=strstr(url,"://"); if(!sep) return value;
        const char* hostStart=sep+3, *p=hostStart;
        while(*p&&*p!='/'&&*p!=':'&&*p!='?') p++;
        size_t hostLen=(size_t)(p-hostStart);
        if(!HostShouldRedirect(hostStart,hostLen)) return value;
        const char* pathStart=p;
        if(*pathStart==':') while(*pathStart&&*pathStart!='/'&&*pathStart!='?') pathStart++;
        static thread_local char tlbuf[2048];
        size_t blen=strlen(g_backend), plen=strlen(pathStart);
        if(blen+plen+1>sizeof(tlbuf)) return value;
        memcpy(tlbuf,g_backend,blen); memcpy(tlbuf+blen,pathStart,plen+1);
        if(Console) {
            printf(CLR_MAGENTA " [LogsLive] " CLR_WHITE "Intercepted: " CLR_YELLOW "%s" CLR_RESET "\n", url);
            printf(CLR_GRAY "             -> " CLR_GREEN "%s" CLR_RESET "\n", tlbuf);
        }
        return tlbuf;
    } __except(EXCEPTION_EXECUTE_HANDLER){ return value; }
}

// Install 14-byte JMP trampoline at target (Tellurium pattern)
inline bool InstallHookAtTarget(uintptr_t target, const char* tag)
{
    if (!target) return false;
    // Verify the 14-byte curl_easy_setopt shadow-spill prologue.
    // When called from the call-site scanner (E8 rel32 -> target) the call
    // instruction itself proves this is curl_easy_setopt, so 14 bytes is
    // a sufficient and accurate identity check.
    __try { if (memcmp((void*)target, g_CurlPrologue, sizeof(g_CurlPrologue)) != 0) return false; }
    __except(EXCEPTION_EXECUTE_HANDLER) { return false; }

    uint8_t* mem = (uint8_t*)VirtualAlloc(nullptr,0x100,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);
    if (!mem) return false;

    uint8_t* tramp = mem;
    uint8_t* stub  = mem + 0x40;

    // Trampoline: stolen bytes + JMP [rip+0] -> target+14
    memcpy(tramp,(void*)target,14);
    tramp[14]=0xFF; tramp[15]=0x25; *(uint32_t*)(tramp+16)=0;
    *(uint64_t*)(tramp+20)=(uint64_t)(target+14);

    // Stub: save volatile regs, call RedirectSetopt, restore, jmp tramp
    auto E=[](uint8_t*&p,std::initializer_list<uint8_t> b){ for(uint8_t v:b)*p++=v; };
    uint8_t* p=stub;
    E(p,{0x50}); E(p,{0x51}); E(p,{0x52});
    E(p,{0x41,0x50}); E(p,{0x41,0x51}); E(p,{0x41,0x52}); E(p,{0x41,0x53});
    E(p,{0x48,0x83,0xEC,0x20});
    E(p,{0x48,0xB8}); *(uint64_t*)p=(uint64_t)&RedirectSetopt; p+=8;
    E(p,{0xFF,0xD0});
    E(p,{0x48,0x89,0x44,0x24,0x38});
    E(p,{0x48,0x83,0xC4,0x20});
    E(p,{0x41,0x5B}); E(p,{0x41,0x5A}); E(p,{0x41,0x59}); E(p,{0x41,0x58});
    E(p,{0x5A}); E(p,{0x59}); E(p,{0x58});
    E(p,{0xFF,0x25}); *(uint32_t*)p=0; p+=4;
    *(uint64_t*)p=(uint64_t)tramp;

    DWORD old;
    VirtualProtect((void*)target,14,PAGE_EXECUTE_READWRITE,&old);
    uint8_t patch[14];
    patch[0]=0xFF; patch[1]=0x25; *(uint32_t*)(patch+2)=0;
    *(uint64_t*)(patch+6)=(uint64_t)stub;
    memcpy((void*)target,patch,14);
    VirtualProtect((void*)target,14,old,&old);
    FlushInstructionCache(GetCurrentProcess(),(void*)target,14);

    // Track for potential Uninstall()
    if (g_hookCount < 64)
        g_hookRecords[g_hookCount++] = { target, mem };

    printf(CLR_GREEN " [+] " CLR_WHITE "[CurlFallback/%s] " CLR_WHITE
           "curl_easy_setopt hooked @ 0x%llX" CLR_RESET "\n",
           tag,(unsigned long long)target);
    return true;
}

// Restore all patched curl_easy_setopt prologues to their original bytes.
// Call this when ProcessRequest VTable hook is preferred over CurlFallback.
inline void Uninstall()
{
    for (int i = 0; i < g_hookCount; i++)
    {
        uintptr_t target = g_hookRecords[i].target;
        uint8_t*  tramp  = g_hookRecords[i].mem; // first 14 bytes = original stolen bytes
        if (!target || !tramp) continue;
        DWORD old;
        VirtualProtect((void*)target, 14, PAGE_EXECUTE_READWRITE, &old);
        memcpy((void*)target, tramp, 14); // restore original prologue
        VirtualProtect((void*)target, 14, old, &old);
        FlushInstructionCache(GetCurrentProcess(), (void*)target, 14);
        VirtualFree(tramp, 0, MEM_RELEASE);
        g_hookRecords[i] = {};
    }
    g_hookCount = 0;
    printf(CLR_GRAY " [~] " CLR_WHITE "[CurlFallback] " CLR_GRAY
           "Curl hooks removed — ProcessRequest VTable hook is active" CLR_RESET "\n");
}

// Scan .text for CALL rel32 (E8) instructions whose target matches the
// curl_easy_setopt prologue. Hook each unique target once.
// This is the Tellurium approach - works even when curl is statically linked
// and has no "curl_easy_setopt" string in rdata/data.
static int ScanAndHookCallSites(uint8_t* textBase, size_t textSize, const char* tag)
{
    if (!textBase || !textSize) return 0;

    int hooked = 0, candidates = 0;

    static const int MAX_TARGETS = 64;
    uintptr_t patched[MAX_TARGETS] = {};
    int patchedCount = 0;

    uint8_t* end = textBase + textSize - 5;
    for (uint8_t* t = textBase; t < end; t++)
    {
        if (t[0] != 0xE8) continue;  // CALL rel32 only

        // Resolve call target
        uintptr_t target = (uintptr_t)(t+5) + (uintptr_t)(*(int32_t*)(t+1));
        if (!target || target==(uintptr_t)(t+5)) continue;

        // Validate prologue under SEH
        __try { if (memcmp((void*)target,g_CurlPrologue,14)!=0) continue; }
        __except(EXCEPTION_EXECUTE_HANDLER){ continue; }

        candidates++;

        // Deduplicate - only hook each target once
        bool already = false;
        for (int i=0; i<patchedCount; i++) if(patched[i]==target){already=true;break;}
        if (!already) {
            if (InstallHookAtTarget(target,tag)) {
                if(patchedCount<MAX_TARGETS) patched[patchedCount++]=target;
                hooked++;
            }
        }
    }

    printf(CLR_GRAY " [~] " CLR_WHITE "[CurlFallback/%s] " CLR_GRAY
           "Scanned .text: %d call sites, %d unique functions hooked" CLR_RESET "\n",
           tag, candidates, hooked);
    return hooked;
}

inline void SetupBackend()
{
    Authy::Options::ParseCommandLine();
    strncpy_s(g_backend, sizeof(g_backend), Authy::Options::BackendA.c_str(), _TRUNCATE);
}

static bool Install(uint64_t moduleBase, HMODULE eosBuf)
{
    SetupBackend();
    printf(CLR_GRAY " [~] " CLR_WHITE "[CurlFallback] " CLR_GRAY
           "Call-site scan fallback starting (backend: %s)" CLR_RESET "\n", g_backend);

    int total = 0;

    // Game module
    {
        auto* dos=(IMAGE_DOS_HEADER*)moduleBase;
        auto* nt=(IMAGE_NT_HEADERS*)(moduleBase+dos->e_lfanew);
        auto* sect=IMAGE_FIRST_SECTION(nt);
        uint8_t* textBase=nullptr; size_t textSize=0;
        for(int i=0;i<nt->FileHeader.NumberOfSections;i++){
            char name[9]={}; memcpy(name,sect[i].Name,8);
            if(!strcmp(name,".text")){
                textBase=(uint8_t*)(moduleBase+sect[i].VirtualAddress);
                textSize=sect[i].Misc.VirtualSize; break;
            }
        }
        if(textBase){
            printf(CLR_GRAY " [~] " CLR_WHITE "[CurlFallback/game] " CLR_GRAY
                   ".text=0x%llX size=0x%llX" CLR_RESET "\n",
                   (unsigned long long)textBase,(unsigned long long)textSize);
            // Retry up to 3x with a short wait — on some builds the call sites
            // only become reachable once the loader has finished mapping the module.
            for (int _attempt = 0; _attempt < 3 && total == 0; _attempt++) {
                if (_attempt > 0) Sleep(150);
                total += ScanAndHookCallSites(textBase,textSize,"game");
            }
        } else printf(CLR_WHITE " [x] [CurlFallback] Game .text section not found" CLR_RESET "\n");
    }

    // EOS module
    if(eosBuf){
        uint64_t eosBase=(uint64_t)eosBuf;
        auto* dos=(IMAGE_DOS_HEADER*)eosBase;
        auto* nt=(IMAGE_NT_HEADERS*)(eosBase+dos->e_lfanew);
        auto* sect=IMAGE_FIRST_SECTION(nt);
        uint8_t* textBase=nullptr; size_t textSize=0;
        for(int i=0;i<nt->FileHeader.NumberOfSections;i++){
            char name[9]={}; memcpy(name,sect[i].Name,8);
            if(!strcmp(name,".text")){
                textBase=(uint8_t*)(eosBase+sect[i].VirtualAddress);
                textSize=sect[i].Misc.VirtualSize; break;
            }
        }
        if(textBase){
            printf(CLR_GRAY " [~] " CLR_WHITE "[CurlFallback/eos] " CLR_GRAY
                   ".text=0x%llX size=0x%llX" CLR_RESET "\n",
                   (unsigned long long)textBase,(unsigned long long)textSize);
            total += ScanAndHookCallSites(textBase,textSize,"eos");
        } else printf(CLR_WHITE " [x] [CurlFallback] EOS .text section not found" CLR_RESET "\n");
    }

    if(total==0)
        printf(CLR_WHITE " [x] [CurlFallback] No curl_easy_setopt functions found in any module" CLR_RESET "\n");

    return total > 0;
}

} // CurlFallback
} // Authy