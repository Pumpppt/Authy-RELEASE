#include "pch.h"
#include "Hooks.h"
#include "Patchfinder.h"
#include "Options.h"
#include "CurlFallback.h"
#include "authyfinder/AuthyFinderRedirect.h"
#include "authyfinder/SafeEnv.h"
#include "../UEFN/UEFN.h"
#include <cstdio>

// ANSI color codes
#define CLR_RESET   "\033[0m"
#define CLR_CYAN    "\033[96m"
#define CLR_YELLOW  "\033[93m"
#define CLR_GREEN   "\033[92m"
#define CLR_RED     "\033[91m"
#define CLR_GRAY    "\033[90m"
#define CLR_WHITE   "\033[97m"
#define CLR_MAGENTA "\033[95m"

static void PrintBanner()
{
    printf(CLR_WHITE
        "\n"
        "   ___   __  __ _____ _  ___   __\n"
        "  / _ \\ / / / /_  __/ / / \\ \\ / /\n"
        " / ___ / /_/ / / / / _  /  \\ V / \n"
        "/_/  |_\\____/ /_/ /_/ /_/   /_/  \n"
        CLR_RESET "\n");

    printf(CLR_GRAY " Backend: " CLR_WHITE "%ls" CLR_RESET "\n", Authy::Options::Backend.c_str());
    printf(CLR_GRAY " ----------------------------------------" CLR_RESET "\n\n");
}

bool InitializeForModule(uint64_t Module, void* Hook, void** OG, bool EOS, bool* bFoundButNoVFT = nullptr)
{
    Authy::PE::ImageBase = Module;

    const char* moduleName = EOS ? "EOSSDK" : "FortniteClient";
    printf(CLR_GRAY " [~] " CLR_WHITE "[%s] " CLR_GRAY "Searching for ProcessRequest string ref..." CLR_RESET "\n", moduleName);

    auto processRequestStr = Authy::Patchfinder::FindStringRef(L"STAT_FCurlHttpRequest_ProcessRequest");

    if (!processRequestStr)
        processRequestStr = Authy::Patchfinder::FindStringRef(L"%p: request (easy handle:%p) has been added to threaded queue for processing");

    if (!processRequestStr)
        processRequestStr = Authy::Patchfinder::FindStringRef("STAT_FCurlHttpRequest_ProcessRequest");

    if (!processRequestStr)
    {
        printf(CLR_WHITE " [x] [%s] Failed to find ProcessRequest string ref" CLR_RESET "\n", moduleName);
        return false;
    }

    printf(CLR_GREEN " [+] " CLR_WHITE "[%s] " CLR_GRAY "String ref found @ 0x%llX" CLR_RESET "\n", moduleName, processRequestStr);
    printf(CLR_GRAY " [~] " CLR_WHITE "[%s] " CLR_GRAY "Walking back to function prologue..." CLR_RESET "\n", moduleName);

    uint64_t ProcessRequest = 0;
    for (int i = 0; i < 2048; i++)
    {
        if (EOS)
        {
            if (Authy::Patchfinder::CheckBytes<0x48, 0x89, 0x5C>(processRequestStr, i, true))
            {
                ProcessRequest = processRequestStr - i;
                break;
            }
        }
        else
        {
            if (Authy::Patchfinder::CheckBytes<0x4C, 0x8B, 0xDC>(processRequestStr, i, true))
            {
                ProcessRequest = processRequestStr - i;
                break;
            }
            else if (Authy::Patchfinder::CheckBytes<0x48, 0x8B, 0xC4>(processRequestStr, i, true))
            {
                ProcessRequest = processRequestStr - i;
                break;
            }
            else if (Authy::Patchfinder::CheckBytes<0x48, 0x81, 0xEC>(processRequestStr, i, true) || Authy::Patchfinder::CheckBytes<0x48, 0x83, 0xEC>(processRequestStr, i, true))
            {
                for (int x = 0; x < 50; x++)
                {
                    if (Authy::Patchfinder::CheckBytes<0x40>(processRequestStr, i + x, true))
                    {
                        ProcessRequest = processRequestStr - i - x;
                        goto _found;
                    }
                    else if (Authy::Patchfinder::CheckBytes<0x4C, 0x8B, 0xDC>(processRequestStr, i + x, true) || Authy::Patchfinder::CheckBytes<0x48, 0x8B, 0xC4>(processRequestStr, i + x, true) || Authy::Patchfinder::CheckBytes<0x48, 0x89, 0x5C>(processRequestStr, i + x, true))
                        break;
                }
            }
        }
    }

    if (!ProcessRequest)
    {
        printf(CLR_WHITE " [x] [%s] Failed to locate ProcessRequest prologue" CLR_RESET "\n", moduleName);
        return false;
    }
_found:
    // SafeEnv: ProcessRequest must live inside .text (false-positive guard)
    {
        auto textSection = Authy::PE::GetSection(".text");
        if (textSection)
        {
            uint64_t textStart = Authy::PE::ImageBase + textSection->VirtualAddress;
            uint64_t textEnd   = textStart + textSection->Misc.VirtualSize;
            if (ProcessRequest < textStart || ProcessRequest >= textEnd)
            {
                printf(CLR_WHITE " [x] [%s] ProcessRequest 0x%llX outside .text [0x%llX-0x%llX] - false positive, skipping" CLR_RESET "\n",
                       moduleName, ProcessRequest, textStart, textEnd);
                return false;
            }
        }
    }

    printf(CLR_GREEN " [+] " CLR_WHITE "[%s] " CLR_GRAY "ProcessRequest @ 0x%llX" CLR_RESET "\n", moduleName, ProcessRequest);
    printf(CLR_GRAY " [~] " CLR_WHITE "[%s] " CLR_GRAY "Scanning .rdata for VTable entry..." CLR_RESET "\n", moduleName);

    auto rdataSection = Authy::PE::GetSection(".rdata");
    const auto rdataStart = (uint8_t*)(Authy::PE::ImageBase + rdataSection->VirtualAddress);

    uint64_t ProcessRequestVFT = 0;

    // SafeEnv: SSE scan can fault on a bad false-positive ProcessRequest value
    __try
    {
        __m128i t = _mm_set1_epi32((int)(ProcessRequest & 0xffffffff));
        for (uint32_t i = 0; i < rdataSection->Misc.VirtualSize - (rdataSection->Misc.VirtualSize % 16); i += 16)
        {
            auto bytes = _mm_load_si128((const __m128i*)(rdataStart + i));
            int offset = _mm_movemask_epi8(_mm_cmpeq_epi32(bytes, t));

            if (offset == 0)
                continue;

            for (int q = 0; q < 16; q += 4)
            {
                int c = offset & (1 << q);
                if (c)
                {
                    auto VFT = (uint64_t*)(rdataStart + i + q);
                    if (*VFT == ProcessRequest)
                    {
                        ProcessRequestVFT = uint64_t(VFT);
                        goto _foundVFT;
                    }
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        printf(CLR_WHITE " [x] [%s] Exception during VTable scan - likely a false-positive string ref" CLR_RESET "\n", moduleName);
        return false;
    }

    // BUG FIX: was '!ProcessRequest' (always non-zero here) - must be '!ProcessRequestVFT'
    if (!ProcessRequestVFT)
    {
        if (bFoundButNoVFT) *bFoundButNoVFT = true; // permanent - same ProcessRequest won't appear in VTable
        printf(CLR_WHITE " [x] [%s] VTable entry not found for ProcessRequest" CLR_RESET "\n", moduleName);
        return false;
    }

_foundVFT:
    printf(CLR_GREEN " [+] " CLR_WHITE "[%s] " CLR_GRAY "VTable entry @ 0x%llX" CLR_RESET "\n", moduleName, ProcessRequestVFT);
    printf(CLR_GRAY " [~] " CLR_WHITE "[%s] " CLR_GRAY "Patching VTable..." CLR_RESET "\n", moduleName);

    // SafeEnv: guard the actual write in case something is wrong
    __try
    {
        DWORD oldProt;
        VirtualProtect(LPVOID(ProcessRequestVFT), sizeof(void*), PAGE_EXECUTE_READWRITE, &oldProt);

        if (OG)
            *OG = (void*)ProcessRequest;

        *(void**)ProcessRequestVFT = Hook;

        VirtualProtect(LPVOID(ProcessRequestVFT), sizeof(void*), oldProt, &oldProt);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        printf(CLR_WHITE " [x] [%s] Exception patching VTable @ 0x%llX" CLR_RESET "\n", moduleName, ProcessRequestVFT);
        return false;
    }

    printf(CLR_GREEN " [+] " CLR_WHITE "[%s] " CLR_GREEN "Hook installed successfully!" CLR_RESET "\n", moduleName);
    return true;
}

bool ProcessRequestHook(Authy::Unreal::FCurlHttpRequest* _this)
{
    _this->RedirectRequest(false);
    return Authy::Unreal::FCurlHttpRequest::ProcessRequestOG(_this);
}

bool ProcessRequest__EOS(Authy::Unreal::FCurlHttpRequest* _this)
{
    _this->RedirectRequest(true);
    return Authy::Unreal::FCurlHttpRequest::ProcessRequestOG__EOS(_this);
}

bool bInit = false;
void Authy::Hooks::Init()
{
    Authy::Options::ParseCommandLine();

    // Point backend FString directly at our static buffer — FMemory::Realloc
    // hasn't been found yet, so we cannot go through AllocString/FString(wchar_t*).
    Authy::Unreal::backend.String  = Authy::Options::Backend_buf;
    Authy::Unreal::backend.Length  = (uint32_t)wcslen(Authy::Options::Backend_buf) + 1;
    Authy::Unreal::backend.MaxSize = 512;

    if (Console)
    {
        AllocConsole();
        SetConsoleTitleA("Authy");

        // Open CONOUT$ directly — bypasses whatever handle the host process had
        HANDLE hCon = CreateFileA(
            "CONOUT$",
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            OPEN_EXISTING,
            0,
            nullptr
        );

        // Enable VT on the handle we actually own
        if (hCon != INVALID_HANDLE_VALUE)
        {
            DWORD dwMode = 0;
            GetConsoleMode(hCon, &dwMode);
            SetConsoleMode(hCon, dwMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING | DISABLE_NEWLINE_AUTO_RETURN);
        }

        // Point CRT stdout at the same handle
        FILE* fptr;
        freopen_s(&fptr, "CONOUT$", "w+", stdout);

        PrintBanner();
    }

    if (Authy::Options::RedType == Authy__RedType::UEFN)
    {
        Authy::UEFN::Init();
        bInit = true;
        return;
    }

    // ── Scan for FMemory::Realloc (initial attempt) ─────────────────────────
    constexpr static auto ReallocSig = Authy::Patchfinder::Pattern<"48 89 5C 24 08 48 89 74 24 10 57 48 83 EC ? 48 8B F1 41 8B D8 48 8B 0D ? ? ? ?">();
    Authy::Unreal::FMemory__Realloc = ReallocSig.Scan();

    if (Authy::Unreal::FMemory__Realloc)
        printf(CLR_GREEN " [+] " CLR_WHITE "[Init] " CLR_GRAY "FMemory::Realloc @ 0x%llX" CLR_RESET "\n",
               Authy::Unreal::FMemory__Realloc);
    else
        printf(CLR_YELLOW " [!] " CLR_WHITE "[Init] " CLR_GRAY
               "FMemory::Realloc not found — likely encrypted build, continuing" CLR_RESET "\n");

    printf(CLR_GRAY "\n [~] " CLR_WHITE "[Init] " CLR_GRAY "Hooking FortniteClient-Win64-Shipping..." CLR_RESET "\n");


    bool gameHooked   = false;
    bool permanentFail = false;
    bool curlInstalled = false;

    // Load EOS module — needed by both code paths
    HMODULE eosBuf = GetModuleHandleA("EOSSDK-Win64-Shipping");
    if (!eosBuf) eosBuf = LoadLibraryA("EOSSDK-Win64-Shipping");

    auto SetupSafeEnvAndFinalize = [&](bool usedCurlFallback)
    {
        if (eosBuf)
        {
            if (bHasPushWidget)
            {
                Authy::PE::ImageBase = *(uint64_t*)(__readgsqword(0x60) + 0x10);
                constexpr static auto PushWidget1 = Authy::Patchfinder::Pattern<"48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC 30 48 8B E9 49 8B D9 48 8D 0D ? ? ? ? 49 8B F8 48 8B F2 E8 ? ? ? ? 4C 8B CF 48 89 5C 24 ? 4C 8B C6 48 8B D5 48 8B 48 78">();
                constexpr static auto PushWidget2 = Authy::Patchfinder::Pattern<"48 8B C4 4C 89 40 18 48 89 50 10 48 89 48 08 55 53 56 57 41 54 41 55 41 56 41 57 48 8D 68 B8 48 81 EC ? ? ? ? 65 48 8B 04 25">();
                constexpr static auto PushWidget3 = Authy::Patchfinder::Pattern<"48 8B C4 48 89 58 ? 48 89 70 ? 48 89 78 ? 55 41 56 41 57 48 8D 68 A1 48 81 EC ? ? ? ? 65 48 8B 04 25 ? ? ? ? 48 8B F9 B9 ? ? ? ?">();
                constexpr static auto PushWidget4 = Authy::Patchfinder::Pattern<"48 89 5C 24 ? 48 89 74 24 ? 55 57 41 54 41 56 41 57 48 8D 6C 24 ? 48 81 EC ? ? ? ? 49 8B D9 49 8B F8 4C 8B E2 4C 8B F1">();

                if (PushWidget1.Scan() || PushWidget2.Scan() || PushWidget3.Scan() || PushWidget4.Scan())
                {
                    constexpr static auto RequestExitWithStatus1 = Authy::Patchfinder::Pattern<"48 89 5C 24 ? 57 48 83 EC 40 41 B9 ? ? ? ? 0F B6 F9 44 38 0D ? ? ? ? 0F B6 DA 72 24 89 5C 24 30 48 8D 05 ? ? ? ? 89 7C 24 28 4C 8D 05 ? ? ? ? 33 D2 48 89 44 24 ? 33 C9 E8 ? ? ? ?">();
                    constexpr static auto RequestExitWithStatus2 = Authy::Patchfinder::Pattern<"48 8B C4 48 89 58 18 88 50 10 88 48 08 57 48 83 EC 30">();
                    constexpr static auto RequestExitWithStatus3 = Authy::Patchfinder::Pattern<"4C 8B DC 49 89 5B 08 49 89 6B 10 49 89 73 18 49 89 7B 20 41 56 48 83 EC 30 80 3D ? ? ? ? ? 49 8B">();

                    auto RequestExitWithStatus = RequestExitWithStatus1.Scan();
                    if (!RequestExitWithStatus) RequestExitWithStatus = RequestExitWithStatus2.Scan();
                    if (!RequestExitWithStatus) RequestExitWithStatus = RequestExitWithStatus3.Scan();

                    constexpr static auto ShowAppEnvironmentSecurityMessage1 = Authy::Patchfinder::Pattern<"4C 8B DC 55 49 8D AB ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 49 89 73 F0 49 89 7B E8 48 8B F9 4D 89 63 E0 4D 8B E0 4D 89 6B D8">();
                    constexpr static auto ShowAppEnvironmentSecurityMessage2 = Authy::Patchfinder::Pattern<"48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 45 ? 41 0F B6 D8 48 89 55 ? 88 5C 24 ?">();
                    constexpr static auto ShowAppEnvironmentSecurityMessage3 = Authy::Patchfinder::Pattern<"48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 80 B9 ? ? ? ? ? 48 8B DA 48 8B F1">();
                    constexpr static auto ShowAppEnvironmentSecurityMessage4 = Authy::Patchfinder::Pattern<"48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? ? 0F B6 ? 44 88 44 24 ?">();
                    constexpr static auto ShowAppEnvironmentSecurityMessage5 = Authy::Patchfinder::Pattern<"48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 45 ? 45 0F B6 F8">();
                    constexpr static auto ShowAppEnvironmentSecurityMessage6 = Authy::Patchfinder::Pattern<"40 55 53 56 57 41 54 41 56 41 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? ? 0F B6 ?">();
                    constexpr static auto ShowAppEnvironmentSecurityMessage7 = Authy::Patchfinder::Pattern<"4C 8B DC 55 49 8D AB ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ?">();

                    auto ShowAppEnvironmentSecurityMessage = ShowAppEnvironmentSecurityMessage1.Scan();
                    if (!ShowAppEnvironmentSecurityMessage) ShowAppEnvironmentSecurityMessage = ShowAppEnvironmentSecurityMessage2.Scan();
                    if (!ShowAppEnvironmentSecurityMessage) ShowAppEnvironmentSecurityMessage = ShowAppEnvironmentSecurityMessage3.Scan();
                    if (!ShowAppEnvironmentSecurityMessage) ShowAppEnvironmentSecurityMessage = ShowAppEnvironmentSecurityMessage4.Scan();
                    if (!ShowAppEnvironmentSecurityMessage) ShowAppEnvironmentSecurityMessage = ShowAppEnvironmentSecurityMessage5.Scan();
                    if (!ShowAppEnvironmentSecurityMessage) ShowAppEnvironmentSecurityMessage = ShowAppEnvironmentSecurityMessage6.Scan();
                    if (!ShowAppEnvironmentSecurityMessage) ShowAppEnvironmentSecurityMessage = ShowAppEnvironmentSecurityMessage7.Scan();

                    if (RequestExitWithStatus)
                    {
                        DWORD oldProt;
                        VirtualProtect(LPVOID(RequestExitWithStatus), 1, PAGE_EXECUTE_READWRITE, &oldProt);
                        *(uint8_t*)RequestExitWithStatus = 0xC3;
                        VirtualProtect(LPVOID(RequestExitWithStatus), 1, oldProt, &oldProt);
                    }

                    if (ShowAppEnvironmentSecurityMessage)
                    {
                        DWORD oldProt;
                        VirtualProtect(LPVOID(ShowAppEnvironmentSecurityMessage), 1, PAGE_EXECUTE_READWRITE, &oldProt);
                        *(uint8_t*)ShowAppEnvironmentSecurityMessage = 0xC3;
                        VirtualProtect(LPVOID(ShowAppEnvironmentSecurityMessage), 1, oldProt, &oldProt);
                    }

                    if (!RequestExitWithStatus || !ShowAppEnvironmentSecurityMessage)
                    {
                        printf(CLR_YELLOW " [!] " CLR_WHITE "[SafeEnv] " CLR_GRAY "Patternfinder missed some SafeEnv hooks, invoking AuthyFinder SafeEnv scanner..." CLR_RESET "\n");
                        Authy::SafeEnv::Install(Authy::PE::ImageBase);
                    }
                }
                else
                {
                    printf(CLR_YELLOW " [!] " CLR_WHITE "[SafeEnv] " CLR_GRAY "PushWidget pattern not found, scanning SafeEnv directly..." CLR_RESET "\n");
                    Authy::SafeEnv::Install(Authy::PE::ImageBase);
                }
            }
        }
        else
            printf(CLR_YELLOW " [!] " CLR_WHITE "[Init] " CLR_GRAY "EOS module not found, skipping EOS hook" CLR_RESET "\n");

        printf(CLR_GRAY "\n [----------------------------------------]" CLR_RESET "\n");
        printf(CLR_WHITE " [+] [Init] Authy initialized! %s" CLR_RESET "\n",
               usedCurlFallback ? "CurlFallback active, listening for requests..." : "ProcessRequest hooked, listening for requests...");
        printf(CLR_GRAY " [----------------------------------------]\n\n" CLR_RESET);
        printf(CLR_MAGENTA " [LogsLive] " CLR_GRAY "Intercepted URLs will appear below:" CLR_RESET "\n\n");

        bInit = true;
    };

    // Helper: try ProcessRequest on the game module once
    auto TryHookProcessRequest = [&]() -> bool
    {
        bool bFoundButNoVFT = false;
        bool hooked = InitializeForModule(Authy::PE::ImageBase, ProcessRequestHook,
                                          (void**)&Authy::Unreal::FCurlHttpRequest::ProcessRequestOG,
                                          false, &bFoundButNoVFT);
        if (bFoundButNoVFT)
        {
            printf(CLR_YELLOW " [!] " CLR_WHITE "[Init] " CLR_GRAY
                   "ProcessRequest found but no VTable — permanent mismatch" CLR_RESET "\n");
            permanentFail = true;
        }
        return hooked;
    };

    // ── PHASE 1: Hook Curl FIRST immediately ─────────────────────────────────
    // Instantly catch all HTTP traffic without any delay
    curlInstalled = Authy::CurlFallback::Install(Authy::PE::ImageBase, eosBuf);
    if (!curlInstalled)
    {
        printf(CLR_YELLOW " [!] " CLR_WHITE "[Init] " CLR_GRAY
               "Primary curl scan failed, trying AuthyFinder..." CLR_RESET "\n");
        curlInstalled = Authy::AuthyFinder::Install(Authy::PE::ImageBase, eosBuf);
    }

    if (curlInstalled)
    {
        SetupSafeEnvAndFinalize(true);
    }

    // ── PHASE 2: Now search / poll for ProcessRequest ─────────────────────────
    printf(CLR_GRAY "\n [~] " CLR_WHITE "[Init] " CLR_GRAY
           "Searching for ProcessRequest in background (up to 4s)..." CLR_RESET "\n");

    const int maxAttempts = 40; // 40 * 100ms = 4.0s
    for (int i = 0; i < maxAttempts && !gameHooked && !permanentFail; i++)
    {
        auto ref = Authy::Patchfinder::FindStringRef(L"STAT_FCurlHttpRequest_ProcessRequest");
        if (!ref) ref = Authy::Patchfinder::FindStringRef(
            L"%p: request (easy handle:%p) has been added to threaded queue for processing");
        if (!ref) ref = Authy::Patchfinder::FindStringRef("STAT_FCurlHttpRequest_ProcessRequest");

        if (ref)
        {
            gameHooked = TryHookProcessRequest();
            if (permanentFail || gameHooked) break;
        }

        Sleep(100);
    }

    // ── PHASE 3: If ProcessRequest is found, uninstall Curl hooks ─────────────
    if (gameHooked)
    {
        if (curlInstalled)
        {
            Authy::CurlFallback::Uninstall();
            curlInstalled = false;
        }

        printf(CLR_GREEN " [+] " CLR_WHITE "[Init] " CLR_GREEN
               "ProcessRequest VTable hook installed!" CLR_RESET "\n");

        // Retry FMemory::Realloc now that modules are loaded
        if (!Authy::Unreal::FMemory__Realloc)
        {
            constexpr static auto RSig = Authy::Patchfinder::Pattern<"48 89 5C 24 08 48 89 74 24 10 57 48 83 EC ? 48 8B F1 41 8B D8 48 8B 0D ? ? ? ?">();
            for (int r = 0; r < 20 && !Authy::Unreal::FMemory__Realloc; r++)
            {
                Authy::Unreal::FMemory__Realloc = RSig.Scan();
                if (!Authy::Unreal::FMemory__Realloc) Sleep(50);
            }
            if (Authy::Unreal::FMemory__Realloc)
                printf(CLR_GREEN " [+] " CLR_WHITE "[Init] " CLR_GRAY "FMemory::Realloc @ 0x%llX" CLR_RESET "\n",
                       Authy::Unreal::FMemory__Realloc);
            else
                printf(CLR_YELLOW " [!] " CLR_WHITE "[Init] " CLR_GRAY
                       "FMemory::Realloc pattern not matched" CLR_RESET "\n");
        }

        if (eosBuf)
        {
            printf(CLR_GREEN " [+] " CLR_WHITE "[Init] " CLR_GRAY "EOS module found, hooking..." CLR_RESET "\n");
            InitializeForModule(uint64_t(eosBuf), ProcessRequest__EOS,
                (void**)&Authy::Unreal::FCurlHttpRequest::ProcessRequestOG__EOS, true);
        }

        SetupSafeEnvAndFinalize(false);
        return;
    }

    // ProcessRequest was not found — CurlFallback remains active
    if (!curlInstalled)
    {
        printf(CLR_WHITE " [x] [Init] All redirect strategies failed — no redirect active" CLR_RESET "\n");
        SetupSafeEnvAndFinalize(true);
    }
}

