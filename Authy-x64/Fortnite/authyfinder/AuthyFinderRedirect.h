#pragma once
#include "pch.h"
#include "authyfinder.h"
#include <cstdio>
#include <cstdint>
#include <Windows.h>

// Forward declarations from CurlFallback
namespace Authy {
namespace CurlFallback {
    bool InstallHookAtTarget(uintptr_t target, const char* tag);
    void SetupBackend();
}
}

namespace Authy {
namespace AuthyFinder {

// Known RVAs from 38.00-redirect-main / Simpsons
constexpr uintptr_t SIMPSONS_GAME_CURL_SETOPT_RVA = 0x94D85F0ull;
constexpr uintptr_t SIMPSONS_EOS_CURL_SETOPT_RVA  = 0x1398C70ull;

// Section info helper
struct SectionInfo {
    uint8_t* base = nullptr;
    size_t size = 0;
};

inline SectionInfo GetModuleSection(uintptr_t moduleBase, const char* sectionName) {
    SectionInfo info{};
    if (!moduleBase) return info;
    auto* dos = (IMAGE_DOS_HEADER*)moduleBase;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return info;
    auto* nt = (IMAGE_NT_HEADERS*)(moduleBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return info;

    auto* sect = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        char name[9] = {};
        memcpy(name, sect[i].Name, 8);
        if (_stricmp(name, sectionName) == 0) {
            info.base = (uint8_t*)(moduleBase + sect[i].VirtualAddress);
            info.size = sect[i].Misc.VirtualSize;
            break;
        }
    }
    return info;
}

// Simpsons style RVA hook attempt
inline bool TrySimpsonsRVA(uintptr_t moduleBase, HMODULE eosBuf) {
    bool hookedAny = false;
    printf("\033[90m [~] \033[97m[AuthyFinder/Simpsons] \033[90mTesting known Simpsons RVAs (0x%llX / 0x%llX)...\033[0m\n",
           (unsigned long long)SIMPSONS_GAME_CURL_SETOPT_RVA, (unsigned long long)SIMPSONS_EOS_CURL_SETOPT_RVA);

    if (moduleBase) {
        uintptr_t gameTarget = moduleBase + SIMPSONS_GAME_CURL_SETOPT_RVA;
        if (Authy::CurlFallback::InstallHookAtTarget(gameTarget, "simpsons-game-rva")) {
            printf("\033[92m [+] \033[97m[AuthyFinder/Simpsons] \033[92mGame curl_easy_setopt hooked via Simpsons RVA!\033[0m\n");
            hookedAny = true;
        }
    }

    if (eosBuf) {
        uintptr_t eosTarget = (uintptr_t)eosBuf + SIMPSONS_EOS_CURL_SETOPT_RVA;
        if (Authy::CurlFallback::InstallHookAtTarget(eosTarget, "simpsons-eos-rva")) {
            printf("\033[92m [+] \033[97m[AuthyFinder/Simpsons] \033[92mEOS curl_easy_setopt hooked via Simpsons RVA!\033[0m\n");
            hookedAny = true;
        }
    }

    return hookedAny;
}

// Linear pattern scan across .text, .rdata, .data for curl_easy_setopt prologue using authyfinder engine
inline bool ScanSectionsForCurl(uintptr_t moduleBase, const char* moduleTag) {
    if (!moduleBase) return false;

    // curl_easy_setopt prologue: 14 bytes \u2014 shadow-store spills identical to g_CurlPrologue.
    // For the linear scan we use the same 14-byte pattern.  The call-site scanner
    // (CurlFallback) is the preferred strategy; AuthyFinder is a last resort so
    // 14 bytes gives the best chance of matching without false-positives in .text.
    static uint8_t curlMatches[14] = {
        0x89, 0x54, 0x24, 0x10,  0x4C, 0x89, 0x44, 0x24, 0x18,
        0x4C, 0x89, 0x4C, 0x24, 0x20
    };
    static uint8_t curlMasks[14] = {
        0xFF, 0xFF, 0xFF, 0xFF,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    };

    struct Context {
        const char* tag;
        bool hooked;
    } ctx{ moduleTag, false };

    auto patch = af_construct_patch(curlMatches, curlMasks, 14, [](struct af_patch_t* p, void* stream) -> bool {
        uintptr_t target = (uintptr_t)stream;
        if (Authy::CurlFallback::InstallHookAtTarget(target, "authyfinder-prologue")) {
            return true; // Stop on first successfully installed hook
        }
        return false;
    });

    struct af_patch_t patches[] = { patch };
    struct af_patchset_t patchset = af_construct_patchset(patches, 1);

    const char* sections[] = { ".text", ".rdata", ".data" };
    for (const char* secName : sections) {
        SectionInfo sec = GetModuleSection(moduleBase, secName);
        if (sec.base && sec.size > 0) {
            printf("\033[90m [~] \033[97m[AuthyFinder/%s] \033[90mScanning section %s (%llu bytes)...\033[0m\n",
                   moduleTag, secName, (unsigned long long)sec.size);
            if (af_patchset_emit(sec.base, sec.size, patchset)) {
                printf("\033[92m [+] \033[97m[AuthyFinder/%s] \033[92mcurl_easy_setopt prologue found in %s and hooked!\033[0m\n",
                       moduleTag, secName);
                return true;
            }
        }
    }

    return false;
}

// Master entrypoint for AuthyFinder fallback
inline bool Install(uintptr_t gameBase, HMODULE eosBuf) {
    Authy::CurlFallback::SetupBackend();
    printf("\033[93m [!] \033[97m[AuthyFinder] \033[90mStarting secondary Simpsons/AuthyFinder strategy...\033[0m\n");

    // 1. Try Simpsons known RVAs first
    if (TrySimpsonsRVA(gameBase, eosBuf)) {
        return true;
    }

    // 2. Linear scan of sections (.text, .rdata, .data) in Game & EOS using authyfinder engine
    bool hooked = false;
    if (ScanSectionsForCurl(gameBase, "game")) {
        hooked = true;
    }
    if (eosBuf && ScanSectionsForCurl((uintptr_t)eosBuf, "eos")) {
        hooked = true;
    }

    return hooked;
}

} // AuthyFinder
} // Authy
