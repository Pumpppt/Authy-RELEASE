#pragma once
#include "pch.h"
#include "authyfinder.h"
#include <cstdio>
#include <Windows.h>

namespace Authy {
namespace SafeEnv {

// Simpsons & Starfall AsmHook template:
// Saves volatile reg r10, loads detour address into r10, calls r10, restores r10, returns (RET 0xC3).
inline void AsmHook(void* ptr, void* detour) {
    if (!ptr || !detour) return;

    uint8_t data[] = {
        0x41, 0x52,                                                 // push r10
        0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r10, detour
        0x41, 0xFF, 0xD2,                                           // call r10
        0x41, 0x5A,                                                 // pop r10
        0xC3                                                        // ret
    };

    DWORD oldProt;
    if (VirtualProtect(ptr, sizeof(data), PAGE_EXECUTE_READWRITE, &oldProt)) {
        memcpy(ptr, data, sizeof(data));
        *(uint64_t*)((uintptr_t)ptr + 4) = (uint64_t)detour;
        VirtualProtect(ptr, sizeof(data), oldProt, &oldProt);
        FlushInstructionCache(GetCurrentProcess(), ptr, sizeof(data));
    }
}

inline void PatchByte(void* ptr, uint8_t byte) {
    if (!ptr) return;
    DWORD oldProt;
    if (VirtualProtect(ptr, 1, PAGE_EXECUTE_READWRITE, &oldProt)) {
        *(uint8_t*)ptr = byte;
        VirtualProtect(ptr, 1, oldProt, &oldProt);
        FlushInstructionCache(GetCurrentProcess(), ptr, 1);
    }
}

// Hook stubs (no-op bypasses)
inline void RequestExitWithStatusHook(bool Force, unsigned char Code) {
    // Suppress exit call from environment checks
}

inline void UnsafeEnvironmentPopupHook(wchar_t** unknown1, unsigned __int8 _case, __int64 unknown2, char unknown3) {
    // Suppress security warning dialog
}

// Callback handlers
inline bool RequestExitWithStatusCallback(struct af_patch_t* patch, void* stream) {
    AsmHook(stream, (void*)RequestExitWithStatusHook);
    printf("\033[92m [+] \033[97m[SafeEnv] \033[92mRequestExitWithStatus hooked @ %p\033[0m\n", stream);
    return true;
}

inline bool UnsafeEnvironmentPopupCallback(struct af_patch_t* patch, void* stream) {
    AsmHook(stream, (void*)UnsafeEnvironmentPopupHook);
    printf("\033[92m [+] \033[97m[SafeEnv] \033[92mUnsafeEnvironmentPopup hooked @ %p\033[0m\n", stream);
    return true;
}

inline void Install(uintptr_t moduleBase) {
    if (!moduleBase) return;

    auto* dos = (IMAGE_DOS_HEADER*)moduleBase;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    auto* nt = (IMAGE_NT_HEADERS*)(moduleBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;

    auto* sect = IMAGE_FIRST_SECTION(nt);
    void* tbuf = nullptr;
    size_t tsize = 0;
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        char name[9] = {};
        memcpy(name, sect[i].Name, 8);
        if (_stricmp(name, ".text") == 0) {
            tbuf = (void*)(moduleBase + sect[i].VirtualAddress);
            tsize = sect[i].Misc.VirtualSize;
            break;
        }
    }

    if (!tbuf || !tsize) {
        printf("\033[93m [!] \033[97m[SafeEnv] \033[90mFailed to find .text section\033[0m\n");
        return;
    }

    printf("\033[90m [~] \033[97m[SafeEnv] \033[90mScanning for RequestExitWithStatus & UnsafeEnvironmentPopup signatures...\033[0m\n");

    // 1. RequestExitWithStatus signatures from Starfall 33.30 & Simpsons 38.00
    constexpr static auto exitPatch1 = af_construct_patch_sig(
        "4C 8B DC 4B 89 5B 08 49 89 6B 10 4B 89 73 18 4B 89 7B 20 43 56 48 83 EC 30 0F B6 F2",
        RequestExitWithStatusCallback
    );
    constexpr static auto exitPatch2 = af_construct_patch_sig(
        "48 89 5C 24 ? 57 48 83 EC 40 41 B9 ? ? ? ? 0F B6 F9 44 38 0D ? ? ? ? 0F B6 DA 72 24 89 5C 24 30 48 8D 05 ? ? ? ? 89 7C 24 28 4C 8D 05 ? ? ? ? 33 D2 48 89 44 24 ? 33 C9 E8 ? ? ? ?",
        RequestExitWithStatusCallback
    );
    constexpr static auto exitPatch3 = af_construct_patch_sig(
        "48 8B C4 48 89 58 18 88 50 10 88 48 08 57 48 83 EC 30",
        RequestExitWithStatusCallback
    );
    constexpr static auto exitPatch4 = af_construct_patch_sig(
        "4C 8B DC 49 89 5B 08 49 89 6B 10 49 89 73 18 49 89 7B 20 41 56 48 83 EC 30 80 3D ? ? ? ? ? 49 8B",
        RequestExitWithStatusCallback
    );

    constexpr static struct af_patch_t exitPatches[] = {
        exitPatch1,
        exitPatch2,
        exitPatch3,
        exitPatch4
    };
    constexpr static struct af_patchset_t exitPatchset = af_construct_patchset(exitPatches, sizeof(exitPatches) / sizeof(struct af_patch_t));
    af_patchset_emit(tbuf, tsize, exitPatchset);

    // 2. UnsafeEnvironmentPopup signatures from Starfall 33.30 & Simpsons 38.00 (32.11 / 30.00 / 29.00 / 28.30 / 28.00 / 19.10)
    constexpr static auto safePopupPatch1 = af_construct_patch_sig(
        "48 89 5C 24 18 55 56 57 43 54 41 55 41 56 43 57 48 8D AC ? ? ? ? ? 4A 81 C4 ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 33 DB",
        UnsafeEnvironmentPopupCallback
    );
    constexpr static auto safePopupPatch2 = af_construct_patch_sig(
        "48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 80 B9 ? ? ? ? ? 48 8B DA 48 8B F1",
        UnsafeEnvironmentPopupCallback
    );
    constexpr static auto safePopupPatch3 = af_construct_patch_sig(
        "40 55 53 56 57 41 54 41 56 41 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? ? 0F B6 ?",
        UnsafeEnvironmentPopupCallback
    );
    constexpr static auto safePopupPatch4 = af_construct_patch_sig(
        "48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? ? 0F B6 ? 44 88 44 24 ?",
        UnsafeEnvironmentPopupCallback
    );
    constexpr static auto safePopupPatch5 = af_construct_patch_sig(
        "48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 45 ? 45 0F B6 F8",
        UnsafeEnvironmentPopupCallback
    );
    constexpr static auto safePopupPatch6 = af_construct_patch_sig(
        "4C 8B DC 55 49 8D AB ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 49 89 73 F0 49 89 7B E8 48 8B F9 4D 89 63 E0 4D 8B E0 4D 89 6B D8",
        UnsafeEnvironmentPopupCallback
    );
    constexpr static auto safePopupPatch7 = af_construct_patch_sig(
        "4C 8B DC 55 49 8D AB ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ?",
        UnsafeEnvironmentPopupCallback
    );

    constexpr static struct af_patch_t safePopupPatches[] = {
        safePopupPatch1,
        safePopupPatch2,
        safePopupPatch3,
        safePopupPatch4,
        safePopupPatch5,
        safePopupPatch6,
        safePopupPatch7
    };
    constexpr static struct af_patchset_t safePopupPatchset = af_construct_patchset(safePopupPatches, sizeof(safePopupPatches) / sizeof(struct af_patch_t));
    af_patchset_emit(tbuf, tsize, safePopupPatchset);
}

} // SafeEnv
} // Authy
