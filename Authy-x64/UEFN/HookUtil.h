#pragma once
#include <Windows.h>
#include <cstdint>
#include <cstring>

namespace Authy {
namespace UEFN {
namespace HookUtil {

inline void AsmHook(void* ptr, void* detour) {
    if (!ptr || !detour) return;

    // x64 Detour trampoline:
    // push r10
    // mov r10, detour
    // call r10
    // pop r10
    // ret
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

} // HookUtil
} // UEFN
} // Authy
