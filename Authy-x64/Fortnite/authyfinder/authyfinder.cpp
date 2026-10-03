#include "pch.h"
#include "authyfinder.h"

#pragma pack(push, 0x1)
struct af_patch_raw_t {
    uint8_t* matches;
    uint8_t* masks;
    bool disabled;
    uint32_t count;
    bool (*callback)(struct af_patch_t* patch, void* stream);
};
#pragma pack(pop)

static inline bool af_maskmatch(uint8_t insn, uint8_t match, uint8_t mask) {
    return (insn & mask) == match;
}

AF_C bool af_find_maskmatch(void* buf, size_t size, struct af_patchset_t patchset) {
    uint8_t* stream = (uint8_t*)buf;
    if (!stream || !size) return false;

    for (size_t i = 0; i < size; i++) {
        for (uint32_t p = 0; p < patchset.count; p++) {
            struct af_patch_raw_t* patch = (struct af_patch_raw_t*)patchset.patches + p;
            if (patch->disabled) continue;

            uint32_t x;
            for (x = 0; x < patch->count; x++) {
                if ((i + x) >= size) break;
                if (!af_maskmatch(stream[i + x], patch->matches[x], patch->masks[x])) {
                    break;
                }
            }

            if (x == patch->count) {
                if (patch->callback((struct af_patch_t*)patch, stream + i)) {
                    return true;
                }
            }
        }
    }
    return false;
}

AF_C bool af_patchset_emit(void* buf, size_t size, struct af_patchset_t patchset) {
    return af_find_maskmatch(buf, size, patchset);
}

AF_C void af_disable_patch(struct af_patch_t* patch) {
    if (patch) patch->disabled = true;
}
