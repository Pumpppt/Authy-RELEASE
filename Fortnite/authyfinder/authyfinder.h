#pragma once
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string_view>
#include <array>
#include <algorithm>

#ifdef __cplusplus
#define AF_C extern "C"
#else
#define AF_C
#endif

#pragma pack(push, 0x1)
struct af_patch_t {
    void* matches;
    void* masks;
    bool disabled;
    uint32_t count;
    bool (*callback)(struct af_patch_t* patch, void* stream);
};

struct af_patchset_t {
    struct af_patch_t* patches;
    uint32_t count;
};
#pragma pack(pop)

#ifdef __cplusplus
constexpr af_patch_t af_construct_patch(void* matches, void* masks, uint32_t count, bool (*callback)(struct af_patch_t* patch, void* stream)) {
    af_patch_t patch{};
    patch.matches = matches;
    patch.masks = masks;
    patch.disabled = false;
    patch.count = count;
    patch.callback = callback;
    return patch;
}

constexpr struct af_patchset_t af_construct_patchset(struct af_patch_t* patches, uint32_t count) {
    af_patchset_t patchset{};
    patchset.patches = patches;
    patchset.count = count;
    return patchset;
}

__forceinline constexpr struct af_patchset_t af_construct_patchset(const struct af_patch_t* patches, uint32_t count) {
    return af_construct_patchset((struct af_patch_t*)patches, count);
}

// Compile-time string & signature helpers (Simpsons/Starfall style)
template <size_t _Sz>
struct AfConstexprString {
    char _St[_Sz];

    consteval AfConstexprString(const char(&_Ps)[_Sz]) {
        std::copy_n(_Ps, _Sz, _St);
    }

    constexpr operator const char* () const {
        return _St;
    }

    constexpr std::string_view StringView() const {
        return _St;
    }

    constexpr int PatternCount() const {
        int c = 0;
        for (size_t i = 0; i < _Sz; i++) {
            if (_St[i] == ' ') c++;
        }
        return c + 1;
    }
};

template <typename _Ft>
struct AfConstexprFunc {
    _Ft _Fn;
    consteval AfConstexprFunc(_Ft _Pf) : _Fn(_Pf) {}
    constexpr _Ft Get() const { return _Fn; }
};

template <size_t _Sz>
struct AfConstexprArray {
    uint8_t _Ar[_Sz];
    consteval AfConstexprArray(std::array<uint8_t, _Sz> _Pa) {
        std::copy_n(_Pa.data(), _Sz, _Ar);
    }
    constexpr const void* Get() const { return (const void*)_Ar; }
};

constexpr int AfPatternCount(std::string_view s) {
    int c = 0;
    for (size_t i = 0; i < s.size(); i++) {
        if (s[i] == ' ') c++;
    }
    return c + 1;
}

constexpr uint32_t AfParsePatternPart(std::string_view s) {
    uint32_t val = 0;
    for (size_t i = 0; i < s.size(); i++) {
        uint8_t byte = s[i];
        if (byte >= '0' && byte <= '9') byte = byte - '0';
        else if (byte >= 'a' && byte <= 'f') byte = byte - 'a' + 10;
        else if (byte >= 'A' && byte <= 'F') byte = byte - 'A' + 10;
        else if (byte == '?') byte = 0;
        val = (val << 4) | (byte & 0xF);
    }
    return val;
}

constexpr uint32_t AfParsePatternMask(std::string_view s) {
    uint32_t val = 0;
    for (size_t i = 0; i < s.size(); i++) {
        uint8_t byte = s[i];
        if ((byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f') || (byte >= 'A' && byte <= 'F')) byte = 0xf;
        else if (byte == '?') byte = 0x0;
        val = (val << 4) | (byte & 0xF);
    }
    return val;
}

template <AfConstexprString _St, AfConstexprFunc _Cb, AfConstexprArray _Ma, AfConstexprArray _Mk>
class AfConstexprPatch {
public:
    constexpr af_patch_t Create() {
        return af_construct_patch((void*)_Ma.Get(), (void*)_Mk.Get(), _St.PatternCount(), _Cb.Get());
    }
};

#define af_construct_patch_sig(sig, callback) AfConstexprPatch<sig, callback, ([&]() consteval { \
    constexpr auto st = std::string_view(sig); \
    constexpr auto arrsz = AfPatternCount(st); \
    std::array<uint8_t, arrsz> matches = { 0 }; \
    size_t cInd = 0; \
    for (int i = 0; i < arrsz; i++) { \
        auto part = st.substr(cInd, st.find_first_of(' ', cInd) == std::string_view::npos ? st.size() - cInd : (st.find_first_of(' ', cInd) + 1) - cInd - 1); \
        matches[i] = (uint8_t)AfParsePatternPart(part); \
        cInd = st.find_first_of(' ', cInd) + 1; \
    } \
    return matches; \
})(), ([&]() consteval { \
    constexpr auto st = std::string_view(sig); \
    constexpr auto arrsz = AfPatternCount(st); \
    std::array<uint8_t, arrsz> masks = { 0 }; \
    size_t cInd = 0; \
    for (int i = 0; i < arrsz; i++) { \
        auto part = st.substr(cInd, st.find_first_of(' ', cInd) == std::string_view::npos ? st.size() - cInd : (st.find_first_of(' ', cInd) + 1) - cInd - 1); \
        masks[i] = (uint8_t)AfParsePatternMask(part); \
        cInd = st.find_first_of(' ', cInd) + 1; \
    } \
    return masks; \
})()>().Create()

#else
AF_C struct af_patch_t af_construct_patch(void* matches, void* masks, uint32_t count, bool (*callback)(struct af_patch_t* patch, void* stream));
AF_C struct af_patchset_t af_construct_patchset(struct af_patch_t* patches, uint32_t count);
#endif

AF_C bool af_find_maskmatch(void* buf, size_t size, struct af_patchset_t patchset);
AF_C bool af_patchset_emit(void* buf, size_t size, struct af_patchset_t patchset);
AF_C void af_disable_patch(struct af_patch_t* patch);
