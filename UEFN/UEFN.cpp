// UEFN.cpp - UEFN Redirection Engine (Call-site scan, EOS, INI auto-config, memory & exit patches)
#include "../Fortnite/pch.h"
#include "../Fortnite/Unreal.h"
#include "../Fortnite/Options.h"
#include "../Fortnite/CurlFallback.h"
#include "../Fortnite/authyfinder/SafeEnv.h"
#include "UEFN.h"
#include "Config.h"
#include "HookUtil.h"
#include <string>
#include <vector>
#include <psapi.h>
#include <shlobj.h>

namespace Authy {
    namespace UEFN {

        static bool g_MemLeakFixed = false;
        static bool g_ExitHooked   = false;

        // ============================================================================
        // Memory & Pattern Scanning Helpers
        // ============================================================================
        static uintptr_t SigScan(HMODULE hModule, const char* signature) {
            if (!hModule) return 0;

            MODULEINFO modInfo{};
            if (!GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo)))
                return 0;

            uint8_t* base = reinterpret_cast<uint8_t*>(modInfo.lpBaseOfDll);
            size_t size   = modInfo.SizeOfImage;

            std::vector<int> bytes;
            const char* current = signature;
            while (*current) {
                while (*current == ' ') current++;
                if (!*current) break;

                if (*current == '?') {
                    bytes.push_back(-1);
                    current++;
                    if (*current == '?') current++;
                } else {
                    bytes.push_back(static_cast<int>(strtoul(current, const_cast<char**>(&current), 16)));
                }
            }

            if (bytes.empty() || size < bytes.size()) return 0;

            size_t patternLen = bytes.size();
            for (size_t i = 0; i <= size - patternLen; ++i) {
                bool match = true;
                for (size_t j = 0; j < patternLen; ++j) {
                    if (bytes[j] != -1 && base[i + j] != static_cast<uint8_t>(bytes[j])) {
                        match = false;
                        break;
                    }
                }
                if (match) {
                    return reinterpret_cast<uintptr_t>(base + i);
                }
            }

            return 0;
        }

        static uintptr_t ScanModuleSignatures(HMODULE hModule, const std::vector<const char*>& signatures) {
            if (!hModule) return 0;
            for (const auto& sig : signatures) {
                uintptr_t addr = SigScan(hModule, sig);
                if (addr) return addr;
            }
            return 0;
        }

        // ============================================================================
        // Auto-Configuration: bEnableCURLInEditor for UEFN & Projects
        // ============================================================================
        static void SetIniKey(const std::wstring& filePath, const wchar_t* section, const wchar_t* key, const wchar_t* value) {
            if (filePath.empty()) return;

            size_t slashPos = filePath.find_last_of(L"\\/");
            if (slashPos != std::wstring::npos) {
                std::wstring dir = filePath.substr(0, slashPos);
                CreateDirectoryW(dir.c_str(), nullptr);
            }

            WritePrivateProfileStringW(section, key, value, filePath.c_str());
        }

        static void AutoEnableCurlInIniFiles() {
            wchar_t localAppData[MAX_PATH] = {};
            if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, localAppData))) {
                std::wstring uefnConfigDir = std::wstring(localAppData) + L"\\UnrealEditorFortnite\\Saved\\Config";
                SetIniKey(uefnConfigDir + L"\\WindowsEditor\\Engine.ini", L"HTTP", L"bEnableCURLInEditor", L"True");
                SetIniKey(uefnConfigDir + L"\\WindowsEditor\\Engine.ini", L"HTTP.Curl", L"bEnableCURLInEditor", L"True");

                SetIniKey(uefnConfigDir + L"\\Windows\\Engine.ini", L"HTTP", L"bEnableCURLInEditor", L"True");
                SetIniKey(uefnConfigDir + L"\\Windows\\Engine.ini", L"HTTP.Curl", L"bEnableCURLInEditor", L"True");
            }

            wchar_t currentDir[MAX_PATH] = {};
            GetCurrentDirectoryW(MAX_PATH, currentDir);
            std::wstring localEngineIni = std::wstring(currentDir) + L"\\Config\\DefaultEngine.ini";
            SetIniKey(localEngineIni, L"HTTP", L"bEnableCURLInEditor", L"True");
            SetIniKey(localEngineIni, L"HTTP.Curl", L"bEnableCURLInEditor", L"True");

            LPWSTR cmdLine = GetCommandLineW();
            if (cmdLine) {
                std::wstring cmd(cmdLine);
                size_t projPos = cmd.find(L".uproject");
                if (projPos != std::wstring::npos) {
                    size_t startQuote = cmd.rfind(L"\"", projPos);
                    size_t startSpace = cmd.rfind(L" ", projPos);
                    size_t start = (startQuote != std::wstring::npos) ? (startQuote + 1) :
                                   ((startSpace != std::wstring::npos) ? (startSpace + 1) : 0);
                    std::wstring uprojectPath = cmd.substr(start, projPos + 9 - start);
                    size_t lastSlash = uprojectPath.find_last_of(L"\\/");
                    if (lastSlash != std::wstring::npos) {
                        std::wstring projDir = uprojectPath.substr(0, lastSlash);
                        std::wstring projEngineIni = projDir + L"\\Config\\DefaultEngine.ini";
                        SetIniKey(projEngineIni, L"HTTP", L"bEnableCURLInEditor", L"True");
                        SetIniKey(projEngineIni, L"HTTP.Curl", L"bEnableCURLInEditor", L"True");
                    }
                }
            }

            printf(CLR_GRAY " [~] " CLR_WHITE "[UEFN] " CLR_GRAY "Auto-configured bEnableCURLInEditor=True in project and editor INI files." CLR_RESET "\n");
        }

        // ============================================================================
        // Patches & Fixes
        // ============================================================================
        static void ApplyMemoryFixes() {
            if (!Config::FixMemLeak || g_MemLeakFixed) return;

            HMODULE hEngine = GetModuleHandleA("UnrealEditorFortnite-Engine-Win64-Shipping.dll");
            if (!hEngine) hEngine = GetModuleHandleA("UnrealEditorFortnite-Win64-Shipping.exe");
            if (!hEngine) hEngine = GetModuleHandleA(nullptr);
            if (!hEngine) return;

            uintptr_t leakAddr = SigScan(hEngine, "4C 8B DC 55 57 41 56 49 8D AB ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 48 8B 01 41 B6");
            if (leakAddr) {
                HookUtil::PatchByte((void*)leakAddr, 0xC3); // Ret
                g_MemLeakFixed = true;
                printf(CLR_GREEN " [+] " CLR_WHITE "[UEFN] " CLR_GREEN "Applied Memory Leak Fix @ 0x%p" CLR_RESET "\n", (void*)leakAddr);
            }
        }

        static void ApplyExitHooks() {
            if (!Config::AntiExit || g_ExitHooked) return;

            HMODULE hEngine = GetModuleHandleA("UnrealEditorFortnite-Engine-Win64-Shipping.dll");
            if (!hEngine) hEngine = GetModuleHandleA("UnrealEditorFortnite-Win64-Shipping.exe");
            if (!hEngine) hEngine = GetModuleHandleA(nullptr);
            if (!hEngine) return;

            // Also invoke AuthyFinder SafeEnv scanner on the module base
            Authy::SafeEnv::Install((uintptr_t)hEngine);

            std::vector<const char*> unsafePopupSigs = {
                "4C 8B DC 55 49 8D AB ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 49 89 73 F0 49 89 7B E8 48 8B F9 4D 89 63 E0 4D 8B E0 4D 89 6B D8",
                "4C 8B DC 55 49 8D AB ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ?",
                "48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 85 ? ? ? ? 80 B9 ? ? ? ? ? 48 8B DA 48 8B F1"
            };

            uintptr_t unsafePopup = ScanModuleSignatures(hEngine, unsafePopupSigs);
            if (unsafePopup) {
                HookUtil::PatchByte((void*)unsafePopup, 0xC3);
                printf(CLR_GREEN " [+] " CLR_WHITE "[UEFN] " CLR_GREEN "Hooked UnsafeEnvironmentPopup @ 0x%p" CLR_RESET "\n", (void*)unsafePopup);
            }

            std::vector<const char*> exitSigs = {
                "48 89 5C 24 ? 57 48 83 EC 40 41 B9 ? ? ? ? 0F B6 F9 44 38 0D ? ? ? ? 0F B6 DA 72 24 89 5C 24 30 48 8D 05 ? ? ? ? 89 7C 24 28 4C 8D 05 ? ? ? ? 33 D2 48 89 44 24 ? 33 C9 E8 ? ? ? ?",
                "48 8B C4 48 89 58 18 88 50 10 88 48 08 57 48 83 EC 30",
                "4C 8B DC 49 89 5B 08 49 89 6B 10 49 89 73 18 49 89 7B 20 41 56 48 83 EC 30 80 3D ? ? ? ? ? 49 8B"
            };

            uintptr_t reqExit = ScanModuleSignatures(hEngine, exitSigs);
            if (reqExit) {
                HookUtil::PatchByte((void*)reqExit, 0xC3);
                printf(CLR_GREEN " [+] " CLR_WHITE "[UEFN] " CLR_GREEN "Hooked RequestExitWithStatus @ 0x%p" CLR_RESET "\n", (void*)reqExit);
            }

            g_ExitHooked = true;
        }

        // ============================================================================
        // Background Polling Thread (catches late-loaded modules)
        // ============================================================================
        static DWORD WINAPI BackgroundPollThread(LPVOID) {
            for (int i = 0; i < 600; ++i) { // Poll for up to 60 seconds
                ApplyMemoryFixes();
                ApplyExitHooks();

                HMODULE hEOS = GetModuleHandleA("EOSSDK-Win64-Shipping.dll");
                if (!hEOS) hEOS = GetModuleHandleA("EOSSDK-Win64-Shipping");

                HMODULE hEngine = GetModuleHandleA("UnrealEditorFortnite-Engine-Win64-Shipping.dll");
                if (!hEngine) hEngine = GetModuleHandleA("UnrealEditorFortnite-Win64-Shipping.exe");
                if (!hEngine) hEngine = GetModuleHandleA(nullptr);

                if (hEngine && hEOS) {
                    break;
                }

                Sleep(100);
            }
            return 0;
        }

        // ============================================================================
        // Public API
        // ============================================================================
        void Init() {
            Config::EnsureInit();

            printf(CLR_GRAY " [~] " CLR_WHITE "[UEFN] " CLR_GRAY "Initializing UEFN redirection engine..." CLR_RESET "\n");
            printf(CLR_GRAY " [~] " CLR_WHITE "[UEFN] " CLR_GRAY "Target Backend: " CLR_GREEN "%s" CLR_RESET "\n", Config::BackendA());

            // 1. Auto-configure bEnableCURLInEditor in all relevant INI files
            AutoEnableCurlInIniFiles();

            // 2. Resolve modules
            HMODULE hEngine = GetModuleHandleA("UnrealEditorFortnite-Engine-Win64-Shipping.dll");
            if (!hEngine) hEngine = GetModuleHandleA("UnrealEditorFortnite-Win64-Shipping.exe");
            if (!hEngine) hEngine = GetModuleHandleA(nullptr);

            HMODULE hEOS = GetModuleHandleA("EOSSDK-Win64-Shipping.dll");
            if (!hEOS) hEOS = GetModuleHandleA("EOSSDK-Win64-Shipping");
            if (!hEOS) hEOS = LoadLibraryA("EOSSDK-Win64-Shipping.dll");

            // 3. Scan & Hook Curl call-sites via full trampoline (robust & crash-free)
            bool hooked = Authy::CurlFallback::Install((uint64_t)hEngine, hEOS);

            // 4. Apply memory and anti-exit patches
            ApplyMemoryFixes();
            ApplyExitHooks();

            if (hooked) {
                printf(CLR_GREEN " [+] " CLR_WHITE "[UEFN] " CLR_GREEN "UEFN Redirection active and ready!" CLR_RESET "\n");
            } else {
                printf(CLR_YELLOW " [!] " CLR_WHITE "[UEFN] " CLR_GRAY "Waiting for UEFN modules to load in background..." CLR_RESET "\n");
            }

            printf(CLR_GRAY " [----------------------------------------]" CLR_RESET "\n");
            printf(CLR_WHITE " [+] [Init] Authy UEFN Engine initialized! Listening for Epic requests..." CLR_RESET "\n");
            printf(CLR_GRAY " [----------------------------------------]\n\n" CLR_RESET);

            // Spawn background poller to ensure late-loaded modules are hooked
            CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)BackgroundPollThread, nullptr, 0, nullptr);
        }

        void Shutdown() {
            g_ExitHooked   = false;
            g_MemLeakFixed = false;
            printf(CLR_YELLOW " [!] " CLR_WHITE "[UEFN] " CLR_GRAY "UEFN Redirection engine stopped." CLR_RESET "\n");
        }
    }
}
