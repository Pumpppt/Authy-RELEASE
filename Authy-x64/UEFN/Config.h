// Config.h - UEFN Configuration Bridge
// All settings driven by Authy::Options (command-line args parsed at runtime).
// No std::string/std::wstring here — all types are POD or references to POD.
#pragma once

#include "../Fortnite/Options.h"
#include <cstdio>
#include <cstdarg>

namespace Config
{
    // -------------------------------------------------------------------------
    // Initialise on first use — safe to call multiple times.
    // Must be called from a thread, NOT from DllMain directly.
    // -------------------------------------------------------------------------
    inline void EnsureInit()
    {
        Authy::Options::ParseCommandLine();
    }

    // -------------------------------------------------------------------------
    // Backend URL — returns the char buffer directly (no heap allocation).
    // Callers can do: Config::BackendA()  -> const char*
    //                 Config::BackendW()  -> const wchar_t*
    // -------------------------------------------------------------------------
    inline const char*    BackendA() { return Authy::Options::BackendA_buf; }
    inline const wchar_t* BackendW() { return Authy::Options::Backend_buf; }

    // -------------------------------------------------------------------------
    // Feature flags
    // -------------------------------------------------------------------------
    inline bool& FixMemLeak = Authy::Options::FixMemLeak;
    inline bool& Console    = Authy::Options::Console;
    inline bool& AntiExit   = Authy::Options::bHasPushWidget;

    // -------------------------------------------------------------------------
    // Logging helpers
    // -------------------------------------------------------------------------
    inline void Log(const char* tag, const char* fmt, ...)
    {
        if (!Authy::Options::Console) return;
        va_list args;
        va_start(args, fmt);
        printf("[%s] ", tag);
        vprintf(fmt, args);
        va_end(args);
    }

    inline void LogUEFN(const char* fmt, ...)
    {
        if (!Authy::Options::Console) return;
        va_list args;
        va_start(args, fmt);
        vprintf(fmt, args);
        va_end(args);
    }
}
