#pragma once
#include "Unreal.h"
#include <Windows.h>

enum Authy__URLSet
{
	Default, // default for private servers
	Hybrid,  // redirect profile, version, and content pages to private server, otherwise use official servers
	Dev,     // redirect profile & content pages to private server, otherwise use official servers
	All,     // redirect every request to private server
};

enum class Authy__RedType
{
	Fortnite,
	UEFN
};

namespace Authy
{
	namespace Options
	{
		// -----------------------------------------------------------------------
		// All globals use POD types only — safe to have as DLL statics.
		// std::string/std::wstring constructors must NOT run during loader lock.
		// -----------------------------------------------------------------------
		constexpr const char*    kDefaultBackend  = "http://127.0.0.1:5595";
		constexpr const wchar_t* kDefaultBackendW = L"http://127.0.0.1:5595";

		inline bool Console         = true;
		inline auto URLSet          = Authy__URLSet::Default;
		inline bool bHasPushWidget  = false;
		inline bool ManualMapping   = false;
		inline bool FixMemLeak      = true;
		inline Authy__RedType RedType = Authy__RedType::Fortnite;
		inline bool Initialized     = false;

		// Plain char buffers — zero-initialised, constructor-free.
		inline char    BackendA_buf[512] = {};
		inline wchar_t Backend_buf[512]  = {};

		// String-view helpers so callers can still write BackendA.c_str() etc.
		// These are thin wrappers around the buffers, not heap strings.
		struct _BackendProxy {
			const char* c_str()    const { return BackendA_buf; }
			operator const char*() const { return BackendA_buf; }
		} inline BackendA;

		struct _BackendWProxy {
			const wchar_t* c_str()    const { return Backend_buf; }
			operator const wchar_t*() const { return Backend_buf; }
		} inline Backend;

		// -----------------------------------------------------------------------
		// Helpers (only called from ParseCommandLine, inside a thread)
		// -----------------------------------------------------------------------
		namespace _detail
		{
			inline void WTrimInPlace(wchar_t* s, int len)
			{
				if (!s || len <= 0) return;
				int start = 0, end = len - 1;
				while (start <= end && (s[start]==L' '||s[start]==L'"'||s[start]==L'\'')) start++;
				while (end >= start && (s[end]==L' '||s[end]==L'"'||s[end]==L'\'')) end--;
				int newLen = end - start + 1;
				if (start > 0) memmove(s, s+start, newLen*sizeof(wchar_t));
				s[newLen] = L'\0';
			}

			inline void ATrimInPlace(char* s, int len)
			{
				if (!s || len <= 0) return;
				int start = 0, end = len - 1;
				while (start <= end && (s[start]==' ' || s[start]=='\t' || s[start]=='\r' || s[start]=='\n' || s[start]=='"' || s[start]=='\'')) start++;
				while (end >= start && (s[end]==' ' || s[end]=='\t' || s[end]=='\r' || s[end]=='\n' || s[end]=='"' || s[end]=='\'')) end--;
				int newLen = end - start + 1;
				if (start > 0) memmove(s, s+start, newLen);
				s[newLen] = '\0';
			}

			// Returns pointer to first char after prefix in haystack, or nullptr.
			inline wchar_t* FindParam(const wchar_t* haystack, const wchar_t* prefix)
			{
				const wchar_t* p = wcsstr(haystack, prefix);
				return p ? const_cast<wchar_t*>(p + wcslen(prefix)) : nullptr;
			}

			// Copy value token (up to next space or end) into dst[dstCap].
			// Returns actual length written (without NUL).
			inline int ExtractToken(const wchar_t* src, wchar_t* dst, int dstCap)
			{
				if (!src || !dst || dstCap <= 0) return 0;
				int i = 0;
				while (src[i] && src[i] != L' ' && i < dstCap - 1)
				{ dst[i] = src[i]; i++; }
				dst[i] = L'\0';
				WTrimInPlace(dst, i);
				return (int)wcslen(dst);
			}

			inline bool ParseBool(const wchar_t* s, bool def)
			{
				if (!s) return def;
				if (_wcsicmp(s, L"true")==0 || s[0]==L'1') return true;
				if (_wcsicmp(s, L"false")==0 || s[0]==L'0') return false;
				return def;
			}

			inline bool ParseBoolA(const char* s, bool def)
			{
				if (!s) return def;
				if (_stricmp(s, "true")==0 || s[0]=='1') return true;
				if (_stricmp(s, "false")==0 || s[0]=='0') return false;
				return def;
			}

			// Simple JSON key-value extraction for flat string/bool values
			inline bool GetJsonKeyValue(const char* json, const char* key, char* outVal, int outCap)
			{
				if (!json || !key || !outVal || outCap <= 0) return false;
				char pattern[128];
				wsprintfA(pattern, "\"%s\"", key);
				const char* p = strstr(json, pattern);
				if (!p) return false;

				p += strlen(pattern);
				while (*p && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n' || *p == ':')) p++;
				if (!*p) return false;

				int idx = 0;
				if (*p == '"') // string value
				{
					p++;
					while (*p && *p != '"' && idx < outCap - 1)
					{
						outVal[idx++] = *p++;
					}
				}
				else // bool / number / unquoted value
				{
					while (*p && *p != ',' && *p != '}' && *p != '\r' && *p != '\n' && idx < outCap - 1)
					{
						outVal[idx++] = *p++;
					}
				}
				outVal[idx] = '\0';
				ATrimInPlace(outVal, idx);
				return true;
			}

			inline void LoadConfigJson()
			{
				HMODULE hMod = NULL;
				// Get handle to current module where this code lives
				GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
					(LPCWSTR)&LoadConfigJson, &hMod);

				wchar_t configPath[MAX_PATH] = {};
				if (GetModuleFileNameW(hMod, configPath, MAX_PATH) == 0) return;

				wchar_t* lastSlash = wcsrchr(configPath, L'\\');
				if (!lastSlash) lastSlash = wcsrchr(configPath, L'/');
				if (!lastSlash) return;

				*(lastSlash + 1) = L'\0';
				wcscat_s(configPath, MAX_PATH, L"config.json");

				HANDLE hFile = CreateFileW(configPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
				if (hFile == INVALID_HANDLE_VALUE) return;

				DWORD fileSize = GetFileSize(hFile, NULL);
				if (fileSize > 0 && fileSize < 65536)
				{
					char* buffer = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, fileSize + 1);
					if (buffer)
					{
						DWORD bytesRead = 0;
						if (ReadFile(hFile, buffer, fileSize, &bytesRead, NULL) && bytesRead > 0)
						{
							buffer[bytesRead] = '\0';

							char val[512] = {};

							// backend
							if (GetJsonKeyValue(buffer, "backend", val, sizeof(val)) || GetJsonKeyValue(buffer, "Backend", val, sizeof(val)))
							{
								if (val[0] != '\0')
								{
									char fullUrl[512];
									if (!strstr(val, "://"))
									{
										strcpy_s(fullUrl, "http://");
										strcat_s(fullUrl, val);
									}
									else
									{
										strcpy_s(fullUrl, val);
									}
									strncpy_s(BackendA_buf, sizeof(BackendA_buf), fullUrl, _TRUNCATE);
									MultiByteToWideChar(CP_ACP, 0, fullUrl, -1, Backend_buf, 512);
								}
							}

							// console
							if (GetJsonKeyValue(buffer, "console", val, sizeof(val)) || GetJsonKeyValue(buffer, "Console", val, sizeof(val)))
							{
								Console = ParseBoolA(val, Console);
							}

							// pushWidget
							if (GetJsonKeyValue(buffer, "pushWidget", val, sizeof(val)) || GetJsonKeyValue(buffer, "pushwidget", val, sizeof(val)) || GetJsonKeyValue(buffer, "bHasPushWidget", val, sizeof(val)))
							{
								bHasPushWidget = ParseBoolA(val, bHasPushWidget);
							}

							// manualMapping
							if (GetJsonKeyValue(buffer, "manualMapping", val, sizeof(val)) || GetJsonKeyValue(buffer, "manualmapping", val, sizeof(val)) || GetJsonKeyValue(buffer, "ManualMapping", val, sizeof(val)))
							{
								ManualMapping = ParseBoolA(val, ManualMapping);
							}

							// fixMemLeak
							if (GetJsonKeyValue(buffer, "fixMemLeak", val, sizeof(val)) || GetJsonKeyValue(buffer, "fixmemleak", val, sizeof(val)) || GetJsonKeyValue(buffer, "FixMemLeak", val, sizeof(val)))
							{
								FixMemLeak = ParseBoolA(val, FixMemLeak);
							}

							// redType / redirectionType
							if (GetJsonKeyValue(buffer, "redType", val, sizeof(val)) || GetJsonKeyValue(buffer, "redtype", val, sizeof(val)) || GetJsonKeyValue(buffer, "RedType", val, sizeof(val)))
							{
								RedType = (_stricmp(val, "UEFN") == 0) ? Authy__RedType::UEFN : Authy__RedType::Fortnite;
							}
						}
						HeapFree(GetProcessHeap(), 0, buffer);
					}
				}
				CloseHandle(hFile);
			}
		} // _detail

		// -----------------------------------------------------------------------
		// ParseCommandLine — call once from your worker thread (not DllMain)
		// -----------------------------------------------------------------------
		inline void ParseCommandLine()
		{
			if (Initialized) return;
			Initialized = true;

			// 1. Seed buffers with defaults first
			strncpy_s(BackendA_buf, sizeof(BackendA_buf), kDefaultBackend,  _TRUNCATE);
			wcsncpy_s(Backend_buf,  512,                  kDefaultBackendW, _TRUNCATE);

			// 2. Load config.json next to the DLL (if it exists)
			_detail::LoadConfigJson();

			// 3. Command line parameters override config.json values
			LPCWSTR cmdLine = GetCommandLineW();
			if (!cmdLine) return;

			wchar_t tok[512];

			// --console=true/false
			{
				wchar_t* v = _detail::FindParam(cmdLine, L"--console=");
				if (v && _detail::ExtractToken(v, tok, 512))
					Console = _detail::ParseBool(tok, Console);
			}

			// --backend=<url>  or  -backend=<url>
			{
				wchar_t* v = _detail::FindParam(cmdLine, L"--backend=");
				if (!v) v = _detail::FindParam(cmdLine, L"-backend=");
				if (v && _detail::ExtractToken(v, tok, 512))
				{
					// Prepend http:// if no scheme
					if (!wcsstr(tok, L"://"))
					{
						wchar_t tmp[512]; wcscpy_s(tmp, L"http://"); wcscat_s(tmp, tok); wcscpy_s(tok, tmp);
					}
					wcsncpy_s(Backend_buf, 512, tok, _TRUNCATE);
					// Narrow copy
					WideCharToMultiByte(CP_ACP, 0, tok, -1, BackendA_buf, (int)sizeof(BackendA_buf), nullptr, nullptr);
				}
			}

			// --pushWidget=true/false
			{
				wchar_t* v = _detail::FindParam(cmdLine, L"--pushWidget=");
				if (!v) v = _detail::FindParam(cmdLine, L"--pushwidget=");
				if (v && _detail::ExtractToken(v, tok, 512))
					bHasPushWidget = _detail::ParseBool(tok, bHasPushWidget);
			}

			// --manual-mapping=true/false
			{
				wchar_t* v = _detail::FindParam(cmdLine, L"--manual-mapping=");
				if (!v) v = _detail::FindParam(cmdLine, L"--manualmapping=");
				if (v && _detail::ExtractToken(v, tok, 512))
					ManualMapping = _detail::ParseBool(tok, ManualMapping);
			}

			// --fix-memleaks=true/false
			{
				wchar_t* v = _detail::FindParam(cmdLine, L"--fix-memleaks=");
				if (!v) v = _detail::FindParam(cmdLine, L"--fixmemleaks=");
				if (v && _detail::ExtractToken(v, tok, 512))
					FixMemLeak = _detail::ParseBool(tok, FixMemLeak);
			}

			// Auto-detect UEFN if not explicitly set in config.json
			if (cmdLine)
			{
				if (wcsstr(cmdLine, L"UnrealEditorFortnite") || wcsstr(cmdLine, L".uproject"))
				{
					RedType = Authy__RedType::UEFN;
				}
			}

			// --red-type=Fortnite/UEFN (CLI overrides auto-detection and config.json)
			{
				wchar_t* v = _detail::FindParam(cmdLine, L"--red-type=");
				if (!v) v = _detail::FindParam(cmdLine, L"--redtype=");
				if (v && _detail::ExtractToken(v, tok, 512))
					RedType = (_wcsicmp(tok, L"UEFN")==0) ? Authy__RedType::UEFN : Authy__RedType::Fortnite;
			}
		}
	}
}

// Global convenience aliases maintaining compatibility across codebase
using Authy::Options::Console;
using Authy::Options::URLSet;
using Authy::Options::bHasPushWidget;
using Authy::Options::ManualMapping;
using Authy::Options::FixMemLeak;
using Authy::Options::RedType;
