#include "DLLMainHook.h"

#include "HookedDXGI.h"
#include "D3D11Wrapper.h"
#include "util_min.h"
#include "globals.h"

HINSTANCE migoto_handle;

//===========================================================================
typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWCH   Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING* PUNICODE_STRING;
//===========================================================================
typedef struct _PEB_LDR_DATA
{
	ULONG           Length;
	BOOLEAN         Initialized;
	PVOID           SsHandle;
	LIST_ENTRY      InLoadOrderModuleList;
	LIST_ENTRY      InMemoryOrderModuleList;
	LIST_ENTRY      InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;
//===========================================================================
typedef struct _LDR_MODULE
{
	LIST_ENTRY      InLoadOrderModuleList;
	LIST_ENTRY      InMemoryOrderModuleList;
	LIST_ENTRY      InInitializationOrderModuleList;
	PVOID           BaseAddress;
	PVOID           EntryPoint;
	ULONG           SizeOfImage;
	UNICODE_STRING  FullDllName;
	UNICODE_STRING  BaseDllName;
	ULONG           Flags;
	SHORT           LoadCount;
	SHORT           TlsIndex;
	LIST_ENTRY      HashTableEntry;
	ULONG           TimeDateStamp;
} LDR_MODULE, * PLDR_MODULE;
//===========================================================================

void UnlinkModule(void* Module)
{
	DWORD dwPEB = 0, dwOffset = 0;
	PLIST_ENTRY pUserModuleHead = NULL, pUserModule = NULL;
	PPEB_LDR_DATA pLdrData;
	PLDR_MODULE pLdrModule = NULL;
	void* ModuleBase = NULL;
	int i = 0, n = 0;
#ifndef _WIN64
	_asm
	{
		pushad
		mov eax, fs: [48]
		mov dwPEB, eax
		popad
	}

	pLdrData = (PPEB_LDR_DATA)(PDWORD)(*(PDWORD)(dwPEB + 12));
#else
	BYTE* _teb = (BYTE*)__readgsqword(0x30);
	pLdrData = (PPEB_LDR_DATA)(PULONGLONG)(*(PULONGLONG)((*(PULONGLONG)(_teb + 0x60)) + 0x18));
#endif  

	for (; i < 3; i++)
	{
		switch (i)
		{
		case 0:
			pUserModuleHead = (PLIST_ENTRY)(&(pLdrData->InLoadOrderModuleList));
			pUserModule = (PLIST_ENTRY)(&(pLdrData->InLoadOrderModuleList));
			dwOffset = 0;
			break;

		case 1:
			pUserModuleHead = (PLIST_ENTRY)(&(pLdrData->InMemoryOrderModuleList));
			pUserModule = (PLIST_ENTRY)(&(pLdrData->InMemoryOrderModuleList));
#ifndef _WIN64
			dwOffset = 8;
#else
			dwOffset = 16;
#endif
			break;
		case 2:
			pUserModuleHead = pUserModule = (PLIST_ENTRY)(&(pLdrData->InInitializationOrderModuleList));
#ifndef _WIN64
			dwOffset = 16;
#else
			dwOffset = 32;
#endif
			break;
		}
		while (pUserModule->Flink != pUserModuleHead)
		{
			pUserModule = pUserModule->Flink;
#ifndef _WIN64
			ModuleBase = *(void**)(((DWORD)(pUserModule)) + (24 - dwOffset));
#else
			ModuleBase = *(void**)(((LONGLONG)(pUserModule)) + (48 - dwOffset));
#endif          
			if (ModuleBase == Module)
			{
#ifndef _WIN64
				if (!pLdrModule)
					pLdrModule = (PLDR_MODULE)(((DWORD)(pUserModule)) - dwOffset);
#else
				if (!pLdrModule)
					pLdrModule = (PLDR_MODULE)(((LONGLONG)(pUserModule)) - dwOffset);
#endif              
				pUserModule->Blink->Flink = pUserModule->Flink;
				pUserModule->Flink->Blink = pUserModule->Blink;
			}
		}
	}
	// Unlink from LdrpHashTable
	if (pLdrModule)
	{
		pLdrModule->HashTableEntry.Blink->Flink = pLdrModule->HashTableEntry.Flink;
		pLdrModule->HashTableEntry.Flink->Blink = pLdrModule->HashTableEntry.Blink;
	}
}

//===========================================================================
void RemovePeHeader(HANDLE GetModuleBase)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)GetModuleBase;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((PBYTE)pDosHeader + (DWORD)pDosHeader->e_lfanew);

	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
		return;

	if (pNTHeader->FileHeader.SizeOfOptionalHeader)
	{
		DWORD Protect;
		WORD Size = pNTHeader->FileHeader.SizeOfOptionalHeader;
		VirtualProtect((void*)GetModuleBase, Size, PAGE_EXECUTE_READWRITE, &Protect);
		RtlZeroMemory((void*)GetModuleBase, Size);
		VirtualProtect((void*)GetModuleBase, Size, Protect, &Protect);
	}
}
//===========================================================================



// ----------------------------------------------------------------------------
// Add in Deviare in-proc for hooking system traps using a Detours approach.  We need access to the
// LoadLibrary call to fix the problem of nvapi.dll bypassing our local patches to the d3d11, when
// it does GetSystemDirectory to get System32, and directly access ..\System32\d3d11.dll
// If we get a failure, we'll just log it, it's not fatal.
//
// Pretty sure this is safe at DLLMain, because we are only accessing kernel32 stuff which is sure
// to be loaded.
//
// It's important to note this will be called from DLLMain, where there are a
// lot of restrictions on what can be called here.  Avoid everything possible.
// Anything that might change the load order of the dlls will make it crash or hang.
//
// Specifically- we cannot legally call LoadLibrary here.
// For libraries we need at DLLMain load time, they need to be linked to the
// d3d11.dll directly using the appropriate .lib file.
// ----------------------------------------------------------------------------


// Used for other hooking. extern in the .h file.
// Only one instance of CNktHookLib is allowed for a given process.
// Automatically instantiated by C++
CNktHookLib cHookMgr;

// ----------------------------------------------------------------------------
// Use this logging when at DLLMain which is too early to do anything with the file system.
#if _DEBUG
bool bLog = true;
#else
bool bLog = false;
#endif

// Special logging for this strange moment at runtime.
// We cannot log to our normal file, because this is too early, in DLLMain.
// Nektra provides a safe log though, so we will use this when debugging.

static void LogHooking(char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);

	if (bLog)
		NktHookLibHelpers::DebugVPrint(fmt, ap);

	va_end(ap);
}


// ----------------------------------------------------------------------------
static HRESULT InstallHookDLLMain(LPCWSTR moduleName, char *func, void **trampoline, void *hook)
{
	HINSTANCE module;
	SIZE_T hook_id;
	DWORD dwOsErr;
	void *fnOrig;

	module = NktHookLibHelpers::GetModuleBaseAddress(moduleName);
	if (module == NULL)
	{
		LogHooking("*** Failed to GetModuleBaseAddress for %s\n", moduleName);
		return E_FAIL;
	}

	fnOrig = NktHookLibHelpers::GetProcedureAddress(module, func);
	if (fnOrig == NULL) {
		LogHooking("*** Failed to get address of %s\n", func);
		return E_FAIL;
	}

	dwOsErr = cHookMgr.Hook(&hook_id, trampoline, fnOrig, hook);
	if (dwOsErr != ERROR_SUCCESS) {
		LogHooking("*** Failed to hook %s: 0x%x\n", func, dwOsErr);
		return E_FAIL;
	}

	return NOERROR;
}


// ----------------------------------------------------------------------------
// Only ExW version for now, used by nvapi.
// Safe: Kernel32.dll known to be linked directly to our d3d11.dll

static HRESULT HookLoadLibraryExW()
{
	HRESULT hr = InstallHookDLLMain(L"Kernel32.dll", "LoadLibraryExW", (LPVOID*)&fnOrigLoadLibraryExW, Hooked_LoadLibraryExW);
	if (FAILED(hr))
		return E_FAIL;

	return NOERROR;
}


// ----------------------------------------------------------------------------
// Object			OS				DXGI version	Feature level
// IDXGIFactory		Win7			1.0				11.0
// IDXGIFactory1	Win7			1.0				11.0
// IDXGIFactory2	Platform update	1.2				11.1
// IDXGIFactory3	Win8.1			1.3
// IDXGIFactory4					1.4
// IDXGIFactory5					1.5
//
// IDXGIFactory2 is *not* exported until Win8.1 DLLs, and is specifically
// not part of a Win7 platform_update runtime.

static HRESULT HookDXGIFactories()
{
	HRESULT hr;

	hr = InstallHookDLLMain(L"dxgi.dll", "CreateDXGIFactory", (LPVOID*)&fnOrigCreateDXGIFactory, Hooked_CreateDXGIFactory);
	if (FAILED(hr))
		return E_FAIL;

	hr = InstallHookDLLMain(L"dxgi.dll", "CreateDXGIFactory1", (LPVOID*)&fnOrigCreateDXGIFactory1, Hooked_CreateDXGIFactory1);
	if (FAILED(hr))
		return E_FAIL;

	// We do not care if this fails - this function does not exist on Win7
	InstallHookDLLMain(L"dxgi.dll", "CreateDXGIFactory2", (LPVOID*)&fnOrigCreateDXGIFactory2, Hooked_CreateDXGIFactory2);

	return NOERROR;
}

static HRESULT HookD3D11(HINSTANCE our_dll)
{
	HRESULT hr;

	LogHooking("Hooking d3d11.dll...\n");

	// TODO: What if d3d11.dll isn't loaded in the process yet? We can't
	// use LoadLibrary() from DllMain. Does Nektra handle this somehow, or
	// should we defer the hook until later (perhaps our LoadLibrary hook)?

	hr = InstallHookDLLMain(L"d3d11.dll", "D3D11CreateDevice",
			(LPVOID*)&_D3D11CreateDevice, D3D11CreateDevice);
	if (FAILED(hr))
		return E_FAIL;

	// Directly using D3D11CreateDeviceAndSwapChain was giving an
	// unresolved external - looks like the function signature doesn't
	// quite match the prototype in the Win 10 SDK. Whatever - it's
	// compatible, so just use GetProcAddress() rather than fight it.
	hr = InstallHookDLLMain(L"d3d11.dll", "D3D11CreateDeviceAndSwapChain",
			(LPVOID*)&_D3D11CreateDeviceAndSwapChain,
			GetProcAddress(our_dll, "D3D11CreateDeviceAndSwapChain"));
	if (FAILED(hr))
		return E_FAIL;

	return S_OK;
}


// ----------------------------------------------------------------------------
static void RemoveHooks()
{
	cHookMgr.UnhookAll();
}

// ----------------------------------------------------------------------------

static bool verify_intended_target(HINSTANCE our_dll)
{
	//Nico:变量必须提前初始化，否则goto 语句会导致无法编译，报错
	//这就是为什么3Dmigoto的东西都是提前初始化的
	std::string magicValue;

	wchar_t our_path[MAX_PATH], exe_path[MAX_PATH];
	wchar_t *our_basename, *exe_basename;
	DWORD filesize, readsize;
	bool rc = false;
	char *buf;
	const char *section;
	char target[MAX_PATH];
	wchar_t target_w[MAX_PATH];
	size_t target_len, exe_len;
	HANDLE f;

	if (!GetModuleFileName(our_dll, our_path, MAX_PATH))
		return false;
	if (!GetModuleFileName(NULL, exe_path, MAX_PATH))
		return false;

	our_basename = wcsrchr(our_path, L'\\');
	exe_basename = wcsrchr(exe_path, L'\\');
	if (!our_basename || !exe_basename)
		return false;

	*(our_basename++) = L'\0';
	*(exe_basename++) = L'\0';

	// If our DLL is located in the same directory as the exe than we are
	// either in the common case where are being loaded out of the game
	// directory, or this is the instance of the DLL loaded into the
	// injector app, and we are okay with being loaded.
	if (!_wcsicmp(our_path, exe_path))
		return true;

	LogHooking("3DMigoto loaded from outside game directory\n"
	           "Exe directory: \"%S\" basename: \"%S\"\n"
	           "Our directory: \"%S\" basename: \"%S\"\n",
		   exe_path, exe_basename, our_path, our_basename);

	// Restore the path separator so we can include game directories in the
	// comparison in the event that the game's executable name is too
	// generic to match by itself:
	*(exe_basename-1) = L'\\';

	// Check if we are being loaded as the profile helper. In this case we
	// are loaded via rundll32, so we are not going to be in the same
	// directory as the exe and the above check will have failed, but we
	// also don't want to blanket pass rundll32 since the injector approach
	// could get us into unrelated rundlls the same as anything else.
	// For this case we will check if the command line contains our profile
	// helper entry point. We won't bother with any further checks if it
	// doesn't match, because the profile helper is the only reason we
	// would ever want to be running inside rundll.
	if (!_wcsicmp(exe_basename, L"rundll32.exe"))
		return !!wcsstr(GetCommandLine(), L",Install3DMigotoDriverProfile ");

	// Otherwise we are being loaded into some random task, and we need to
	// filter ourselves out of any tasks that are not the intended target
	// so that we don't cause any unintended side effects, and so that our
	// DLL doesn't get locked by random tasks making it a pain to update
	// during development, or for an end user to delete.
	//
	// To check if we are the intended task we are going to open the
	// d3dx.ini in the directory where our DLL is located (i.e. the one
	// shipped with the injector), find the [Loader] section and locate
	// the target setting to verify that it matches this executable.
	//
	// We need to be careful not to do anything that could trigger a
	// LoadLibrary since we are still running in DllMain, so rather than
	// use our main config load function we will use a minimal parser here
	// that restricts itself to Kernel32.dll API calls and the statically
	// linked standard library that should be fairly safe, and will be
	// faster than the main parser since we aren't populating our data
	// structures as yet, so we can bail out of unwanted targets sooner.

	wcsncat_s(our_path, MAX_PATH, L"\\d3dx.ini", _TRUNCATE);
	f = CreateFile(our_path, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (f == INVALID_HANDLE_VALUE)
		return false;

	filesize = GetFileSize(f, NULL);
	buf = new char[filesize + 1];
	if (!buf)
		goto out_close;

	if (!ReadFile(f, buf, filesize, &readsize, 0) || filesize != readsize)
		goto out_free;

	
	//Nico: 对读取的d3dx.ini的buf进行最简单的解密
	//这里如果ini文件是以NICO开头，那么我们就把它解密，否则不做任何处理
	//这里是第一处加密，第二处加密在ParseIniStream()

	
	for (int i = 0; i < 4; ++i) {
		magicValue += buf[i];
	}

	if (magicValue == "NICO") {
		char key = 'K';

		for (size_t i = 0; i < filesize + 1; ++i) {
			buf[i] = buf[i] ^ key;  // 使用异或运算对字符进行解密
		}
		// 解密结束
	}
	//else if (magicValue == "NMBT") {
	//	char key = -5;

	//	for (size_t i = 0; i < filesize + 1; ++i) {
	//		buf[i] = buf[i] ^ key;  // 使用异或运算对字符进行解密
	//	}
	//	// 解密结束
	//}




	buf[filesize] = '\0';

	section = find_ini_section_lite(buf, "loader");
	if (!section)
		goto out_free;

	if (!find_ini_setting_lite(section, "target", target, MAX_PATH))
		goto out_free;

	// Fixes some compatability issues with cultivation  writen by silent.
	int i = 0, j = 0;
	while (target[i] != '\0') {

		// Remove forward slashes
		if (target[i] == '/') {
			target[j] = '\\';
		}
		// Remove double slashes
		else if (target[i] == '\\' && target[i + 1] == '\\') {
			target[j] = '\\';
			i++;
		}
		else if (target[i] == '\"') {
			j--;
		}
		else {
			target[j] = target[i];
		}
		i++;
		j++;
	}
	target[j] = '\0';

	// Convert to UTF16 to match the Win32 API in case there are any
	// non-ASCII characters somewhere in the path:
	if (!MultiByteToWideChar(CP_UTF8, 0, target, -1, target_w, MAX_PATH))
		goto out_free;

	// If we are injecting into an application with a generic name like
	// "game.exe" we may want to check part of the directory structure as
	// well, so we will do the comparison using the end of the full
	// executable path.
	target_len = wcslen(target_w);
	exe_len = wcslen(exe_path);
	if (exe_len < target_len)
		goto out_free;

	// Unless we are matching a full path we do expect the match be
	// immediately following a directory separator, even if this was
	// not explicitly stated in the target string:
	if (target_w[0] != L'\\' && exe_len > target_len && exe_path[exe_len - target_len - 1] != L'\\')
		goto out_free;

	rc = !_wcsicmp(exe_path + exe_len - target_len, target_w);

	if (rc) {
		// Bump our refcount so we don't get unloaded if the injector
		// application exits before the game has started initialising DirectX
		HMODULE handle = NULL;
		GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
				(LPCWSTR)verify_intended_target, &handle);
	}

out_free:
	delete [] buf;
out_close:
	CloseHandle(f);
	return rc;
}


// ----------------------------------------------------------------------------
// Now doing hooking for every build, x32 and x64.  Release and Debug.
// Originally created to solve a problem Nvidia introduced by changing the
// dll search path, this is also now used for DXGI Present hooking.
//
// If we return false here, then the game will error out and not run.


DWORD tls_idx = TLS_OUT_OF_INDEXES;

BOOL WINAPI DllMain(
	_In_  HINSTANCE hinstDLL,
	_In_  DWORD fdwReason,
	_In_  LPVOID lpvReserved)
{
	switch (fdwReason)
	{
		case DLL_PROCESS_ATTACH:
			migoto_handle = hinstDLL;
			cHookMgr.SetEnableDebugOutput(bLog);

			// If we are loaded via injection we will end up in
			// every newly task in the system. We don't want that,
			// so bail early if this is not the intended target
			if (!verify_intended_target(hinstDLL))
				return false;

			// Hook d3d11.dll if we are loaded via injection either
			// under a different name, or just not as the primary
			// d3d11.dll. I'm not positive if this is the "best"
			// way to check for this, but it seems to work:
			if (hinstDLL != GetModuleHandleA("d3d11.dll"))
				HookD3D11(hinstDLL);

			

			if (FAILED(HookLoadLibraryExW()))
				return false;
			if (FAILED(HookDXGIFactories()))
				return false;

			//DisableThreadLibraryCalls(hinstDLL);
			//RemovePeHeader(hinstDLL);
			//UnlinkModule((void*)hinstDLL);

			tls_idx = TlsAlloc();
			if (tls_idx == TLS_OUT_OF_INDEXES)
				return false;

			break;

		case DLL_PROCESS_DETACH:
			RemoveHooks();
			if (tls_idx != TLS_OUT_OF_INDEXES) {
				// FIXME: If we are being dynamically unloaded
				// (lpvReserved == NULL), we should delete the
				// TLS structure from all other threads, but we
				// don't have an easy way to get that at the
				// moment. On program termination (lpvReserved
				// != NULL) we are not permitted to do that, so
				// for now just release the TLS structure from
				// the current thread (if allocated) and
				// release the TLS index allocated for the DLL.
				delete TlsGetValue(tls_idx);
				TlsFree(tls_idx);
			}
			DestroyDLL();
			break;

		case DLL_THREAD_ATTACH:
			// Do thread-specific initialization.

			// We could allocate a TLS structure here, but why
			// bother? This isn't called for threads that already
			// exist when we were attached and get_tls() will
			// allocate the structure on demand as needed.

			break;

		case DLL_THREAD_DETACH:
			// Do thread-specific cleanup.
			delete TlsGetValue(tls_idx);
			break;
	}

	return true;
}
