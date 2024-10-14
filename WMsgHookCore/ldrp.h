#pragma once
#include <winnt.h>
#include <WTypesbase.h>
//#include <winternl.h>

// Kernels | x64 | Windows 10 | 2016 | 2210 22H2(May 2023 Update)

//0x18 bytes (sizeof)
typedef struct _RTL_BALANCED_NODE
{
    union
    {
        _RTL_BALANCED_NODE* Children[2];                             //0x0
        struct
        {
            _RTL_BALANCED_NODE* Left;                                //0x0
            _RTL_BALANCED_NODE* Right;                               //0x8
        };
    };
    union
    {
        struct
        {
            UCHAR Red : 1;                                                    //0x10
            UCHAR Balance : 2;                                                //0x10
        };
        ULONGLONG ParentValue;                                                //0x10
    };
}RTL_BALANCED_NODE, * PRTL_BALANCED_NODE, * LPRTL_BALANCED_NODE;

//0x4 bytes (sizeof)
enum _LDR_DLL_LOAD_REASON
{
    LoadReasonStaticDependency = 0,
    LoadReasonStaticForwarderDependency = 1,
    LoadReasonDynamicForwarderDependency = 2,
    LoadReasonDelayloadDependency = 3,
    LoadReasonDynamicLoad = 4,
    LoadReasonAsImageLoad = 5,
    LoadReasonAsDataLoad = 6,
    LoadReasonEnclavePrimary = 7,
    LoadReasonEnclaveDependency = 8,
    LoadReasonUnknown = -1
};

typedef _LDR_DLL_LOAD_REASON    LDR_DLL_LOAD_REASON;

//0x10 bytes (sizeof)
typedef struct _LDR_SERVICE_TAG_RECORD
{
    _LDR_SERVICE_TAG_RECORD* Next;                                           //0x0
    ULONG ServiceTag;                                                       //0x8
}LDR_SERVICE_TAG_RECORD, * PLDR_SERVICE_TAG_RECORD;

//0x8 bytes (sizeof)
typedef struct _LDRP_CSLIST
{
    SINGLE_LIST_ENTRY* Tail;                                                //0x0
}LDRP_CSLIST;

//0x4 bytes (sizeof)
enum _LDR_DDAG_STATE
{
    LdrModulesMerged = -5,
    LdrModulesInitError = -4,
    LdrModulesSnapError = -3,
    LdrModulesUnloaded = -2,
    LdrModulesUnloading = -1,
    LdrModulesPlaceHolder = 0,
    LdrModulesMapping = 1,
    LdrModulesMapped = 2,
    LdrModulesWaitingForDependencies = 3,
    LdrModulesSnapping = 4,
    LdrModulesSnapped = 5,
    LdrModulesCondensed = 6,
    LdrModulesReadyToInit = 7,
    LdrModulesInitializing = 8,
    LdrModulesReadyToRun = 9
};

typedef _LDR_DDAG_STATE   LDR_DDAG_STATE;

//0x50 bytes (sizeof)
typedef struct _LDR_DDAG_NODE
{
    LIST_ENTRY Modules;                                                     //0x0
    PLDR_SERVICE_TAG_RECORD ServiceTagList;                                 //0x10
    ULONG LoadCount;                                                        //0x18
    ULONG LoadWhileUnloadingCount;                                          //0x1c
    ULONG LowestLink;                                                       //0x20
    LDRP_CSLIST Dependencies;                                               //0x28
    LDRP_CSLIST IncomingDependencies;                                       //0x30
    LDR_DDAG_STATE State;                                                   //0x38
    SINGLE_LIST_ENTRY CondenseLink;                                         //0x40
    ULONG PreorderNumber;                                                   //0x48
}LDR_DDAG_NODE, * PLDR_DDAG_NODE;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING* PUNICODE_STRING;
typedef const UNICODE_STRING* PCUNICODE_STRING;

//0x120 bytes (sizeof)
typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;                                            //0x0
    LIST_ENTRY InMemoryOrderLinks;                                          //0x10
    LIST_ENTRY InInitializationOrderLinks;                                  //0x20
    VOID* DllBase;                                                          //0x30
    VOID* EntryPoint;                                                       //0x38
    ULONG SizeOfImage;                                                      //0x40
    UNICODE_STRING FullDllName;                                             //0x48
    UNICODE_STRING BaseDllName;                                             //0x58
    union
    {
        UCHAR FlagGroup[4];                                                 //0x68
        ULONG Flags;                                                        //0x68
        struct
        {
            ULONG PackagedBinary : 1;                                         //0x68
            ULONG MarkedForRemoval : 1;                                       //0x68
            ULONG ImageDll : 1;                                               //0x68
            ULONG LoadNotificationsSent : 1;                                  //0x68
            ULONG TelemetryEntryProcessed : 1;                                //0x68
            ULONG ProcessStaticImport : 1;                                    //0x68
            ULONG InLegacyLists : 1;                                          //0x68
            ULONG InIndexes : 1;                                              //0x68
            ULONG ShimDll : 1;                                                //0x68
            ULONG InExceptionTable : 1;                                       //0x68
            ULONG ReservedFlags1 : 2;                                         //0x68
            ULONG LoadInProgress : 1;                                         //0x68
            ULONG LoadConfigProcessed : 1;                                    //0x68
            ULONG EntryProcessed : 1;                                         //0x68
            ULONG ProtectDelayLoad : 1;                                       //0x68
            ULONG ReservedFlags3 : 2;                                         //0x68
            ULONG DontCallForThreads : 1;                                     //0x68
            ULONG ProcessAttachCalled : 1;                                    //0x68
            ULONG ProcessAttachFailed : 1;                                    //0x68
            ULONG CorDeferredValidate : 1;                                    //0x68
            ULONG CorImage : 1;                                               //0x68
            ULONG DontRelocate : 1;                                           //0x68
            ULONG CorILOnly : 1;                                              //0x68
            ULONG ChpeImage : 1;                                              //0x68
            ULONG ReservedFlags5 : 2;                                         //0x68
            ULONG Redirected : 1;                                             //0x68
            ULONG ReservedFlags6 : 2;                                         //0x68
            ULONG CompatDatabaseProcessed : 1;                                //0x68
        }uFlags;
    };
    USHORT ObsoleteLoadCount;                                               //0x6c
    USHORT TlsIndex;                                                        //0x6e
    LIST_ENTRY HashLinks;                                                   //0x70
    ULONG TimeDateStamp;                                                    //0x80
    struct ACTIVATION_CONTEXT* EntryPointActivationContext;                 //0x88
    VOID* Lock;                                                             //0x90
    LDR_DDAG_NODE* DdagNode;                                                //0x98
    LIST_ENTRY NodeModuleLink;                                              //0xa0
    struct LDRP_LOAD_CONTEXT* LoadContext;                                  //0xb0
    VOID* ParentDllBase;                                                    //0xb8
    VOID* SwitchBackContext;                                                //0xc0
    RTL_BALANCED_NODE BaseAddressIndexNode;                                 //0xc8
    RTL_BALANCED_NODE MappingInfoIndexNode;                                 //0xe0
    ULONGLONG OriginalBase;                                                 //0xf8
    LARGE_INTEGER LoadTime;                                                 //0x100
    ULONG BaseNameHashValue;                                                //0x108
    LDR_DLL_LOAD_REASON LoadReason;                                         //0x10c
    ULONG ImplicitPathOptions;                                              //0x110
    ULONG ReferenceCount;                                                   //0x114
    ULONG DependentLoadFlags;                                               //0x118
    UCHAR SigningLevel;                                                     //0x11c
}LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;


//0x58 bytes (sizeof)
typedef struct _PEB_LDR_DATA32
{
    ULONG Length; // +0x00
    BOOLEAN Initialized; // +0x04
    PVOID SsHandle; // +0x08
    LIST_ENTRY InLoadOrderModuleList; // +0x0c
    LIST_ENTRY InMemoryOrderModuleList; // +0x14
    LIST_ENTRY InInitializationOrderModuleList;// +0x1c
} PEB_LDR_DATA32, * PPEB_LDR_DATA32; // +0x24


typedef struct _PEB32
{
    UCHAR InheritedAddressSpace;                                            //0x0
    UCHAR ReadImageFileExecOptions;                                         //0x1
    UCHAR BeingDebugged;                                                    //0x2
    union
    {
        UCHAR BitField;                                                     //0x3
        struct
        {
            UCHAR ImageUsesLargePages : 1;                                    //0x3
            UCHAR IsProtectedProcess : 1;                                     //0x3
            UCHAR IsImageDynamicallyRelocated : 1;                            //0x3
            UCHAR SkipPatchingUser32Forwarders : 1;                           //0x3
            UCHAR IsPackagedProcess : 1;                                      //0x3
            UCHAR IsAppContainer : 1;                                         //0x3
            UCHAR IsProtectedProcessLight : 1;                                //0x3
            UCHAR IsLongPathAwareProcess : 1;                                 //0x3
        };
    };
    PVOID Mutant;                                                           //0x4
    PVOID ImageBaseAddress;                                                 //0x8
    PEB_LDR_DATA32* Ldr;                                                    //0xc
    struct RTL_USER_PROCESS_PARAMETERS* ProcessParameters;                  //0x10
    PVOID SubSystemData;                                                    //0x14
    PVOID ProcessHeap;                                                      //0x18
    RTL_CRITICAL_SECTION* FastPebLock;                                      //0x1c
    SLIST_HEADER* volatile AtlThunkSListPtr;                                //0x20
    PVOID IFEOKey;                                                          //0x24
} PEB32, * PPEB32;

typedef struct _STRING64
{
    USHORT Length;                                                          //0x0
    USHORT MaximumLength;                                                   //0x2
    ULONGLONG Buffer;                                                       //0x8
}STRING64, * LPSTRING64;

typedef struct _PEB_LDR_DATA64
{
    ULONG Length;                                                           //0x0
    UCHAR Initialized;                                                      //0x4
    PVOID SsHandle;                                                         //0x8
    LIST_ENTRY InLoadOrderModuleList;                                       //0x10
    LIST_ENTRY InMemoryOrderModuleList;                                     //0x20
    LIST_ENTRY InInitializationOrderModuleList;                             //0x30
    PVOID EntryInProgress;                                                  //0x40
    UCHAR ShutdownInProgress;                                               //0x48
    PVOID ShutdownThreadId;                                                 //0x50
}PEB_LDR_DATA64, * PPEB_LDR_DATA64;

typedef struct _PEB64
{
    UCHAR InheritedAddressSpace;                                            //0x0
    UCHAR ReadImageFileExecOptions;                                         //0x1
    UCHAR BeingDebugged;                                                    //0x2
    union
    {
        UCHAR BitField;                                                     //0x3
        struct
        {
            UCHAR ImageUsesLargePages : 1;                                    //0x3
            UCHAR IsProtectedProcess : 1;                                     //0x3
            UCHAR IsImageDynamicallyRelocated : 1;                            //0x3
            UCHAR SkipPatchingUser32Forwarders : 1;                           //0x3
            UCHAR IsPackagedProcess : 1;                                      //0x3
            UCHAR IsAppContainer : 1;                                         //0x3
            UCHAR IsProtectedProcessLight : 1;                                //0x3
            UCHAR IsLongPathAwareProcess : 1;                                 //0x3
        };
    };
    UCHAR Padding0[4];                                                      //0x4
    ULONGLONG Mutant;                                                       //0x8
    ULONGLONG ImageBaseAddress;                                             //0x10
    PEB_LDR_DATA64* Ldr;                                                    //0x18
    ULONGLONG ProcessParameters;                                            //0x20
    ULONGLONG SubSystemData;                                                //0x28
    ULONGLONG ProcessHeap;                                                  //0x30
    ULONGLONG FastPebLock;                                                  //0x38
    ULONGLONG AtlThunkSListPtr;                                             //0x40
    ULONGLONG IFEOKey;                                                      //0x48
}PEB64, * PPEB64;

#ifdef _WIN64
typedef PEB64                   PEB;
typedef PPEB64                  PPEB;
typedef PEB_LDR_DATA64          PEB_LDR_DATA;
typedef PPEB_LDR_DATA64         PPEB_LDR_DATA;
#else
typedef PEB32                   PEB;
typedef PPEB32                  PPEB;
typedef PEB_LDR_DATA32          PEB_LDR_DATA;
typedef PPEB_LDR_DATA32         PPEB_LDR_DATA;
#endif