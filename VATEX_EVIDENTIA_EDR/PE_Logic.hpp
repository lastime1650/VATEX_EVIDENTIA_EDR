#ifndef PE_LOGIC
#define PE_LOGIC

#include	<ntifs.h>
#include "API.hpp"

#define IMAGE_DOS_SIGNATURE 0x5A4D   // 'MZ'
#define IMAGE_NT_SIGNATURE  0x00004550 // 'PE00'
#define IMAGE_NT_OPTIONAL_HDR32_MAGIC 0x010b
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x020b
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
#define IMAGE_DIRECTORY_ENTRY_IMPORT 1

#define IMAGE_DIRECTORY_ENTRY_EXPORT 0

#define IMAGE_SUBSYSTEM_WINDOWS_GUI   2
#define IMAGE_SUBSYSTEM_WINDOWS_CUI   3

#define IMAGE_FILE_EXECUTABLE_IMAGE 0x0002
#define IMAGE_FILE_DLL 0x2000

typedef struct _IMAGE_DOS_HEADER {
    USHORT e_magic;                  // Magic number
    USHORT e_cblp;                   // Bytes on last page of file
    USHORT e_cp;                     // Pages in file
    USHORT e_crlc;                   // Relocations
    USHORT e_cparhdr;                // Size of header in paragraphs
    USHORT e_minalloc;               // Minimum extra paragraphs needed
    USHORT e_maxalloc;               // Maximum extra paragraphs needed
    USHORT e_ss;                     // Initial (relative) SS value
    USHORT e_sp;                     // Initial SP value
    USHORT e_csum;                   // Checksum
    USHORT e_ip;                     // Initial IP value
    USHORT e_cs;                     // Initial (relative) CS value
    USHORT e_lfarlc;                // File address of relocation table
    USHORT e_ovno;                   // Overlay number
    USHORT e_res[4];                 // Reserved words
    USHORT e_oemid;                  // OEM identifier
    USHORT e_oeminfo;                // OEM information
    USHORT e_res2[10];               // Reserved words
    LONG   e_lfanew;                 // File address of new exe header
} IMAGE_DOS_HEADER__, * PIMAGE_DOS_HEADER__;


#define IMAGE_SIZEOF_SHORT_NAME 8
typedef struct _IMAGE_SECTION_HEADER__ {
    CHAR    Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
        ULONG32   PhysicalAddress;
        ULONG32   VirtualSize;
    } Misc;
    ULONG32   VirtualAddress;
    ULONG32   SizeOfRawData;
    ULONG32   PointerToRawData;
    ULONG32   PointerToRelocations;
    ULONG32   PointerToLinenumbers;
    USHORT    NumberOfRelocations;
    USHORT    NumberOfLinenumbers;
    ULONG32   Characteristics;
} IMAGE_SECTION_HEADER__, * PIMAGE_SECTION_HEADER__;

typedef struct _IMAGE_FILE_HEADER {
    USHORT  Machine;                 // Machine type
    USHORT  NumberOfSections;        // Number of sections
    ULONG   TimeDateStamp;           // Time and date stamp
    ULONG   PointerToSymbolTable;    // File pointer to symbol table
    ULONG   NumberOfSymbols;         // Number of symbols
    USHORT  SizeOfOptionalHeader;    // Size of optional header
    USHORT  Characteristics;         // Characteristics
} IMAGE_FILE_HEADER__, * PIMAGE_FILE_HEADER__;

typedef struct _IMAGE_DATA_DIRECTORY {
    ULONG VirtualAddress;
    ULONG Size;
} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER32__ {
    USHORT  Magic;                   // Optional header magic
    UCHAR   MajorLinkerVersion;      // Major linker version
    UCHAR   MinorLinkerVersion;      // Minor linker version
    ULONG   SizeOfCode;             // Size of code
    ULONG   SizeOfInitializedData;  // Size of initialized data
    ULONG   SizeOfUninitializedData;// Size of uninitialized data
    ULONG   AddressOfEntryPoint;    // Address of entry point
    ULONG   BaseOfCode;             // Base of code
    ULONG   BaseOfData;             // Base of data
    ULONG   ImageBase;              // Image base address
    ULONG   SectionAlignment;       // Section alignment
    ULONG   FileAlignment;          // File alignment
    USHORT  MajorOperatingSystemVersion; // Major OS version
    USHORT  MinorOperatingSystemVersion; // Minor OS version
    USHORT  MajorImageVersion;      // Major image version
    USHORT  MinorImageVersion;      // Minor image version
    USHORT  MajorSubsystemVersion; // Major subsystem version
    USHORT  MinorSubsystemVersion; // Minor subsystem version
    ULONG   Win32VersionValue;      // Reserved
    ULONG   SizeOfImage;            // Size of image
    ULONG   SizeOfHeaders;          // Size of headers
    ULONG   CheckSum;               // Checksum
    USHORT  Subsystem;              // Subsystem
    USHORT  DllCharacteristics;     // DLL characteristics
    ULONG   SizeOfStackReserve;     // Size of stack reserve
    ULONG   SizeOfStackCommit;      // Size of stack commit
    ULONG   SizeOfHeapReserve;      // Size of heap reserve
    ULONG   SizeOfHeapCommit;       // Size of heap commit
    ULONG   LoaderFlags;            // Loader flags
    ULONG   NumberOfRvaAndSizes;    // Number of RVA and sizes
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32__, * PIMAGE_OPTIONAL_HEADER32__;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    USHORT      Magic;
    UCHAR       MajorLinkerVersion;
    UCHAR       MinorLinkerVersion;
    ULONG       SizeOfCode;
    ULONG       SizeOfInitializedData;
    ULONG       SizeOfUninitializedData;
    ULONG       AddressOfEntryPoint;
    ULONG       BaseOfCode;
    ULONGLONG   ImageBase;
    ULONG       SectionAlignment;
    ULONG       FileAlignment;
    USHORT      MajorOperatingSystemVersion;
    USHORT      MinorOperatingSystemVersion;
    USHORT      MajorImageVersion;
    USHORT      MinorImageVersion;
    USHORT      MajorSubsystemVersion;
    USHORT      MinorSubsystemVersion;
    ULONG       Win32VersionValue;
    ULONG       SizeOfImage;
    ULONG       SizeOfHeaders;
    ULONG       CheckSum;
    USHORT      Subsystem;
    USHORT      DllCharacteristics;
    ULONGLONG   SizeOfStackReserve;
    ULONGLONG   SizeOfStackCommit;
    ULONGLONG   SizeOfHeapReserve;
    ULONGLONG   SizeOfHeapCommit;
    ULONG       LoaderFlags;
    ULONG       NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64__, * PIMAGE_OPTIONAL_HEADER64__;

// 64 bit process
typedef struct _IMAGE_NT_HEADERS64__ {
    ULONG               Signature;      // PE signature
    IMAGE_FILE_HEADER__   FileHeader;     // File header
    IMAGE_OPTIONAL_HEADER64__ OptionalHeader; // Optional header
} IMAGE_NT_HEADERS64__, * PIMAGE_NT_HEADERS64__;

// 32 bit process
typedef struct _IMAGE_NT_HEADERS32__ {
    ULONG               Signature;      // PE signature
    IMAGE_FILE_HEADER__   FileHeader;     // File header
    IMAGE_OPTIONAL_HEADER32__ OptionalHeader; // Optional header
} IMAGE_NT_HEADERS32__, * PIMAGE_NT_HEADERS32__;


typedef struct _IMAGE_EXPORT_DIRECTORY {

    ULONG Characteristics;
    ULONG TimeDateStamp;

    USHORT MajorVersion;
    USHORT MinorVersion;

    ULONG Name;
    ULONG Base;

    ULONG NumberOfFunctions;
    ULONG NumberOfNames;

    ULONG AddressOfFunctions; // 함수 주소 배열(EAT)
    ULONG AddressOfNames; //함수명 배열
    ULONG AddressOfNameOrdinals; // 함수 서수 배열

} IMAGE_EXPORT_DIRECTORY, * PIMAGE_EXPORT_DIRECTORY;

typedef struct _PEB_LDR_DATA {
    CHAR       Reserved1[8];
    PVOID      Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB {
    UCHAR InheritedAddressSpace;       // 0x000
    UCHAR ReadImageFileExecOptions;    // 0x001
    UCHAR BeingDebugged;               // 0x002
    UCHAR BitField;                    // 0x003
    CHAR  Padding0[4];                 // 0x004
    void* Mutant;                      // 0x008
    void* ImageBaseAddress;            // 0x010
    struct _PEB_LDR_DATA* Ldr;         // 0x018
    void* ProcessParameters;           // 0x020
    void* SubSystemData;               // 0x028
    void* ProcessHeap;                 // 0x030
    void* FastPebLock;                 // 0x038
    void* AtlThunkSListPtr;            // 0x040
    void* IFEOKey;                     // 0x048
    UINT32 CrossProcessFlags;          // 0x050
    CHAR  Padding1[4];                 // 0x054
    void* KernelCallbackTable;         // 0x058
    UINT32 SystemReserved;             // 0x060
    UINT32 AtlThunkSListPtr32;         // 0x064
    void* ApiSetMap;                   // 0x068
    UINT32 TlsExpansionCounter;        // 0x070
    CHAR  Padding2[4];                 // 0x074
    void* TlsBitmap;                   // 0x078
    UINT32 TlsBitmapBits[2];           // 0x080
    void* ReadOnlySharedMemoryBase;    // 0x088
    void* SharedData;                  // 0x090
    void** ReadOnlyStaticServerData;   // 0x098
    void* AnsiCodePageData;            // 0x0a0
    void* OemCodePageData;             // 0x0a8
    void* UnicodeCaseTableData;        // 0x0b0
    UINT32 NumberOfProcessors;         // 0x0b8
    UINT32 NtGlobalFlag;               // 0x0bc
    CHAR  CriticalSectionTimeout[8];   // 0x0c0
    UINT64 HeapSegmentReserve;         // 0x0c8
    UINT64 HeapSegmentCommit;          // 0x0d0
    UINT64 HeapDeCommitTotalFreeThreshold; // 0x0d8
    UINT64 HeapDeCommitFreeBlockThreshold; // 0x0e0
    UINT32 NumberOfHeaps;              // 0x0e8
    UINT32 MaximumNumberOfHeaps;       // 0x0ec
    void** ProcessHeaps;               // 0x0f0
    void* GdiSharedHandleTable;        // 0x0f8
    void* ProcessStarterHelper;        // 0x100
    UINT32 GdiDCAttributeList;         // 0x108
    CHAR  Padding3[4];                 // 0x10c
    void* LoaderLock;                  // 0x110
    UINT32 OSMajorVersion;             // 0x118
    UINT32 OSMinorVersion;             // 0x11c
    UINT16 OSBuildNumber;              // 0x120
    UINT16 OSCSDVersion;               // 0x122
    UINT32 OSPlatformId;               // 0x124
    UINT32 ImageSubsystem;             // 0x128
    UINT32 ImageSubsystemMajorVersion; // 0x12c
    UINT32 ImageSubsystemMinorVersion; // 0x130
    CHAR  Padding4[4];                 // 0x134
    UINT64 ActiveProcessAffinityMask;  // 0x138
    UINT32 GdiHandleBuffer[60];        // 0x140
    void* PostProcessInitRoutine;      // 0x230
    void* TlsExpansionBitmap;          // 0x238
    UINT32 TlsExpansionBitmapBits[32]; // 0x240
    UINT32 SessionId;                  // 0x2c0
    CHAR  Padding5[4];                 // 0x2c4
    CHAR  AppCompatFlags[8];           // 0x2c8
    CHAR  AppCompatFlagsUser[8];       // 0x2d0
    void* pShimData;                   // 0x2d8
    void* AppCompatInfo;               // 0x2e0
    CHAR  CSDVersion[16];              // 0x2e8
    void* ActivationContextData;       // 0x2f8
    void* ProcessAssemblyStorageMap;   // 0x300
    void* SystemDefaultActivationContextData; // 0x308
    void* SystemAssemblyStorageMap;    // 0x310
    UINT64 MinimumStackCommit;         // 0x318
    void* SparePointers[2];            // 0x320
    void* PatchLoaderData;             // 0x330
    void* ChpeV2ProcessInfo;           // 0x338
    UINT32 AppModelFeatureState;       // 0x340
    UINT32 SpareUlongs[2];             // 0x344
    UINT16 ActiveCodePage;             // 0x34c
    UINT16 OemCodePage;                // 0x34e
    UINT16 UseCaseMapping;             // 0x350
    UINT16 UnusedNlsField;             // 0x352
    void* WerRegistrationData;         // 0x358
    void* WerShipAssertPtr;            // 0x360
    void* EcCodeBitMap;                // 0x368
    void* pImageHeaderHash;            // 0x370
    UINT32 TracingFlags;               // 0x378
    CHAR  Padding6[4];                 // 0x37c
    UINT64 CsrServerReadOnlySharedMemoryBase; // 0x380
    UINT64 TppWorkerpListLock;         // 0x388
    CHAR  TppWorkerpList[16];          // 0x390
    void* WaitOnAddressHashTable[128]; // 0x3a0
    void* TelemetryCoverageHeader;     // 0x7a0
    UINT32 CloudFileFlags;             // 0x7a8
    UINT32 CloudFileDiagFlags;         // 0x7ac
    CHAR  PlaceholderCompatibilityMode; // 0x7b0
    CHAR  PlaceholderCompatibilityModeReserved[7]; // 0x7b1
    void* LeapSecondData;              // 0x7b8
    UINT32 LeapSecondFlags;            // 0x7c0
    UINT32 NtGlobalFlag2;              // 0x7c4
    UINT64 ExtendedFeatureDisableMask; // 0x7c8
} PEB, * PPEB;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    // ... 이하 생략
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;



typedef struct ImageSectionInformation {

    CHAR SectionName[256]; // ".data", ".rdata" 같은 것들

    PUCHAR SectionBaseAddress;
    SIZE_T SectionSize;

    PUCHAR NextAddr;

}ImageSectionInformation, * PImageSectionInformation;

typedef struct ImageInformation {

    PUCHAR Image_BaseAddress;
    SIZE_T ImageSize;

    UNICODE_STRING ImageName;

    PImageSectionInformation SectionInfo_StartNode; // Section 정보

    PUCHAR NextAddr; // next node

}ImageInformation, * PImageInformation;

#define ImageInformationNode_TAG 'IINT' // ImageInofrmationNodeTag

namespace EDR
{
    namespace Util
    {
        namespace PE
        {
            // Looking for the Dll and API Address from Target Process
            NTSTATUS Dll_API_Address_Search(
                HANDLE Processid,

                PWCH Dll_Name, // Dll Name
                PCHAR Api_Name, // API Name

                PUCHAR* Dll_Base_VirtualAddress, // Dll Base Address
                PUCHAR* API_VirtualAddress
            ) {
                NTSTATUS status = STATUS_UNSUCCESSFUL;

                if (
                    !Dll_Name ||
                    !Api_Name ||
                    !API_VirtualAddress ||
                    !Dll_Base_VirtualAddress) {
                    return STATUS_INVALID_PARAMETER;
                }

                /*
                ==================================================================
                Find DLL ! From TargetProcess

                ** Attention
                * should be know the target process 32 or 64 bit !!!  ( for PE parsing )
                * If return the API Address, it is a VIrtual Address! Not Kernel Address... !!!@@#$!@

                STEP 1) Looking for the Eprocess from PID

                STEP 2) Attach to UserMode target process Context

                STEP 3) Get PEB

                STEP 4) Get Dll informations from LDR ..

                STEP 5) Get Api Address from Dll Base Address

                ==================================================================
                */



                // STEP 1
                PEPROCESS targetProcess = NULL;
                status = PsLookupProcessByProcessId(Processid, &targetProcess);
                if (!NT_SUCCESS(status))
                    goto EXIT0;

                // STEP 2
                KAPC_STATE APC_STATE;
                KeStackAttachProcess(targetProcess, &APC_STATE);

                // STEP 3
                PPEB Peb = (PPEB)PsGetProcessPeb(targetProcess);
                if (!Peb) {
                    status = STATUS_UNSUCCESSFUL;
                    goto EXIT2;
                }

                // find the dll
                if (Peb->Ldr && Peb->Ldr->InMemoryOrderModuleList.Flink) {

                    PLIST_ENTRY ListHead = &Peb->Ldr->InMemoryOrderModuleList;
                    PLIST_ENTRY CurrentEntry = ListHead->Flink;

                    UNICODE_STRING moduleName;
                    RtlInitUnicodeString(&moduleName, Dll_Name);

                    // STEP 4
                    while (CurrentEntry != ListHead) {

                        PLDR_DATA_TABLE_ENTRY LdrEntry = CONTAINING_RECORD(CurrentEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

                        // Compare the Dll Name
                        if (RtlEqualUnicodeString(&LdrEntry->BaseDllName, &moduleName, TRUE)) {
                            // Found the Dll
                            *Dll_Base_VirtualAddress = (PUCHAR)LdrEntry->DllBase; // Set Dll Base Address

                            // STEP 5
                            PIMAGE_DOS_HEADER__ DllDosHeader = (PIMAGE_DOS_HEADER__)LdrEntry->DllBase;
                            if (DllDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
                                DbgPrintEx(
                                    DPFLTR_IHVDRIVER_ID,
                                    DPFLTR_ERROR_LEVEL,
                                    " Invalid Dll Dos Header Signature %d \n", Processid
                                );
                                status = STATUS_INVALID_IMAGE_FORMAT;
                                goto EXIT2;
                            }

                            PIMAGE_EXPORT_DIRECTORY ExportDir = NULL;

                            BOOLEAN is64bit = (PsGetProcessWow64Process(targetProcess) == NULL); // if NULL, its 64bit process
                            if (is64bit) {



                                // 64bit
                                PIMAGE_NT_HEADERS64__ NtHeaders64 = (PIMAGE_NT_HEADERS64__)((PUCHAR)LdrEntry->DllBase + DllDosHeader->e_lfanew);

                                if (
                                    NtHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
                                    ) {
                                    ExportDir = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)LdrEntry->DllBase + NtHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

                                }

                            }
                            else {
                                // 32bit
                                PIMAGE_NT_HEADERS32__ NtHeaders32 = (PIMAGE_NT_HEADERS32__)((PUCHAR)LdrEntry->DllBase + DllDosHeader->e_lfanew);

                                if (
                                    NtHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
                                    ) {
                                    ExportDir = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)LdrEntry->DllBase + NtHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
                                }

                            }

                            if (!ExportDir) {
                                DbgPrintEx(
                                    DPFLTR_IHVDRIVER_ID,
                                    DPFLTR_ERROR_LEVEL,
                                    " No Export APIS \n"
                                );
                                status = STATUS_NOT_FOUND;
                                goto EXIT2;
                            }

                            PULONG pAddressOfFunctions = (PULONG)((PUCHAR)LdrEntry->DllBase + ExportDir->AddressOfFunctions);
                            PULONG pAddressOfNames = (PULONG)((PUCHAR)LdrEntry->DllBase + ExportDir->AddressOfNames);
                            PUSHORT  pAddressOfNameOrdinals = (PUSHORT)((PUCHAR)LdrEntry->DllBase + ExportDir->AddressOfNameOrdinals);

                            // 2. Export된 모든 함수 이름을 순회합니다.
                            for (ULONG i = 0; i < ExportDir->NumberOfNames; i++) {

                                PUCHAR Functionname = ((PUCHAR)LdrEntry->DllBase + pAddressOfNames[i]);

                                USHORT Oridnal = pAddressOfNameOrdinals[i];

                                ULONG FunctionRva = pAddressOfFunctions[Oridnal];

                                PUCHAR FunctionAddress = ((PUCHAR)LdrEntry->DllBase + FunctionRva);

                                // Compare API Name
                                if (strcmp((PCHAR)Functionname, Api_Name) != 0) {
                                    continue; // Skip if not match
                                }

                                // Found the API

                                DbgPrintEx(
                                    DPFLTR_IHVDRIVER_ID,
                                    DPFLTR_ERROR_LEVEL,
                                    "성공: API '%s'를 찾았습니다. 주소: %p \n",
                                    Functionname,
                                    FunctionAddress
                                );

                                *API_VirtualAddress = FunctionAddress;

                                goto EXIT2;
                            }

                            break;
                        }

                        CurrentEntry = CurrentEntry->Flink; // Move to next entry


                    }


                }
                else {
                    DbgPrintEx(
                        DPFLTR_IHVDRIVER_ID,
                        DPFLTR_ERROR_LEVEL,
                        " Can't found LDR from PEB %d \n", Processid
                    );
                }




            EXIT2:
                KeUnstackDetachProcess(&APC_STATE);
                ObDereferenceObject(targetProcess);
            EXIT0:
                return status;
            }

            NTSTATUS Get_ImageInformation_by_ProcessId(HANDLE ProcessId, PImageInformation* output) {

                NTSTATUS status = STATUS_UNSUCCESSFUL;

                // STEP 1
                PEPROCESS targetProcess = NULL;
                status = PsLookupProcessByProcessId(ProcessId, &targetProcess);
                if (!NT_SUCCESS(status))
                    goto EXIT0;

                // STEP 2
                KAPC_STATE APC_STATE;
                KeStackAttachProcess(targetProcess, &APC_STATE);

                // STEP 3
                PPEB Peb = (PPEB)PsGetProcessPeb(targetProcess);
                if (!Peb) {
                    status = STATUS_UNSUCCESSFUL;
                    goto EXIT1;
                }


                PImageInformation StartNode = NULL;
                PImageInformation CurrentNode = NULL;

                // find the dll
                if (Peb->Ldr && Peb->Ldr->InMemoryOrderModuleList.Flink) {




                    PLIST_ENTRY ListHead = &Peb->Ldr->InMemoryOrderModuleList;
                    PLIST_ENTRY CurrentEntry = ListHead->Flink;


                    // STEP 4
                    while (CurrentEntry != ListHead) {

                        PLDR_DATA_TABLE_ENTRY LdrEntry = CONTAINING_RECORD(CurrentEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

                        /*



                        */
                        // STEP 5
                        PIMAGE_DOS_HEADER__ DllDosHeader = (PIMAGE_DOS_HEADER__)LdrEntry->DllBase;
                        PIMAGE_NT_HEADERS64__ NtHeaders64 = (PIMAGE_NT_HEADERS64__)((PUCHAR)LdrEntry->DllBase + DllDosHeader->e_lfanew);

                        PIMAGE_SECTION_HEADER__ SectionHeader = (PIMAGE_SECTION_HEADER__)((PUCHAR)&NtHeaders64->OptionalHeader + NtHeaders64->FileHeader.SizeOfOptionalHeader);
                        USHORT SectionNumber = NtHeaders64->FileHeader.NumberOfSections;



                        PImageSectionInformation SectionStartNode = NULL;
                        PImageSectionInformation SectionCurrentNode = NULL;


                        for (USHORT i = 0; i < SectionNumber; i++) {

                            PImageSectionInformation SectionInfo = (PImageSectionInformation)ExAllocatePoolWithTag(NonPagedPool, sizeof(ImageSectionInformation), ImageInformationNode_TAG);
                            RtlZeroMemory(SectionInfo, sizeof(ImageSectionInformation));

                            // 1. Section Name
                            RtlCopyMemory(SectionInfo->SectionName, SectionHeader[i].Name, strlen(SectionHeader[i].Name) + 1);

                            // 2. Section ImageBaseAddr
                            SectionInfo->SectionBaseAddress = (PUCHAR)((PUCHAR)DllDosHeader + SectionHeader[i].VirtualAddress);

                            // 3. Section ImageSize
                            SectionInfo->SectionSize = SectionHeader[i].Misc.VirtualSize;

                            SectionInfo->NextAddr = NULL;

                            if (!SectionStartNode) {
                                SectionStartNode = SectionInfo;
                                SectionCurrentNode = SectionStartNode;
                            }
                            else {
                                SectionCurrentNode->NextAddr = (PUCHAR)SectionInfo;
                                SectionCurrentNode = SectionInfo;
                            }


                        }


                        /*




                        */


                        PImageInformation information = (PImageInformation)ExAllocatePoolWithTag(NonPagedPool, sizeof(ImageInformation), ImageInformationNode_TAG);

                        information->SectionInfo_StartNode = SectionStartNode;


                        // 1. Image Name
                        // 문자열 버퍼 할당
                        USHORT nameLen = LdrEntry->BaseDllName.Length;
                        information->ImageName.Length = nameLen;
                        information->ImageName.MaximumLength = nameLen + sizeof(WCHAR);
                        information->ImageName.Buffer = (PWCH)ExAllocatePoolWithTag(NonPagedPool, information->ImageName.MaximumLength, ImageInformationNode_TAG);

                        // 문자열 복사
                        if (information->ImageName.Buffer) {
                            RtlCopyUnicodeString(&information->ImageName, &LdrEntry->BaseDllName);
                        }

                        // 2. Image Baseaadress ( Virtual )
                        information->Image_BaseAddress = (PUCHAR)LdrEntry->DllBase;

                        // 3. Image of Size
                        information->ImageSize = LdrEntry->SizeOfImage;

                        information->NextAddr = NULL;


                        if (!StartNode) {
                            StartNode = information;
                            CurrentNode = StartNode;
                        }
                        else {
                            CurrentNode->NextAddr = (PUCHAR)information;
                            CurrentNode = information;
                        }

                        CurrentEntry = CurrentEntry->Flink;
                    }
                }

                *output = StartNode;

            EXIT1:
                KeUnstackDetachProcess(&APC_STATE);
            EXIT0:
                ObDereferenceObject(targetProcess);
                return status;
            }
            VOID Release_ImageInformation(PImageInformation input) {

                if (input) {
                    // 모듈 정보 해제
                    PImageInformation current = input;

                    while (current) {


                        // 섹션 메모리 해제
                        PImageSectionInformation current_Section = current->SectionInfo_StartNode;
                        while (current_Section) {

                            PImageSectionInformation Next_Section = (PImageSectionInformation)current_Section->NextAddr;
                            ExFreePoolWithTag(current_Section, ImageInformationNode_TAG);

                            current_Section = Next_Section;
                        }


                        if (current->ImageName.Buffer) {
                            ExFreePoolWithTag(current->ImageName.Buffer, ImageInformationNode_TAG);
                        }

                        PImageInformation Next = (PImageInformation)current->NextAddr;
                        ExFreePoolWithTag(current, ImageInformationNode_TAG);

                        current = Next;
                    }
                }


            }
        }
    }
}


#endif