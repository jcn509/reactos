#include "xbe/xbe.h"

typedef struct _XBE_HEADER {
	uint8_t   Magic[4];                // 000 "XBEH"
	uint8_t   HeaderSignature[256];    // 004 RSA digital signature of the entire header area
	uint32_t  BaseAddress;             // 104 Base address of XBE image (must be 0x00010000?)
	uint32_t  HeaderSize;              // 108 Size of all headers combined - other headers must be within this
	uint32_t  ImageSize;               // 10C Size of entire image
	uint32_t  XbeHeaderSize;           // 110 Size of this header (always 0x178?)
	uint32_t  Timestamp;               // 114 Image timestamp - unknown format
	uint32_t  Certificate;             // 118 Pointer to certificate data (must be within HeaderSize)
	int32_t   NumSections;             // 11C Number of sections
	uint32_t  Sections;                // 120 Pointer to section headers (must be within HeaderSize)
	uint32_t  InitFlags;               // 124 Initialization flags
	uint32_t  EntryPoint;              // 128 Entry point
	uint32_t  TlsDirectory;            // 12C Pointer to TLS directory
	uint32_t  StackCommit;             // 130 Stack commit size
	uint32_t  HeapReserve;             // 134 Heap reserve size
	uint32_t  HeapCommit;              // 138 Heap commit size
	uint32_t  PeBaseAddress;           // 13C PE base address (?)
	uint32_t  PeImageSize;             // 140 PE image size (?)
	uint32_t  PeChecksum;              // 144 PE checksum (?)
	uint32_t  PeTimestamp;             // 148 PE timestamp (?)
	uint32_t  PcExePath;               // 14C PC path and filename to EXE file from which XBE is derived
	uint32_t  PcExeFilename;           // 150 PC filename (last part of PcExePath) from which XBE is derived
	uint32_t  PcExeFilenameUnicode;    // 154 PC filename (Unicode version of PcExeFilename)
	uint32_t  KernelThunkTable;        // 158 Pointer to kernel thunk table (XOR'd; EFB1F152 debug)
	uint32_t  DebugImportTable;        // 15C Non-kernel import table (debug only)
	int32_t   NumLibraries;            // 160 Number of library headers
	uint32_t  Libraries;               // 164 Pointer to library headers
	uint32_t  KernelLibrary;           // 168 Pointer to kernel library header
	uint32_t  XapiLibrary;             // 16C Pointer to XAPI library
	uint32_t  LogoBitmap;              // 170 Pointer to logo bitmap (NULL = use default of Microsoft)
	uint32_t  LogoBitmapSize;          // 174 Size of logo bitmap
} XBE_HEADER, *PXBE_HEADER;

// Section headers
typedef struct _XBE_SECTION {
	uint32_t  Flags;                   // 000 Flags
	uint32_t  VirtualAddress;          // 004 Virtual address (where this section loads in RAM)
	uint32_t  VirtualSize;             // 008 Virtual size (size of section in RAM; after FileSize it's 00'd)
	uint32_t  FileAddress;             // 00C File address (where in the file from which this section comes)
	uint32_t  FileSize;                // 010 File size (size of the section in the XBE file)
	uint32_t  SectionName;             // 014 Pointer to section name
	int32_t   SectionReferenceCount;   // 018 Section reference count - when >= 1, section is loaded
	uint32_t  HeadReferenceCount;      // 01C Pointer to head shared page reference count
	uint32_t  TailReferenceCount;      // 020 Pointer to tail shared page reference count
	uint8_t   ShaHash[20];             // 024 SHA1 hash.  Hash int32_t containing FileSize, then hash section.
} XBE_SECTION, *PXBE_SECTION;


static char *m_import_addrs[400] = {
#define KERNEL_IMPORT_NULL(i) [i] = 0,
#define KERNEL_IMPORT_FUNC(i, n) [i] = #n,
#define KERNEL_IMPORT_DATA(i, n) [i] = #n, // FIXME
#define KERNEL_IMPORTS \
	KERNEL_IMPORT_NULL(0) \
	KERNEL_IMPORT_FUNC(1, AvGetSavedDataAddress) \
	KERNEL_IMPORT_FUNC(2, AvSendTVEncoderOption) \
	KERNEL_IMPORT_FUNC(3, AvSetDisplayMode) \
	KERNEL_IMPORT_FUNC(4, AvSetSavedDataAddress) \
	KERNEL_IMPORT_FUNC(5, DbgBreakPoint) \
	KERNEL_IMPORT_FUNC(6, DbgBreakPointWithStatus) \
	KERNEL_IMPORT_FUNC(7, DbgLoadImageSymbols) \
	KERNEL_IMPORT_FUNC(8, DbgPrint) \
	KERNEL_IMPORT_FUNC(9, HalReadSMCTrayState) \
	KERNEL_IMPORT_FUNC(10, DbgPrompt) \
	KERNEL_IMPORT_FUNC(11, DbgUnLoadImageSymbols) \
	KERNEL_IMPORT_FUNC(12, ExAcquireReadWriteLockExclusive) \
	KERNEL_IMPORT_FUNC(13, ExAcquireReadWriteLockShared) \
	KERNEL_IMPORT_FUNC(14, ExAllocatePool) \
	KERNEL_IMPORT_FUNC(15, ExAllocatePoolWithTag) \
	KERNEL_IMPORT_DATA(16, ExEventObjectType) \
	KERNEL_IMPORT_FUNC(17, ExFreePool) \
	KERNEL_IMPORT_FUNC(18, ExInitializeReadWriteLock) \
	KERNEL_IMPORT_FUNC(19, ExInterlockedAddLargeInteger) \
	KERNEL_IMPORT_FUNC(20, ExInterlockedAddLargeStatistic) \
	KERNEL_IMPORT_FUNC(21, ExInterlockedCompareExchange64) \
	KERNEL_IMPORT_DATA(22, ExMutantObjectType) \
	KERNEL_IMPORT_FUNC(23, ExQueryPoolBlockSize) \
	KERNEL_IMPORT_FUNC(24, ExQueryNonVolatileSetting) \
	KERNEL_IMPORT_FUNC(25, ExReadWriteRefurbInfo) \
	KERNEL_IMPORT_FUNC(26, ExRaiseException) \
	KERNEL_IMPORT_FUNC(27, ExRaiseStatus) \
	KERNEL_IMPORT_FUNC(28, ExReleaseReadWriteLock) \
	KERNEL_IMPORT_FUNC(29, ExSaveNonVolatileSetting) \
	KERNEL_IMPORT_DATA(30, ExSemaphoreObjectType) \
	KERNEL_IMPORT_DATA(31, ExTimerObjectType) \
	KERNEL_IMPORT_FUNC(32, ExfInterlockedInsertHeadList) \
	KERNEL_IMPORT_FUNC(33, ExfInterlockedInsertTailList) \
	KERNEL_IMPORT_FUNC(34, ExfInterlockedRemoveHeadList) \
	KERNEL_IMPORT_FUNC(35, FscGetCacheSize) \
	KERNEL_IMPORT_FUNC(36, FscInvalidateIdleBlocks) \
	KERNEL_IMPORT_FUNC(37, FscSetCacheSize) \
	KERNEL_IMPORT_FUNC(38, HalClearSoftwareInterrupt) \
	KERNEL_IMPORT_FUNC(39, HalDisableSystemInterrupt) \
	KERNEL_IMPORT_DATA(40, HalDiskCachePartitionCount) \
	KERNEL_IMPORT_DATA(41, HalDiskModelNumber) \
	KERNEL_IMPORT_DATA(42, HalDiskSerialNumber) \
	KERNEL_IMPORT_FUNC(43, HalEnableSystemInterrupt) \
	KERNEL_IMPORT_FUNC(44, HalGetInterruptVector) \
	KERNEL_IMPORT_FUNC(45, HalReadSMBusValue) \
	KERNEL_IMPORT_FUNC(46, HalReadWritePCISpace) \
	KERNEL_IMPORT_FUNC(47, HalRegisterShutdownNotification) \
	KERNEL_IMPORT_FUNC(48, HalRequestSoftwareInterrupt) \
	KERNEL_IMPORT_FUNC(49, HalReturnToFirmware) \
	KERNEL_IMPORT_FUNC(50, HalWriteSMBusValue) \
	KERNEL_IMPORT_FUNC(51, InterlockedCompareExchange) \
	KERNEL_IMPORT_FUNC(52, InterlockedDecrement) \
	KERNEL_IMPORT_FUNC(53, InterlockedIncrement) \
	KERNEL_IMPORT_FUNC(54, InterlockedExchange) \
	KERNEL_IMPORT_FUNC(55, InterlockedExchangeAdd) \
	KERNEL_IMPORT_FUNC(56, InterlockedFlushSList) \
	KERNEL_IMPORT_FUNC(57, InterlockedPopEntrySList) \
	KERNEL_IMPORT_FUNC(58, InterlockedPushEntrySList) \
	KERNEL_IMPORT_FUNC(59, IoAllocateIrp) \
	KERNEL_IMPORT_FUNC(60, IoBuildAsynchronousFsdRequest) \
	KERNEL_IMPORT_FUNC(61, IoBuildDeviceIoControlRequest) \
	KERNEL_IMPORT_FUNC(62, IoBuildSynchronousFsdRequest) \
	KERNEL_IMPORT_FUNC(63, IoCheckShareAccess) \
	KERNEL_IMPORT_DATA(64, IoCompletionObjectType) \
	KERNEL_IMPORT_FUNC(65, IoCreateDevice) \
	KERNEL_IMPORT_FUNC(66, IoCreateFile) \
	KERNEL_IMPORT_FUNC(67, IoCreateSymbolicLink) \
	KERNEL_IMPORT_FUNC(68, IoDeleteDevice) \
	KERNEL_IMPORT_FUNC(69, IoDeleteSymbolicLink) \
	KERNEL_IMPORT_DATA(70, IoDeviceObjectType) \
	KERNEL_IMPORT_DATA(71, IoFileObjectType) \
	KERNEL_IMPORT_FUNC(72, IoFreeIrp) \
	KERNEL_IMPORT_FUNC(73, IoInitializeIrp) \
	KERNEL_IMPORT_FUNC(74, IoInvalidDeviceRequest) \
	KERNEL_IMPORT_FUNC(75, IoQueryFileInformation) \
	KERNEL_IMPORT_FUNC(76, IoQueryVolumeInformation) \
	KERNEL_IMPORT_FUNC(77, IoQueueThreadIrp) \
	KERNEL_IMPORT_FUNC(78, IoRemoveShareAccess) \
	KERNEL_IMPORT_FUNC(79, IoSetIoCompletion) \
	KERNEL_IMPORT_FUNC(80, IoSetShareAccess) \
	KERNEL_IMPORT_FUNC(81, IoStartNextPacket) \
	KERNEL_IMPORT_FUNC(82, IoStartNextPacketByKey) \
	KERNEL_IMPORT_FUNC(83, IoStartPacket) \
	KERNEL_IMPORT_FUNC(84, IoSynchronousDeviceIoControlRequest) \
	KERNEL_IMPORT_FUNC(85, IoSynchronousFsdRequest) \
	KERNEL_IMPORT_FUNC(86, IofCallDriver) \
	KERNEL_IMPORT_FUNC(87, IofCompleteRequest) \
	KERNEL_IMPORT_DATA(88, KdDebuggerEnabled) \
	KERNEL_IMPORT_DATA(89, KdDebuggerNotPresent) \
	KERNEL_IMPORT_FUNC(90, IoDismountVolume) \
	KERNEL_IMPORT_FUNC(91, IoDismountVolumeByName) \
	KERNEL_IMPORT_FUNC(92, KeAlertResumeThread) \
	KERNEL_IMPORT_FUNC(93, KeAlertThread) \
	KERNEL_IMPORT_FUNC(94, KeBoostPriorityThread) \
	KERNEL_IMPORT_FUNC(95, KeBugCheck) \
	KERNEL_IMPORT_FUNC(96, KeBugCheckEx) \
	KERNEL_IMPORT_FUNC(97, KeCancelTimer) \
	KERNEL_IMPORT_FUNC(98, KeConnectInterrupt) \
	KERNEL_IMPORT_FUNC(99, KeDelayExecutionThread) \
	KERNEL_IMPORT_FUNC(100, KeDisconnectInterrupt) \
	KERNEL_IMPORT_FUNC(101, KeEnterCriticalRegion) \
	KERNEL_IMPORT_DATA(102, MmGlobalData) \
	KERNEL_IMPORT_FUNC(103, KeGetCurrentIrql) \
	KERNEL_IMPORT_FUNC(104, KeGetCurrentThread) \
	KERNEL_IMPORT_FUNC(105, KeInitializeApc) \
	KERNEL_IMPORT_FUNC(106, KeInitializeDeviceQueue) \
	KERNEL_IMPORT_FUNC(107, KeInitializeDpc) \
	KERNEL_IMPORT_FUNC(108, KeInitializeEvent) \
	KERNEL_IMPORT_FUNC(109, KeInitializeInterrupt) \
	KERNEL_IMPORT_FUNC(110, KeInitializeMutant) \
	KERNEL_IMPORT_FUNC(111, KeInitializeQueue) \
	KERNEL_IMPORT_FUNC(112, KeInitializeSemaphore) \
	KERNEL_IMPORT_FUNC(113, KeInitializeTimerEx) \
	KERNEL_IMPORT_FUNC(114, KeInsertByKeyDeviceQueue) \
	KERNEL_IMPORT_FUNC(115, KeInsertDeviceQueue) \
	KERNEL_IMPORT_FUNC(116, KeInsertHeadQueue) \
	KERNEL_IMPORT_FUNC(117, KeInsertQueue) \
	KERNEL_IMPORT_FUNC(118, KeInsertQueueApc) \
	KERNEL_IMPORT_FUNC(119, KeInsertQueueDpc) \
	KERNEL_IMPORT_DATA(120, KeInterruptTime) \
	KERNEL_IMPORT_FUNC(121, KeIsExecutingDpc) \
	KERNEL_IMPORT_FUNC(122, KeLeaveCriticalRegion) \
	KERNEL_IMPORT_FUNC(123, KePulseEvent) \
	KERNEL_IMPORT_FUNC(124, KeQueryBasePriorityThread) \
	KERNEL_IMPORT_FUNC(125, KeQueryInterruptTime) \
	KERNEL_IMPORT_FUNC(126, KeQueryPerformanceCounter) \
	KERNEL_IMPORT_FUNC(127, KeQueryPerformanceFrequency) \
	KERNEL_IMPORT_FUNC(128, KeQuerySystemTime) \
	KERNEL_IMPORT_FUNC(129, KeRaiseIrqlToDpcLevel) \
	KERNEL_IMPORT_FUNC(130, KeRaiseIrqlToSynchLevel) \
	KERNEL_IMPORT_FUNC(131, KeReleaseMutant) \
	KERNEL_IMPORT_FUNC(132, KeReleaseSemaphore) \
	KERNEL_IMPORT_FUNC(133, KeRemoveByKeyDeviceQueue) \
	KERNEL_IMPORT_FUNC(134, KeRemoveDeviceQueue) \
	KERNEL_IMPORT_FUNC(135, KeRemoveEntryDeviceQueue) \
	KERNEL_IMPORT_FUNC(136, KeRemoveQueue) \
	KERNEL_IMPORT_FUNC(137, KeRemoveQueueDpc) \
	KERNEL_IMPORT_FUNC(138, KeResetEvent) \
	KERNEL_IMPORT_FUNC(139, KeRestoreFloatingPointState) \
	KERNEL_IMPORT_FUNC(140, KeResumeThread) \
	KERNEL_IMPORT_FUNC(141, KeRundownQueue) \
	KERNEL_IMPORT_FUNC(142, KeSaveFloatingPointState) \
	KERNEL_IMPORT_FUNC(143, KeSetBasePriorityThread) \
	KERNEL_IMPORT_FUNC(144, KeSetDisableBoostThread) \
	KERNEL_IMPORT_FUNC(145, KeSetEvent) \
	KERNEL_IMPORT_FUNC(146, KeSetEventBoostPriority) \
	KERNEL_IMPORT_FUNC(147, KeSetPriorityProcess) \
	KERNEL_IMPORT_FUNC(148, KeSetPriorityThread) \
	KERNEL_IMPORT_FUNC(149, KeSetTimer) \
	KERNEL_IMPORT_FUNC(150, KeSetTimerEx) \
	KERNEL_IMPORT_FUNC(151, KeStallExecutionProcessor) \
	KERNEL_IMPORT_FUNC(152, KeSuspendThread) \
	KERNEL_IMPORT_FUNC(153, KeSynchronizeExecution) \
	KERNEL_IMPORT_DATA(154, KeSystemTime) \
	KERNEL_IMPORT_FUNC(155, KeTestAlertThread) \
	KERNEL_IMPORT_DATA(156, KeTickCount) \
	KERNEL_IMPORT_DATA(157, KeTimeIncrement) \
	KERNEL_IMPORT_FUNC(158, KeWaitForMultipleObjects) \
	KERNEL_IMPORT_FUNC(159, KeWaitForSingleObject) \
	KERNEL_IMPORT_FUNC(160, KfRaiseIrql) \
	KERNEL_IMPORT_FUNC(161, KfLowerIrql) \
	KERNEL_IMPORT_DATA(162, KiBugCheckData) \
	KERNEL_IMPORT_FUNC(163, KiUnlockDispatcherDatabase) \
	KERNEL_IMPORT_DATA(164, LaunchDataPage) \
	KERNEL_IMPORT_FUNC(165, MmAllocateContiguousMemory) \
	KERNEL_IMPORT_FUNC(166, MmAllocateContiguousMemoryEx) \
	KERNEL_IMPORT_FUNC(167, MmAllocateSystemMemory) \
	KERNEL_IMPORT_FUNC(168, MmClaimGpuInstanceMemory) \
	KERNEL_IMPORT_FUNC(169, MmCreateKernelStack) \
	KERNEL_IMPORT_FUNC(170, MmDeleteKernelStack) \
	KERNEL_IMPORT_FUNC(171, MmFreeContiguousMemory) \
	KERNEL_IMPORT_FUNC(172, MmFreeSystemMemory) \
	KERNEL_IMPORT_FUNC(173, MmGetPhysicalAddress) \
	KERNEL_IMPORT_FUNC(174, MmIsAddressValid) \
	KERNEL_IMPORT_FUNC(175, MmLockUnlockBufferPages) \
	KERNEL_IMPORT_FUNC(176, MmLockUnlockPhysicalPage) \
	KERNEL_IMPORT_FUNC(177, MmMapIoSpace) \
	KERNEL_IMPORT_FUNC(178, MmPersistContiguousMemory) \
	KERNEL_IMPORT_FUNC(179, MmQueryAddressProtect) \
	KERNEL_IMPORT_FUNC(180, MmQueryAllocationSize) \
	KERNEL_IMPORT_FUNC(181, MmQueryStatistics) \
	KERNEL_IMPORT_FUNC(182, MmSetAddressProtect) \
	KERNEL_IMPORT_FUNC(183, MmUnmapIoSpace) \
	KERNEL_IMPORT_FUNC(184, NtAllocateVirtualMemory) \
	KERNEL_IMPORT_FUNC(185, NtCancelTimer) \
	KERNEL_IMPORT_FUNC(186, NtClearEvent) \
	KERNEL_IMPORT_FUNC(187, NtClose) \
	KERNEL_IMPORT_FUNC(188, NtCreateDirectoryObject) \
	KERNEL_IMPORT_FUNC(189, NtCreateEvent) \
	KERNEL_IMPORT_FUNC(190, NtCreateFile) \
	KERNEL_IMPORT_FUNC(191, NtCreateIoCompletion) \
	KERNEL_IMPORT_FUNC(192, NtCreateMutant) \
	KERNEL_IMPORT_FUNC(193, NtCreateSemaphore) \
	KERNEL_IMPORT_FUNC(194, NtCreateTimer) \
	KERNEL_IMPORT_FUNC(195, NtDeleteFile) \
	KERNEL_IMPORT_FUNC(196, NtDeviceIoControlFile) \
	KERNEL_IMPORT_FUNC(197, NtDuplicateObject) \
	KERNEL_IMPORT_FUNC(198, NtFlushBuffersFile) \
	KERNEL_IMPORT_FUNC(199, NtFreeVirtualMemory) \
	KERNEL_IMPORT_FUNC(200, NtFsControlFile) \
	KERNEL_IMPORT_FUNC(201, NtOpenDirectoryObject) \
	KERNEL_IMPORT_FUNC(202, NtOpenFile) \
	KERNEL_IMPORT_FUNC(203, NtOpenSymbolicLinkObject) \
	KERNEL_IMPORT_FUNC(204, NtProtectVirtualMemory) \
	KERNEL_IMPORT_FUNC(205, NtPulseEvent) \
	KERNEL_IMPORT_FUNC(206, NtQueueApcThread) \
	KERNEL_IMPORT_FUNC(207, NtQueryDirectoryFile) \
	KERNEL_IMPORT_FUNC(208, NtQueryDirectoryObject) \
	KERNEL_IMPORT_FUNC(209, NtQueryEvent) \
	KERNEL_IMPORT_FUNC(210, NtQueryFullAttributesFile) \
	KERNEL_IMPORT_FUNC(211, NtQueryInformationFile) \
	KERNEL_IMPORT_FUNC(212, NtQueryIoCompletion) \
	KERNEL_IMPORT_FUNC(213, NtQueryMutant) \
	KERNEL_IMPORT_FUNC(214, NtQuerySemaphore) \
	KERNEL_IMPORT_FUNC(215, NtQuerySymbolicLinkObject) \
	KERNEL_IMPORT_FUNC(216, NtQueryTimer) \
	KERNEL_IMPORT_FUNC(217, NtQueryVirtualMemory) \
	KERNEL_IMPORT_FUNC(218, NtQueryVolumeInformationFile) \
	KERNEL_IMPORT_FUNC(219, NtReadFile) \
	KERNEL_IMPORT_FUNC(220, NtReadFileScatter) \
	KERNEL_IMPORT_FUNC(221, NtReleaseMutant) \
	KERNEL_IMPORT_FUNC(222, NtReleaseSemaphore) \
	KERNEL_IMPORT_FUNC(223, NtRemoveIoCompletion) \
	KERNEL_IMPORT_FUNC(224, NtResumeThread) \
	KERNEL_IMPORT_FUNC(225, NtSetEvent) \
	KERNEL_IMPORT_FUNC(226, NtSetInformationFile) \
	KERNEL_IMPORT_FUNC(227, NtSetIoCompletion) \
	KERNEL_IMPORT_FUNC(228, NtSetSystemTime) \
	KERNEL_IMPORT_FUNC(229, NtSetTimerEx) \
	KERNEL_IMPORT_FUNC(230, NtSignalAndWaitForSingleObjectEx) \
	KERNEL_IMPORT_FUNC(231, NtSuspendThread) \
	KERNEL_IMPORT_FUNC(232, NtUserIoApcDispatcher) \
	KERNEL_IMPORT_FUNC(233, NtWaitForSingleObject) \
	KERNEL_IMPORT_FUNC(234, NtWaitForSingleObjectEx) \
	KERNEL_IMPORT_FUNC(235, NtWaitForMultipleObjectsEx) \
	KERNEL_IMPORT_FUNC(236, NtWriteFile) \
	KERNEL_IMPORT_FUNC(237, NtWriteFileGather) \
	KERNEL_IMPORT_FUNC(238, NtYieldExecution) \
	KERNEL_IMPORT_FUNC(239, ObCreateObject) \
	KERNEL_IMPORT_DATA(240, ObDirectoryObjectType) \
	KERNEL_IMPORT_FUNC(241, ObInsertObject) \
	KERNEL_IMPORT_FUNC(242, ObMakeTemporaryObject) \
	KERNEL_IMPORT_FUNC(243, ObOpenObjectByName) \
	KERNEL_IMPORT_FUNC(244, ObOpenObjectByPointer) \
	KERNEL_IMPORT_DATA(245, ObpObjectHandleTable) \
	KERNEL_IMPORT_FUNC(246, ObReferenceObjectByHandle) \
	KERNEL_IMPORT_FUNC(247, ObReferenceObjectByName) \
	KERNEL_IMPORT_FUNC(248, ObReferenceObjectByPointer) \
	KERNEL_IMPORT_DATA(249, ObSymbolicLinkObjectType) \
	KERNEL_IMPORT_FUNC(250, ObfDereferenceObject) \
	KERNEL_IMPORT_FUNC(251, ObfReferenceObject) \
	KERNEL_IMPORT_FUNC(252, PhyGetLinkState) \
	KERNEL_IMPORT_FUNC(253, PhyInitialize) \
	KERNEL_IMPORT_FUNC(254, PsCreateSystemThread) \
	KERNEL_IMPORT_FUNC(255, PsCreateSystemThreadEx) \
	KERNEL_IMPORT_FUNC(256, PsQueryStatistics) \
	KERNEL_IMPORT_FUNC(257, PsSetCreateThreadNotifyRoutine) \
	KERNEL_IMPORT_FUNC(258, PsTerminateSystemThread) \
	KERNEL_IMPORT_DATA(259, PsThreadObjectType) \
	KERNEL_IMPORT_FUNC(260, RtlAnsiStringToUnicodeString) \
	KERNEL_IMPORT_FUNC(261, RtlAppendStringToString) \
	KERNEL_IMPORT_FUNC(262, RtlAppendUnicodeStringToString) \
	KERNEL_IMPORT_FUNC(263, RtlAppendUnicodeToString) \
	KERNEL_IMPORT_FUNC(264, RtlAssert) \
	KERNEL_IMPORT_FUNC(265, RtlCaptureContext) \
	KERNEL_IMPORT_FUNC(266, RtlCaptureStackBackTrace) \
	KERNEL_IMPORT_FUNC(267, RtlCharToInteger) \
	KERNEL_IMPORT_FUNC(268, RtlCompareMemory) \
	KERNEL_IMPORT_FUNC(269, RtlCompareMemoryUlong) \
	KERNEL_IMPORT_FUNC(270, RtlCompareString) \
	KERNEL_IMPORT_FUNC(271, RtlCompareUnicodeString) \
	KERNEL_IMPORT_FUNC(272, RtlCopyString) \
	KERNEL_IMPORT_FUNC(273, RtlCopyUnicodeString) \
	KERNEL_IMPORT_FUNC(274, RtlCreateUnicodeString) \
	KERNEL_IMPORT_FUNC(275, RtlDowncaseUnicodeChar) \
	KERNEL_IMPORT_FUNC(276, RtlDowncaseUnicodeString) \
	KERNEL_IMPORT_FUNC(277, RtlEnterCriticalSection) \
	KERNEL_IMPORT_FUNC(278, RtlEnterCriticalSectionAndRegion) \
	KERNEL_IMPORT_FUNC(279, RtlEqualString) \
	KERNEL_IMPORT_FUNC(280, RtlEqualUnicodeString) \
	KERNEL_IMPORT_FUNC(281, RtlExtendedIntegerMultiply) \
	KERNEL_IMPORT_FUNC(282, RtlExtendedLargeIntegerDivide) \
	KERNEL_IMPORT_FUNC(283, RtlExtendedMagicDivide) \
	KERNEL_IMPORT_FUNC(284, RtlFillMemory) \
	KERNEL_IMPORT_FUNC(285, RtlFillMemoryUlong) \
	KERNEL_IMPORT_FUNC(286, RtlFreeAnsiString) \
	KERNEL_IMPORT_FUNC(287, RtlFreeUnicodeString) \
	KERNEL_IMPORT_FUNC(288, RtlGetCallersAddress) \
	KERNEL_IMPORT_FUNC(289, RtlInitAnsiString) \
	KERNEL_IMPORT_FUNC(290, RtlInitUnicodeString) \
	KERNEL_IMPORT_FUNC(291, RtlInitializeCriticalSection) \
	KERNEL_IMPORT_FUNC(292, RtlIntegerToChar) \
	KERNEL_IMPORT_FUNC(293, RtlIntegerToUnicodeString) \
	KERNEL_IMPORT_FUNC(294, RtlLeaveCriticalSection) \
	KERNEL_IMPORT_FUNC(295, RtlLeaveCriticalSectionAndRegion) \
	KERNEL_IMPORT_FUNC(296, RtlLowerChar) \
	KERNEL_IMPORT_FUNC(297, RtlMapGenericMask) \
	KERNEL_IMPORT_FUNC(298, RtlMoveMemory) \
	KERNEL_IMPORT_FUNC(299, RtlMultiByteToUnicodeN) \
	KERNEL_IMPORT_FUNC(300, RtlMultiByteToUnicodeSize) \
	KERNEL_IMPORT_FUNC(301, RtlNtStatusToDosError) \
	KERNEL_IMPORT_FUNC(302, RtlRaiseException) \
	KERNEL_IMPORT_FUNC(303, RtlRaiseStatus) \
	KERNEL_IMPORT_FUNC(304, RtlTimeFieldsToTime) \
	KERNEL_IMPORT_FUNC(305, RtlTimeToTimeFields) \
	KERNEL_IMPORT_FUNC(306, RtlTryEnterCriticalSection) \
	KERNEL_IMPORT_FUNC(307, RtlUlongByteSwap) \
	KERNEL_IMPORT_FUNC(308, RtlUnicodeStringToAnsiString) \
	KERNEL_IMPORT_FUNC(309, RtlUnicodeStringToInteger) \
	KERNEL_IMPORT_FUNC(310, RtlUnicodeToMultiByteN) \
	KERNEL_IMPORT_FUNC(311, RtlUnicodeToMultiByteSize) \
	KERNEL_IMPORT_FUNC(312, RtlUnwind) \
	KERNEL_IMPORT_FUNC(313, RtlUpcaseUnicodeChar) \
	KERNEL_IMPORT_FUNC(314, RtlUpcaseUnicodeString) \
	KERNEL_IMPORT_FUNC(315, RtlUpcaseUnicodeToMultiByteN) \
	KERNEL_IMPORT_FUNC(316, RtlUpperChar) \
	KERNEL_IMPORT_FUNC(317, RtlUpperString) \
	KERNEL_IMPORT_FUNC(318, RtlUshortByteSwap) \
	KERNEL_IMPORT_FUNC(319, RtlWalkFrameChain) \
	KERNEL_IMPORT_FUNC(320, RtlZeroMemory) \
	KERNEL_IMPORT_DATA(321, XboxEEPROMKey) \
	KERNEL_IMPORT_DATA(322, XboxHardwareInfo) \
	KERNEL_IMPORT_DATA(323, XboxHDKey) \
	KERNEL_IMPORT_DATA(324, XboxKrnlVersion) \
	KERNEL_IMPORT_DATA(325, XboxSignatureKey) \
	KERNEL_IMPORT_DATA(326, XeImageFileName) \
	KERNEL_IMPORT_FUNC(327, XeLoadSection) \
	KERNEL_IMPORT_FUNC(328, XeUnloadSection) \
	KERNEL_IMPORT_FUNC(329, READ_PORT_BUFFER_UCHAR) \
	KERNEL_IMPORT_FUNC(330, READ_PORT_BUFFER_USHORT) \
	KERNEL_IMPORT_FUNC(331, READ_PORT_BUFFER_ULONG) \
	KERNEL_IMPORT_FUNC(332, WRITE_PORT_BUFFER_UCHAR) \
	KERNEL_IMPORT_FUNC(333, WRITE_PORT_BUFFER_USHORT) \
	KERNEL_IMPORT_FUNC(334, WRITE_PORT_BUFFER_ULONG) \
	KERNEL_IMPORT_FUNC(335, XcSHAInit) \
	KERNEL_IMPORT_FUNC(336, XcSHAUpdate) \
	KERNEL_IMPORT_FUNC(337, XcSHAFinal) \
	KERNEL_IMPORT_FUNC(338, XcRC4Key) \
	KERNEL_IMPORT_FUNC(339, XcRC4Crypt) \
	KERNEL_IMPORT_FUNC(340, XcHMAC) \
	KERNEL_IMPORT_FUNC(341, XcPKEncPublic) \
	KERNEL_IMPORT_FUNC(342, XcPKDecPrivate) \
	KERNEL_IMPORT_FUNC(343, XcPKGetKeyLen) \
	KERNEL_IMPORT_FUNC(344, XcVerifyPKCS1Signature) \
	KERNEL_IMPORT_FUNC(345, XcModExp) \
	KERNEL_IMPORT_FUNC(346, XcDESKeyParity) \
	KERNEL_IMPORT_FUNC(347, XcKeyTable) \
	KERNEL_IMPORT_FUNC(348, XcBlockCrypt) \
	KERNEL_IMPORT_FUNC(349, XcBlockCryptCBC) \
	KERNEL_IMPORT_FUNC(350, XcCryptService) \
	KERNEL_IMPORT_FUNC(351, XcUpdateCrypto) \
	KERNEL_IMPORT_FUNC(352, RtlRip) \
	KERNEL_IMPORT_DATA(353, XboxLANKey) \
	KERNEL_IMPORT_DATA(354, XboxAlternateSignatureKeys) \
	KERNEL_IMPORT_DATA(355, XePublicKeyData) \
	KERNEL_IMPORT_FUNC(356, HalBootSMCVideoMode) \
	KERNEL_IMPORT_DATA(357, IdexChannelObject) \
	KERNEL_IMPORT_FUNC(358, HalIsResetOrShutdownPending) \
	KERNEL_IMPORT_FUNC(359, IoMarkIrpMustComplete) \
	KERNEL_IMPORT_FUNC(360, HalInitiateShutdown) \
	KERNEL_IMPORT_FUNC(361, RtlSnprintf) \
	KERNEL_IMPORT_FUNC(362, RtlSprintf) \
	KERNEL_IMPORT_FUNC(363, RtlVsnprintf) \
	KERNEL_IMPORT_FUNC(364, RtlVsprintf) \
	KERNEL_IMPORT_FUNC(365, HalEnableSecureTrayEject) \
	KERNEL_IMPORT_FUNC(366, HalWriteSMCScratchRegister) \
	KERNEL_IMPORT_NULL(367) \
	KERNEL_IMPORT_NULL(368) \
	KERNEL_IMPORT_NULL(369) \
	KERNEL_IMPORT_NULL(370) \
	KERNEL_IMPORT_NULL(371) \
	KERNEL_IMPORT_NULL(372) \
	KERNEL_IMPORT_NULL(373) \
	KERNEL_IMPORT_FUNC(374, MmDbgAllocateMemory) \
	KERNEL_IMPORT_FUNC(375, MmDbgFreeMemory) \
	KERNEL_IMPORT_FUNC(376, MmDbgQueryAvailablePages) \
	KERNEL_IMPORT_FUNC(377, MmDbgReleaseAddress) \
	KERNEL_IMPORT_FUNC(378, MmDbgWriteCheck) \

KERNEL_IMPORTS
#undef KERNEL_IMPORT_NULL
#undef KERNEL_IMPORT_FUNC
#undef KERNEL_IMPORT_DATA
};

static uint32_t xbe_unscramble(uint32_t addr, uint32_t debug, uint32_t retail)
{
    uint32_t addr_out;

    #define XBOX_RAM_SIZE (64*0x100000)

    addr_out = addr ^ retail;
    if (addr_out < XBOX_RAM_SIZE) {
        return addr_out;
    }

    return addr ^ debug;
}

static void xbe_patch_imports(XBE_HEADER *hdr)
{
    DbgPrint("xbe_patch_imports");
    // Patch Kernel Imports


    const uint32_t XOR_KT_DEBUG                            = 0xEFB1F152; // Kernel Thunk (Debug)
    const uint32_t XOR_KT_RETAIL                           = 0x5B6D40B6; // Kernel Thunk (Retail)
    uint32_t xor_kt;
    if ((hdr->KernelThunkTable & KSEG0_BASE) >  0x80000000) {
        DbgPrint("Is a debug xbe\n");
        xor_kt = XOR_KT_DEBUG;
    }
    else {
        DbgPrint("Is a retail XBE\n");
        xor_kt = XOR_KT_RETAIL;
    }

    uint32_t imports_num = hdr->KernelThunkTable;
    imports_num ^= xor_kt;
    uint32_t* imports = (uint32_t*)imports_num;

    DbgPrint("Unscrambled. Thunk table is at %x\n", imports_num);
    for (int i = 0; imports[i] != 0; i++) {
        uint32_t import_num = imports[i] & 0x7FFFFFFF;
        DbgPrint("Patch import i=%i, imports[i]=%u, import_num=%u\n", i, imports[i], import_num);
        // assert(import_num < 379);
        // Import addrs actually just contains strings right now...
        DbgPrint("import %s\n", m_import_addrs[import_num]);
    }
}


void LoadInitialXbe(PUNICODE_STRING SmssName) {

    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE hFile = NULL;
    IO_STATUS_BLOCK IoStatusBlock;
    XBE_HEADER Header;

    DbgPrint("New test");
    /* Open the Image File */
    InitializeObjectAttributes(&ObjectAttributes,
                               SmssName,
                               OBJ_CASE_INSENSITIVE & (OBJ_CASE_INSENSITIVE | OBJ_INHERIT),
                               NULL,
                               NULL);
    NTSTATUS Status = ZwOpenFile(&hFile,
                        SYNCHRONIZE | FILE_EXECUTE | FILE_READ_DATA,
                        &ObjectAttributes,
                        &IoStatusBlock,
                        FILE_SHARE_DELETE | FILE_SHARE_READ,
                        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("Failed to read image file from disk, Status = 0x%08X\n", Status);
    }
    else {
        DbgPrint("File open success!");
    }

    // Load XBE header
    // TODO: some headers are larger and we may want the extra bytes?
    Status = ZwReadFile(
        hFile,
        NULL,
        NULL,
        NULL,
        &IoStatusBlock,
        &Header,
        sizeof(Header),
        NULL,
        NULL
    );

    if(!NT_SUCCESS(Status)) {
        DbgPrint("Unable to read XBE header");
    }
    else {
        DbgPrint("Read XBE header!");
    }

    if (strncmp((char*)Header.Magic, "XBEH", 4) != 0) {
        DbgPrint("Invalid Magic!\n");
        while (1);
    }

    DPRINT1("Base Address: %x\n", Header.BaseAddress);
    // Copy header data
    PVOID BaseAddress = (PVOID)Header.BaseAddress;
    SIZE_T RegionSize = Header.HeaderSize;
    // TODO: shouldn't really have process handle...
    Status = ZwAllocateVirtualMemory(NtCurrentProcess(), &BaseAddress, 0, &RegionSize, 0x1000, 0x04);
    if(!NT_SUCCESS(Status)) {
        DbgPrint("Failed to allocate XBE header memory :( %X", Status);
    }
    else {
        DbgPrint("Allocated XBE Header memory!");
    }

    // TODO: should copy the extra bytes to right after these ones!
    memcpy((void*)(Header.BaseAddress), &Header, Header.HeaderSize);
    DbgPrint("Finished copying the XBE header!");

    XBE_SECTION *sections = (XBE_SECTION *)Header.Sections;

    // Copy section data
    // TODO: should not be loading all sections by default (see CXBXr source for details..)
    size_t i;
    for (i = 0; i < Header.NumSections; i++) {
        // TODO: should the section headers be kept in memory somewhere?
        XBE_SECTION s;
        LARGE_INTEGER read_offset;
        DbgPrint("About to read Section %i!", (int)i);
        read_offset = RtlConvertUlongToLargeInteger(
            (Header.Sections + (sizeof(XBE_SECTION) * i)) - Header.BaseAddress
        );
        Status = ZwReadFile(
            hFile,
            NULL,
            NULL,
            NULL,
            &IoStatusBlock,
            &s,
            sizeof(s),
            &read_offset,
            NULL
        );
        if(!NT_SUCCESS(Status)) {
            DbgPrint("Failed to read section header :( %X", Status);
        }
        else {
            DbgPrint("Read section header!");
        }

        //DbgPrint("[Section %d] %s\n", i, &xbe_data[s->SectionName-header->BaseAddress]);

        DbgPrint("\tVirtualAddress = %08x\n", s.VirtualAddress);
        DbgPrint("\tVirtualSize    = %08x\n", s.VirtualSize);
        DbgPrint("\tFileAddress    = %08x\n", s.FileAddress);
        DbgPrint("\tFileSize       = %08x\n", s.FileSize);

        BaseAddress = (void*)s.VirtualAddress;
        RegionSize = s.VirtualSize;
        Status = ZwAllocateVirtualMemory(NtCurrentProcess(), &BaseAddress, 0, &RegionSize, 0x1000, 0x40);
        if(!NT_SUCCESS(Status)) {
            DbgPrint("Failed to allocate XBE section memory :( %X", Status);
        }
        else {
            DbgPrint("Allocated XBE section memory!");
        }
        // FIXME: Leak, check return status (we assert now)
        //DbgPrint("Copying %x bytes from %x to %x\n", s->FileSize, &xbe_data[s->FileAddress], (void*)(s->VirtualAddress));
        //memcpy((void*)(s.VirtualAddress), &xbe_data[s->FileAddress], s->FileSize);
        read_offset = RtlConvertUlongToLargeInteger(
            s.FileAddress
        );
        Status = ZwReadFile(
            hFile,
            NULL,
            NULL,
            NULL,
            &IoStatusBlock,
            s.VirtualAddress,
            s.FileSize,
            &read_offset,
            NULL
        );
        
        // Zero out remaining part of section
        memset((void*)(s.VirtualAddress+s.FileSize), 0, s.VirtualSize-s.FileSize);

        DbgPrint("\tLoaded\n");
    }

    xbe_patch_imports(&Header);
}