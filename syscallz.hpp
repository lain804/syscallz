#pragma once

#include <Windows.h>
#include <winternl.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <vector>

#define XOR_KEY 0x67

static inline DWORD RvaToFileOffset(PIMAGE_NT_HEADERS ntHeaders, DWORD rva) {
	PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);

	for (int sectionIndex = 0; sectionIndex < ntHeaders->FileHeader.NumberOfSections; ++sectionIndex, ++sectionHeader) {
		DWORD sectionStartRva = sectionHeader->VirtualAddress;
		DWORD sectionSize = sectionHeader->Misc.VirtualSize;

		if (rva >= sectionStartRva and rva < sectionStartRva + sectionSize) {
			DWORD offsetWithinSection = rva - sectionStartRva;
			return sectionHeader->PointerToRawData + offsetWithinSection;
		}
	}

	return NULL;
}

template <size_t N>
struct XorStr {
	char m_data[N];

	consteval XorStr(const char (&str)[N]) {
		for (size_t i = 0; i < N; ++i) {
			m_data[i] = str[i] ^ XOR_KEY;
		}
	}

	std::string str() {
		char buffer[N];
		for (size_t i = 0; i < N; ++i) {
			buffer[i] = m_data[i] ^ XOR_KEY;
		}

		return std::string(buffer, N);
	}
};

static inline std::unordered_map<std::string, uint32_t> buildNtdllMap() {
	std::unordered_map<std::string, uint32_t> syscallMappings;

	HANDLE hFile = CreateFileA(
		XorStr("C:\\Windows\\System32\\ntdll.dll").str().c_str(),
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	DWORD fileSize = GetFileSize(hFile, NULL);

	//printf("File Size: %lu bytes\n", fileSize);

	std::vector<BYTE> buffer(fileSize);

	{
		BOOL ok = ReadFile(hFile, buffer.data(), fileSize, NULL, NULL);
		CloseHandle(hFile);

		if (!ok) {
			//printf("Failed to read file. Error code: %lu\n", GetLastError());
			return {};
		}
	}

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)buffer.data();
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(buffer.data() + dosHeader->e_lfanew);

	DWORD exportsRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	DWORD exportsFileOffset = RvaToFileOffset(ntHeaders, exportsRva);

	BYTE* fileBase = buffer.data();

	PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)(fileBase + exportsFileOffset);

	DWORD exportNamesOffset = RvaToFileOffset(ntHeaders, exportDirectory->AddressOfNames);
	DWORD* exportNameRvas = (DWORD*)(fileBase + exportNamesOffset);

	DWORD ordinalsOffset = RvaToFileOffset(ntHeaders, exportDirectory->AddressOfNameOrdinals);
	WORD* ordinals = (WORD*)(fileBase + ordinalsOffset);

	DWORD functionsOffset = RvaToFileOffset(ntHeaders, exportDirectory->AddressOfFunctions);
	DWORD* functionRvas = (DWORD*)(fileBase + functionsOffset);

	for (DWORD i = 0; i < exportDirectory->NumberOfNames; ++i) {
		DWORD nameRva = exportNameRvas[i];

		if (not nameRva) {
			continue;
		}

		DWORD nameFileOffset = RvaToFileOffset(ntHeaders, nameRva);
		const char* exportName = (const char*)(fileBase + nameFileOffset);

		if (not exportName) {
			continue;
		}

		WORD ordinal = ordinals[i];

		DWORD functionRva = functionRvas[ordinal];
		DWORD functionFileOffset = RvaToFileOffset(ntHeaders, functionRva);
		BYTE* functionPtr = fileBase + functionFileOffset;

		// sneaky
		BYTE syscallStubSignature[] = { 0xC3 };
		if (memcmp(syscallStubSignature, functionPtr+20, sizeof(syscallStubSignature)) != 0) {
			continue;
		}

		uint32_t syscallIndex;
		short syscallOffset = 0x4;
		memcpy(&syscallIndex, functionPtr + syscallOffset, sizeof(syscallIndex));

		//printf("%s : syscall hex index: %X\n", exportName, syscallIndex);

		syscallMappings.emplace(exportName, syscallIndex);
	}

	return syscallMappings;
}

using SetSyscallIndexStub = void(NTAPI*)(uint32_t);
using ResetSyscallIndexStub = void(NTAPI*)();

inline uint32_t syscallIndex = 0;
inline BYTE* syscallStubPage = nullptr;
inline SetSyscallIndexStub setSyscallIndexStub = nullptr;
inline void* executeSyscallWithArgsStub = nullptr;
inline ResetSyscallIndexStub resetSyscallIndexStub = nullptr;

static inline void PatchAddress(BYTE* code, size_t offset, const void* address) {
	const auto patchedAddress = reinterpret_cast<uintptr_t>(address);
	std::memcpy(code + offset, &patchedAddress, sizeof(patchedAddress));
}

static inline bool InitSyscallStub() {
	constexpr std::array<BYTE, 13> setSyscallIndexCode = {
		0x48, 0xB8,                         // mov rax, imm64
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x89, 0x08,                         // mov dword ptr [rax], ecx
		0xC3                                // ret
	};

	constexpr std::array<BYTE, 18> executeSyscallWithArgsCode = {
		0x48, 0xB8,                         // mov rax, imm64
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x8B, 0x00,                         // mov eax, dword ptr [rax]
		0x4C, 0x8B, 0xD1,                   // mov r10, rcx
		0x0F, 0x05,                         // syscall
		0xC3                                // ret
	};

	constexpr std::array<BYTE, 17> resetSyscallIndexCode = {
		0x48, 0xB8,                         // mov rax, imm64
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0xC7, 0x00,                         // mov dword ptr [rax], imm32
		0x00, 0x00, 0x00, 0x00,
		0xC3                                // ret
	};

	constexpr SIZE_T stubSize =
		setSyscallIndexCode.size() +
		executeSyscallWithArgsCode.size() +
		resetSyscallIndexCode.size();

	BYTE* page = static_cast<BYTE*>(VirtualAlloc(
		nullptr,
		stubSize,
		MEM_RESERVE | MEM_COMMIT,
		PAGE_READWRITE
	));

	if (not page) {
		return false;
	}

	BYTE* cursor = page;

	BYTE* setSyscallIndex = cursor;
	std::memcpy(cursor, setSyscallIndexCode.data(), setSyscallIndexCode.size());
	PatchAddress(cursor, 2, &syscallIndex);
	cursor += setSyscallIndexCode.size();

	BYTE* executeSyscallWithArgs = cursor;
	std::memcpy(cursor, executeSyscallWithArgsCode.data(), executeSyscallWithArgsCode.size());
	PatchAddress(cursor, 2, &syscallIndex);
	cursor += executeSyscallWithArgsCode.size();

	BYTE* resetSyscallIndex = cursor;
	std::memcpy(cursor, resetSyscallIndexCode.data(), resetSyscallIndexCode.size());
	PatchAddress(cursor, 2, &syscallIndex);

	DWORD oldProtect = 0;
	if (not VirtualProtect(page, stubSize, PAGE_EXECUTE, &oldProtect)) {
		VirtualFree(page, 0, MEM_RELEASE);
		return false;
	}

	FlushInstructionCache(GetCurrentProcess(), page, stubSize);

	syscallStubPage = page;
	setSyscallIndexStub = reinterpret_cast<SetSyscallIndexStub>(setSyscallIndex);
	executeSyscallWithArgsStub = executeSyscallWithArgs;
	resetSyscallIndexStub = reinterpret_cast<ResetSyscallIndexStub>(resetSyscallIndex);

	return true;
}

static inline bool syscallStubReady = InitSyscallStub();

static inline void SetSyscallIndex(uint32_t idx) {
	setSyscallIndexStub(idx);
}

template <typename T>
static decltype(auto) NormalizeSyscallArg(T&& value) {
	using Arg = std::remove_cvref_t<T>;

	if constexpr (std::is_null_pointer_v<Arg>) {
		return static_cast<void*>(nullptr);
	}
	else if constexpr (std::is_enum_v<Arg>) {
		return static_cast<uintptr_t>(value);
	}
	else if constexpr (std::is_integral_v<Arg> && sizeof(Arg) < sizeof(uintptr_t)) {
		if constexpr (std::is_signed_v<Arg>) {
			return static_cast<intptr_t>(value);
		}
		else {
			return static_cast<uintptr_t>(value);
		}
	}
	else {
		return std::forward<T>(value);
	}
}

template <typename... Args>
static inline NTSTATUS ExecuteSyscallWithArgs(Args&&... args) {
	using ExecuteSyscallWithArgsFn = NTSTATUS(*)(...);
	auto executeSyscallWithArgs = reinterpret_cast<ExecuteSyscallWithArgsFn>(executeSyscallWithArgsStub);

	return executeSyscallWithArgs(NormalizeSyscallArg(std::forward<Args>(args))...);
}

static inline void ResetSyscallIndex() {
	resetSyscallIndexStub();
}

// Helper struct so we can select the syscall id using the template string (C++20).
template <size_t N>
struct ProcName {
	char m_procName[N];

	constexpr ProcName(const char (&procName)[N]) {
		for (size_t i = 0; i < N; ++i) {
			m_procName[i] = procName[i] ^ XOR_KEY;
		}
	}

};

static inline auto ntdllMappings = std::unordered_map<std::string, uint32_t>{};

namespace syscallz {
	inline void init() {
		ntdllMappings = buildNtdllMap();
	}

	template <ProcName procName, typename... Args>
	NTSTATUS syscall(Args&&... args) {
		constexpr size_t procNameLength = sizeof(procName.m_procName);

		char decryptedProcName[procNameLength];

		for (size_t i = 0; i < procNameLength; ++i) {
			decryptedProcName[i] = procName.m_procName[i] ^ XOR_KEY;
		}

		std::string exportName = decryptedProcName;

		//printf("looking for: %s\n", exportName.c_str());

		auto it = ntdllMappings.find(exportName);

		if (it == ntdllMappings.end()) {
			//printf("failed to find %s in map\n", exportName.c_str());
			return -1;
		}

		//printf("found %s in map, setting syscall idx to %u and executing..\n", exportName.c_str(), it->second);

		SetSyscallIndex(it->second);
		NTSTATUS ok = ExecuteSyscallWithArgs(std::forward<Args>(args)...);
		ResetSyscallIndex();

		//printf("executed syscall and cleared index, returning NTSTATUS 0x%X\n", ok);

		return ok;
	}
}
