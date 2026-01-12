#pragma once
#include <Windows.h>
#include <cstdint>
#include <ntstatus.h>
#include <tlhelp32.h>
#include <optional>

#include "Aether.h"

// These are cleaned up at the end of the file
#define NT_FAILURE(NtStatus) NtStatus != 0x00000000

#define VALID_HANDLE(Handle) Handle != nullptr && (Handle) != INVALID_HANDLE_VALUE
#define INVALID_HANDLE(Handle) Handle == nullptr || (Handle) == INVALID_HANDLE_VALUE

namespace Wraith
{
	typedef struct _CLIENT_ID
	{
		HANDLE UniqueProcess;
		HANDLE UniqueThread;
	} CLIENT_ID, *PCLIENT_ID;

	typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
	{
		PVOID       Object;
		HANDLE      UniqueProcessId;
		HANDLE      HandleValue;
		ACCESS_MASK GrantedAccess;
		USHORT      CreatorBackTraceIndex;
		USHORT      ObjectTypeIndex;
		ULONG       HandleAttributes;
		ULONG       Reserved;
	} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

	typedef struct _SYSTEM_HANDLE_INFORMATION_EX
	{
		ULONG_PTR                                                         NumberOfHandles;
		ULONG_PTR                                                         Reserved;
		_Field_size_( NumberOfHandles ) SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[ 1 ];
	} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

	typedef struct _OBJECT_ATTRIBUTES
	{
		ULONG  Length;
		HANDLE RootDirectory;
		PVOID  ObjectName;
		ULONG  Attributes;
		PVOID  SecurityDescriptor;       // PSECURITY_DESCRIPTOR;
		PVOID  SecurityQualityOfService; // PSECURITY_QUALITY_OF_SERVICE
	} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

	// Aether Function Definitions

	inline NTSTATUS RtlAdjustPrivilege( const ULONG Privilege, const BOOLEAN Enable, const BOOLEAN Client, const BOOLEAN* WasEnabled )
	{
		return Aether::Syscall<NTSTATUS>( "RtlAdjustPrivilege", Privilege, Enable, Client, WasEnabled );
	}

	inline NTSTATUS NtQuerySystemInformation( const uint32_t /* SYSTEM_INFORMATION_CLASS */ SystemInformationClass, void* SystemInformation, const ULONG SystemInformationLength, ULONG* ReturnLength = nullptr )
	{
		return Aether::Syscall<NTSTATUS>( "NtQuerySystemInformation", SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength );
	}

	inline NTSTATUS NtOpenProcess( HANDLE* ProcessHandle, const ACCESS_MASK DesiredAccess, const PVOID ObjectAttributes, const PVOID ClientId )
	{
		return Aether::Syscall<NTSTATUS>( "NtOpenProcess", ProcessHandle, DesiredAccess, ObjectAttributes, ClientId );
	}

	inline NTSTATUS NtDuplicateObject( const HANDLE SourceProcessHandle, const HANDLE SourceHandle, const HANDLE TargetProcessHandle, HANDLE* TargetHandle, const ACCESS_MASK DesiredAccess, const ULONG HandleAttributes, const ULONG Options )
	{
		return Aether::Syscall<NTSTATUS>( "NtDuplicateObject", SourceProcessHandle, SourceHandle, TargetProcessHandle, TargetHandle, DesiredAccess, HandleAttributes, Options );
	}

	// Check this in case of failure
	inline NTSTATUS Error = STATUS_SUCCESS;

	inline std::optional<HANDLE> HijackHandle( const uint32_t PID )
	{
		ULONG    Size = 0x10000;
		NTSTATUS Status;
		PVOID    Buffer;

		BOOLEAN oPrivilege = FALSE;
		( void )RtlAdjustPrivilege( 0x14, TRUE, FALSE, &oPrivilege ); // LUID of SeDebugPrivilege == 0x14

		do
		{
			Buffer = VirtualAlloc( nullptr, Size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );

			if ( !Buffer )
			{
				Error = STATUS_INSUFFICIENT_RESOURCES;
				return std::nullopt;
			}

			Status = NtQuerySystemInformation( 64, Buffer, Size, &Size );

			if ( Status == STATUS_INFO_LENGTH_MISMATCH )
			{
				VirtualFree( Buffer, 0, MEM_RELEASE );
				Size *= 2;
			}
		} while ( Status == STATUS_INFO_LENGTH_MISMATCH );

		if ( NT_FAILURE( Status ) )
		{
			Error = Status;
			VirtualFree( Buffer, 0, MEM_RELEASE );
			return std::nullopt;
		}

		const auto        HandleInfo      = static_cast<_SYSTEM_HANDLE_INFORMATION_EX*>( Buffer );
		HANDLE            DuplicateHandle = nullptr;
		CLIENT_ID         cID             = {};
		HANDLE            CurrentHandle   = nullptr;
		OBJECT_ATTRIBUTES Attributes      = { sizeof( OBJECT_ATTRIBUTES ), nullptr, nullptr, 0, nullptr, nullptr };

		for ( ULONG_PTR i = 0; i < HandleInfo->NumberOfHandles; i++ )
		{
			SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX& Info   = HandleInfo->Handles[ i ];
			const HANDLE                       Handle = Info.HandleValue;

			if ( INVALID_HANDLE( Handle ) )
			{
				continue;
			}

			if ( reinterpret_cast<ULONG_PTR>( Info.UniqueProcessId ) == PID )
			{
				continue; // The target process, we don't want to open this one
			}

			if ( VALID_HANDLE( CurrentHandle ) )
			{
				CloseHandle( CurrentHandle );
				CurrentHandle = nullptr;
			}

			cID.UniqueProcess = Info.UniqueProcessId;
			cID.UniqueThread  = nullptr;

			Status = NtOpenProcess( &CurrentHandle, PROCESS_DUP_HANDLE, &Attributes, &cID );

			if ( NT_FAILURE( Status ) )
			{
				continue;
			}

			Status = NtDuplicateObject( CurrentHandle, Info.HandleValue, reinterpret_cast<HANDLE>( -1 ), &DuplicateHandle, PROCESS_ALL_ACCESS, 0, 0 );

			if ( INVALID_HANDLE( DuplicateHandle ) || NT_FAILURE( Status ) )
			{
				continue;
			}

			if ( GetProcessId( DuplicateHandle ) != PID )
			{
				CloseHandle( DuplicateHandle );
				continue;
			}

			return DuplicateHandle;
		}

		Error = STATUS_INVALID_HANDLE;
		return std::nullopt;
	}
}

// Cleanup
#undef NT_FAILURE
#undef VALID_HANDLE
#undef INVALID_HANDLE
