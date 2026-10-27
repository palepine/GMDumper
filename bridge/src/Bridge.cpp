/*
  GMDumperBridge - GameMaker game-thread reflection bridge
  Copyright (C) 2026 palepine

  GPL-3.0-or-later. See LICENSE in the project root.

  For YYToolkit interoperability, runner-interface recovery identifies the
  extension-interface initializer and reconstructs selected ABI entries from
  its RIP-relative LEA / stack MOV assignments. This implementation is original.
*/

/*
Zyan Disassembler Library (Zydis)
Original Author: Florian Bernd

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

/*
MinHook - The Minimalistic API Hooking Library for x64/x86
Copyright (C) 2009-2017 Tsuda Kageyu.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

 1. Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.
 2. Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER
OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

================================================================================
Portions of this software are Copyright (c) 2008-2009, Vyacheslav Patkov.
================================================================================
Hacker Disassembler Engine 32 C
Copyright (c) 2008-2009, Vyacheslav Patkov.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

 1. Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.
 2. Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

-------------------------------------------------------------------------------
Hacker Disassembler Engine 64 C
Copyright (c) 2008-2009, Vyacheslav Patkov.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

 1. Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.
 2. Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#include "GMDumperBridge.h"

#include <MinHook.h>
#include <Zydis/Zydis.h>
#include <Windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <deque>
#include <limits>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

/*
  GameMaker's reflection and script APIs are not thread-safe. It handles:

    1. Discovery/configuration finds runner functions and installs a Code_Execute detour
    2. Request execution moves work queued by CE onto the runner thread, copies the result into bridge-owned storage, and lets CE read that copy later
  
*/
namespace gmd::bridge::detail
{
  // ------------------------------ Limits and ABI ------------------------------

  constexpr std::uint32_t BridgeAbi = 1;
  constexpr std::uint32_t MaximumMemberLimit = 1u << 20;
  constexpr std::uint32_t MaximumArgumentCount = 4096;

  // ---------------------------- Discovery model -------------------------------

  // Offsets are relative to the beginning of YYRunnerInterface. They are supplied by the version profile from CE due to instability
  struct DiscoveryProfile
  {
    std::ptrdiff_t yy_get_string_offset{ 16 * sizeof(void*) };
    std::ptrdiff_t free_rvalue_offset{ 27 * sizeof(void*) };
    std::ptrdiff_t script_find_id_offset{ 30 * sizeof(void*) };
    std::ptrdiff_t script_perform_offset{ 31 * sizeof(void*) };
    std::ptrdiff_t struct_add_rvalue_offset{ 79 * sizeof(void*) };
    std::ptrdiff_t struct_get_member_offset{ 91 * sizeof(void*) };
    std::ptrdiff_t struct_get_keys_offset{ 92 * sizeof(void*) };
    std::ptrdiff_t array_get_length_offset{ 98 * sizeof(void*) };
    std::size_t minimum_assignments{ 88 };
    std::size_t maximum_assignments{ 160 };
    std::int64_t maximum_stack_span{ 0x380 };
    std::uintptr_t maximum_instruction_span{ 0x1400 };
    std::uintptr_t maximum_function_distance{ 0x800 };
    std::int64_t maximum_base_slack{};
  };

#pragma pack(push, 4)

  // Modern RValue ABI. Explicit packing keeps the public record stable and makes accidental layout drift a compile-time failure below
  struct RValue
  {
    union
    {
      double real;
      std::int64_t i64;
      std::int32_t i32;
      void* pointer;
    } value{};

    std::uint32_t flags{};
    std::int32_t kind{ 5 };
  };

#pragma pack(pop)

  static_assert( sizeof(RValue) == 16 );

  static_assert( sizeof(GmdRValue) == sizeof(RValue) );

#if defined(_WIN64)

  constexpr auto MachineMode = ZYDIS_MACHINE_MODE_LONG_64;
#define GMD_CODE_EXECUTE_CONVENTION __fastcall

#else

  constexpr auto MachineMode = ZYDIS_MACHINE_MODE_LEGACY_32;
#define GMD_CODE_EXECUTE_CONVENTION __cdecl

#endif

  using CodeExecute = bool( GMD_CODE_EXECUTE_CONVENTION* )( void*, void*, void*, RValue*, int );

  using StructGetKeys = int (*)( RValue*, const char**, int* );

  using StructGetMember = RValue* (*)( RValue*, const char* );

  using YYGetString = const char* (*)( const RValue*, int );

  using FreeRValue = void (*)( RValue* );

  using FindVariableSlot = int (*)( void*, const char* );

#if !defined(_WIN64)

  // x86 GMS2 runners expose no stable name-to-slot interface entry.
  // variable_instance_get_names routine obtains each name from object's member dictionary with this internal helper
  using VariableNameFromSlot = const char* (__cdecl*)( int, int, int );

  // GMS2 2.2 and earlier expose the same dictionary only through an iterator used by variable_instance_get_names
  // The iterator advances two caller-owned cursors & returns a pointer to the current value entry (or null after the final entry).
  using MemberDictionaryIterator = void* (__thiscall*)( void*, int*, int* );

#endif

  using ScriptFindId = int (*)( const char* );

  using ScriptPerform = bool (*)( int, void*, void*, int, RValue*, RValue* );

  using ArrayGetLength = int (*)( RValue* );

  using Routine = void (*)( RValue&, void*, void*, int, RValue* );

  /// Return true for a register that may address the temporary interface.
  ///
  /// x64 runner initializers use their frame/stack pointer
  // Older x86 runners commonly keep the destination interface pointer in a general register.
  bool interface_base_register(ZydisRegister value)
  {
#if defined(_WIN64)
    return value == ZYDIS_REGISTER_RBP || value == ZYDIS_REGISTER_RSP;
#else
    switch (value)
    {
      case ZYDIS_REGISTER_EAX:
      case ZYDIS_REGISTER_EBX:
      case ZYDIS_REGISTER_ECX:
      case ZYDIS_REGISTER_EDX:
      case ZYDIS_REGISTER_ESI:
      case ZYDIS_REGISTER_EDI:
      case ZYDIS_REGISTER_EBP:
      case ZYDIS_REGISTER_ESP:
        return true;
      default:
        return false;
    }
#endif
  }

  // ------------------------------- Requests -----------------------------------

  enum class RequestKind
  {
    Members,
    Array,
    Script,
    Routine
  };

  struct Request
  {
    RequestKind kind{ RequestKind::Members };

    void* object{};

    std::uint32_t maximum{};

    std::atomic< GmdRequestStatus > status{ GmdRequestStatus::Queued };

    std::vector< GmdMemberRecord > members;

    std::string script_name;

    Routine routine{};

    void* self{};

    void* other{};

    std::vector<RValue> arguments;

    RValue result;

    int script_id{ -1 };

    std::string error;
  };

  // ------------------------- Disassembly observations --------------------------

  struct Section
  {
    std::byte* start{};
    std::size_t size{};
  };

  struct Assignment
  {
    std::uintptr_t instruction{};
    std::int64_t displacement{};
    std::uintptr_t target{};
    ZydisRegister stack_base{ ZYDIS_REGISTER_NONE };
  };

  // ------------------------------ Shared state --------------------------------

  // Queue ownership is guarded by g_mutex
  // Request payloads become immutable before they enter the queue; only their atomic status changes concurrently
  std::mutex g_mutex;

  std::unordered_set< Request* > g_requests;

  std::deque< Request* > g_queue;

  std::atomic< std::uint32_t > g_active_dispatches{};

  std::atomic< std::uint32_t > g_pending_requests{};

  std::atomic< DWORD > g_scheduler_thread{};

  // Runner functions are published atomically because configuration happens on a CE thread while requests consume them on the GM thread
  std::atomic< StructGetKeys > g_struct_get_keys{};

  std::atomic< StructGetMember > g_struct_get_member{};

  std::atomic< YYGetString > g_yy_get_string{};

  std::atomic< FreeRValue > g_free_rvalue{};

  std::atomic< FindVariableSlot > g_find_variable_slot{};

  std::atomic< Routine > g_struct_add_rvalue{};

  std::atomic< Routine > g_member_get_names{};

  std::atomic< Routine > g_member_names_count{};

#if !defined(_WIN64)

  std::atomic< VariableNameFromSlot > g_variable_name_from_slot{};

  std::atomic< MemberDictionaryIterator > g_member_dictionary_iterator{};

  std::atomic< std::int32_t > g_member_dictionary_variable_base{};

  std::atomic< std::int32_t > g_member_dictionary_offset{ -1 };

  std::atomic< std::int32_t > g_member_dictionary_entries_offset{ -1 };

  std::atomic< std::int32_t > g_member_dictionary_slot_offset{ -1 };

  std::atomic< std::int32_t > g_member_dictionary_state_offset{ -1 };

  std::atomic< std::int32_t > g_member_dictionary_count_offset{};

  std::atomic< std::int32_t > g_member_dictionary_mask_offset{ -1 };

  std::atomic< bool > g_member_dictionary_hash_state{};

#endif

  std::atomic< ScriptFindId > g_script_find_id{};

  std::atomic< ScriptPerform > g_script_perform{};

  std::atomic< ArrayGetLength > g_array_get_length{};

  std::atomic< Routine > g_array_length_routine{};

  std::atomic< std::int64_t > g_array_storage_offset{ -1 };

  std::atomic< Routine > g_script_execute{};

  // MinHook dispatcher state is mutated only while g_mutex is held.
  CodeExecute g_code_execute_original{};

  void* g_code_execute_target{};

  bool g_hook_created{};

  bool g_minhook_initialized{};

  // Discovery and error text have independent locks so a status query never waits behind queue processing
  std::mutex g_error_mutex;

  std::mutex g_discovery_mutex;

  DiscoveryProfile g_discovery_profile;

  std::string g_last_error;

  // ----------------------------- Error channel --------------------------------

  /// Store the last err msg returned through gmd_get_last_error().
  void set_error(std::string value)
  {
    std::scoped_lock lock( g_error_mutex );

    g_last_error = std::move(value);
  }

  /// Clear stale err msg before starting a public operation.
  void clear_error()
  {
    std::scoped_lock lock( g_error_mutex );
    g_last_error.clear();
  }

  // ---------------------- Runner-interface discovery ---------------------------

  /// Locate mapped PE section
  bool image_section(HMODULE module, const char name[8], Section &result)
  {
    if (!module)
    {
      return false;
    }

    const auto base = reinterpret_cast< std::byte* >( module );

    const auto dos = reinterpret_cast< const IMAGE_DOS_HEADER* >( base );
    
    if ( dos->e_magic != IMAGE_DOS_SIGNATURE )
    {
      return false;
    }
    
    const auto nt = reinterpret_cast< const IMAGE_NT_HEADERS* >( base + dos->e_lfanew );
    
    if ( nt->Signature != IMAGE_NT_SIGNATURE )
    {
      return false;
    }
    
    const auto sections = IMAGE_FIRST_SECTION(nt);
    
    for (unsigned index = 0; index < nt->FileHeader.NumberOfSections; ++index)
    {
      if ( std::strncmp( reinterpret_cast< const char* >( sections[index].Name ), name, 8 ) == 0 )
      {
        result.start = base + sections[ index ].VirtualAddress;
        result.size = std::max< std::size_t >( sections[ index ].Misc.VirtualSize, sections[ index ].SizeOfRawData );
        return true;
      }
    }
    return false;
  }

  /// Return the PE preferred image base recorded in the optional header.
  std::uintptr_t preferred_image_base(HMODULE module)
  {
    if ( !module )
    {
      return 0;
    }

    const auto base = reinterpret_cast< const std::byte* >( module );
    const auto dos = reinterpret_cast< const IMAGE_DOS_HEADER* >( base );

    if ( dos->e_magic != IMAGE_DOS_SIGNATURE ) return 0;

    const auto nt = reinterpret_cast< const IMAGE_NT_HEADERS* >( base + dos->e_lfanew );
    if ( nt->Signature != IMAGE_NT_SIGNATURE ) return 0;

    return static_cast< std::uintptr_t >( nt->OptionalHeader.ImageBase );
  }

  /// Recover YYRunnerInterface member assignments from the executable section.
  ///
  /// The extension initializer gets runner function addresses & stores them into a stack-local YYRunnerInterface
  // x64 normally uses RIP-relative LEA followed by MOV
  // x86 normally uses an immediate MOV, either directly into the stack slot or through a register.
  // Coherent initializer frames are selected & validated later by discover_reflection().
  std::vector< Assignment > collect_stack_assignments(const Section &text)
  {
    std::vector< Assignment > output;
    std::uintptr_t runtime = reinterpret_cast< std::uintptr_t >( text.start );
    const auto end = runtime + text.size;
    ZydisRegister last_register = ZYDIS_REGISTER_NONE;
    std::uintptr_t last_target{};
    std::uintptr_t last_lea{};

    while ( runtime < end )
    {
      ZydisDisassembledInstruction instruction{};

      if ( !ZYAN_SUCCESS( ZydisDisassembleIntel( MachineMode, runtime, reinterpret_cast< const void* >( runtime ), end - runtime, &instruction ) ) )
      {
        ++runtime;
        continue;
      }

      // remember the most recent executable address stored into a register.
      // the MOV below must consume this same register shortly.
      if (
            instruction.info.mnemonic == ZYDIS_MNEMONIC_LEA &&
            instruction.info.operand_count_visible >= 2 &&
            instruction.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            instruction.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&

#if defined(_WIN64)
            instruction.operands[1].mem.base == ZYDIS_REGISTER_RIP
#else
            instruction.operands[1].mem.base == ZYDIS_REGISTER_NONE &&
            instruction.operands[1].mem.index == ZYDIS_REGISTER_NONE
#endif

          )
      {
        ZyanU64 absolute{};

        if ( ZYAN_SUCCESS( ZydisCalcAbsoluteAddress( &instruction.info, &instruction.operands[1], runtime, &absolute ) ) )
        {
          last_register = ZydisRegisterGetLargestEnclosing( MachineMode, instruction.operands[0].reg.value );
          
          if ( last_register == ZYDIS_REGISTER_NONE )
          {
            last_register = instruction.operands[0].reg.value;
          }

          last_target = static_cast< std::uintptr_t >( absolute );
          last_lea = runtime;
        }

      }

#if !defined(_WIN64)

      // x86 commonly gets a function address with MOV reg, imm32.
      else if (
                instruction.info.mnemonic == ZYDIS_MNEMONIC_MOV &&
                instruction.info.operand_count_visible >= 2 &&
                instruction.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                instruction.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                !instruction.operands[1].imm.is_relative
              )
      {
        last_register = ZydisRegisterGetLargestEnclosing( MachineMode, instruction.operands[0].reg.value );

        if ( last_register == ZYDIS_REGISTER_NONE )
        {
          last_register = instruction.operands[0].reg.value;
        }

        last_target = static_cast< std::uintptr_t >( instruction.operands[1].imm.value.u );
        last_lea = runtime;
      }

      // MSVC x86 also emits MOV [ebp/esp+slot], imm32 directly.
      else if (
                instruction.info.mnemonic == ZYDIS_MNEMONIC_MOV &&
                instruction.info.operand_count_visible >= 2 &&
                instruction.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                interface_base_register( instruction.operands[0].mem.base ) &&
                instruction.operands[0].mem.index == ZYDIS_REGISTER_NONE &&
                instruction.operands[0].mem.disp.has_displacement &&
                instruction.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                !instruction.operands[1].imm.is_relative
              )
      {
        output.push_back(
          Assignment
          {
            runtime,
            instruction.operands[0].mem.disp.value,
            static_cast< std::uintptr_t >( instruction.operands[1].imm.value.u ),
            instruction.operands[0].mem.base
          }
        );
      }

#endif

      // associate the remembered address with its interface slot.
      // both frame-pointer & stack-pointer initializers exist in the wild.
      else if (
                instruction.info.mnemonic == ZYDIS_MNEMONIC_MOV &&
                instruction.info.operand_count_visible >= 2 &&
                instruction.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                interface_base_register( instruction.operands[0].mem.base ) &&
                instruction.operands[0].mem.index == ZYDIS_REGISTER_NONE &&
                instruction.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                runtime - last_lea <= 24
              )
      {
        auto source = ZydisRegisterGetLargestEnclosing( MachineMode, instruction.operands[1].reg.value );

        if ( source == ZYDIS_REGISTER_NONE )
        {
          source = instruction.operands[1].reg.value;
        }

        if ( source == last_register && instruction.operands[0].mem.disp.has_displacement )
        {
          output.push_back( Assignment
                            {
                              last_lea,
                              instruction.operands[0].mem.disp.value,
                              last_target,
                              instruction.operands[0].mem.base
                            }
                          );
        }

      }

      runtime += instruction.info.length;
    }
    return output;
  }

  /// Decode a bounded straight-line instruction sequence.
  ///
  /// It stops at the first undecodable instruction. It's used for small known runner functions
  std::vector< ZydisDisassembledInstruction > disassemble(void* start, std::size_t maximum)
  {
    std::vector< ZydisDisassembledInstruction > result;

    auto runtime = reinterpret_cast< std::uintptr_t >( start );

    const auto end = runtime + maximum;

    while ( runtime < end )
    {
      ZydisDisassembledInstruction instruction{};

      if ( !ZYAN_SUCCESS( ZydisDisassembleIntel( MachineMode, runtime, reinterpret_cast< const void* >( runtime ), end - runtime, &instruction ) ) )
      {
        break;
      }

      result.push_back( instruction );

      runtime += instruction.info.length;
    }
    
    return result;
  }

  /// Follow a bounded chain of compiler/linker jump thunks.
  ///
  /// Four hops cover import & incremental-link thunks while preventing a malformed runner from causing an unbounded walk.
  void* follow_direct_jumps(void* function)
  {
    auto* current = function;

    for (int depth = 0; current && depth < 4; ++depth)
    {
      const auto instructions = disassemble( current, 16 );

      if ( instructions.empty() || instructions[0].info.mnemonic != ZYDIS_MNEMONIC_JMP || instructions[0].info.operand_count_visible == 0 )
      {
        break;
      }

      ZyanU64 target{};

      if ( !ZYAN_SUCCESS( ZydisCalcAbsoluteAddress( &instructions[0].info, &instructions[0].operands[0], instructions[0].runtime_address, &target ) ) || !target )
      {
        break;
      }

      current = reinterpret_cast< void* >( static_cast< std::uintptr_t >( target ) );
    }

    return current;
  }

#if defined(_WIN64)

  /// Score the structural operations required of StructGetKeys.
  ///
  /// key enumerator walks the YYObjectBase member map, indexes 16-byte entries,
  // writes name pointers to the caller-provided output array. 
  std::uint32_t struct_get_keys_score(void* function)
  {
    const auto instructions = disassemble( follow_direct_jumps( function ), 0x180 );
    
    std::uint32_t member_map_accesses{};
    
    bool scales_entries{};
    
    bool writes_output_array{};

    for (const auto &instruction : instructions)
    {
      if ( instruction.info.mnemonic == ZYDIS_MNEMONIC_RET || instruction.info.mnemonic == ZYDIS_MNEMONIC_INT3 )
      {
        break;
      }

      for (std::uint8_t index = 0; index < instruction.info.operand_count_visible; ++index)
      {
        const auto &operand = instruction.operands[ index ];

        if ( operand.type == ZYDIS_OPERAND_TYPE_MEMORY && operand.mem.disp.has_displacement && operand.mem.disp.value == 0x48 )
        {
          ++member_map_accesses;
        }
      }

      if (
           instruction.info.mnemonic == ZYDIS_MNEMONIC_SHL &&
           instruction.info.operand_count_visible >= 2 &&
           instruction.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
           instruction.operands[1].imm.value.u == 4
         )
      {
        scales_entries = true;
      }

      if (
           instruction.info.mnemonic == ZYDIS_MNEMONIC_MOV &&
           instruction.info.operand_count_visible >= 2 &&
           instruction.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
           instruction.operands[0].mem.index != ZYDIS_REGISTER_NONE &&
           instruction.operands[0].mem.scale == 8 &&
           instruction.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER
         )
      {
        writes_output_array = true;
      }
    }

    return member_map_accesses + (scales_entries ? 1u : 0u) + (writes_output_array ? 1u : 0u);
  }

#endif

  /// Return the first direct CALL/JMP target in a bounded function prefix.
  void* first_direct_target(void* function, std::size_t maximum, bool accept_jump)
  {
    const auto instructions = disassemble( function, maximum );

    for (const auto &instruction : instructions)
    {
      if ( instruction.info.mnemonic != ZYDIS_MNEMONIC_CALL && ( !accept_jump || instruction.info.mnemonic != ZYDIS_MNEMONIC_JMP ) )
      {
        continue;
      }

      if ( instruction.info.operand_count_visible == 0 )
      {
        continue;
      }

      ZyanU64 target{};

      if ( ZYAN_SUCCESS( ZydisCalcAbsoluteAddress( &instruction.info, &instruction.operands[0], instruction.runtime_address, &target ) ) && target )
      {
        return reinterpret_cast< void* >( static_cast< std::uintptr_t >( target ) );
      }
    }

    return nullptr;
  }

  /// Recover Code_Variable_FindAlloc_Slot_From_Name from StructAddRValue.
  ///
  /// YYRunnerInterface::StructAddRValue first enters YYObjectBase::Add
  /// that implementation's 1st direct call resolves/allocates the runtime slot.
  /// The fallback calls it only for names returned by the runner itself, no requests creation of an unknown field.
  FindVariableSlot discover_find_variable_slot(void* struct_add_rvalue)
  {
    if ( !struct_add_rvalue )
    {
      return nullptr;
    }

    const auto object_add = first_direct_target( struct_add_rvalue, 32, true );
    const auto find_slot = object_add ? first_direct_target( object_add, 48, false ) : nullptr;

    return reinterpret_cast< FindVariableSlot >( find_slot );
  }

  bool executable_pointer(const void* address)
  {
    MEMORY_BASIC_INFORMATION region{};

    if ( !address || !VirtualQuery( address, &region, sizeof(region) ) || region.State != MEM_COMMIT )
    {
      return false;
    }

    const auto protection = region.Protect & 0xFF;

    return protection == PAGE_EXECUTE || protection == PAGE_EXECUTE_READ || protection == PAGE_EXECUTE_READWRITE || protection == PAGE_EXECUTE_WRITECOPY;
  }

#if !defined(_WIN64)

  /// Recover the member-dictionary walk used by x86 GMS2's variable_instance_get_names implementation.
  ///
  /// they dont expose StructGetMember API, YYRunnerInterface slot historically used to infer a name-to-slot helper isnt stable.
  /// public get-names built-in seemingly more reliable: its loop reads each live dictionary entry's slot, converts it to a name.
  bool discover_x86_member_dictionary(Routine get_names, Routine names_count)
  {
    g_variable_name_from_slot.store( nullptr, std::memory_order_release );

    g_member_dictionary_iterator.store( nullptr, std::memory_order_release );

    g_member_dictionary_variable_base.store( 0, std::memory_order_release );

    g_member_dictionary_offset.store( -1, std::memory_order_release );

    g_member_dictionary_entries_offset.store( -1, std::memory_order_release );

    g_member_dictionary_slot_offset.store( -1, std::memory_order_release );

    g_member_dictionary_state_offset.store( -1, std::memory_order_release );

    g_member_dictionary_count_offset.store( 0, std::memory_order_release );

    g_member_dictionary_mask_offset.store( -1, std::memory_order_release );

    g_member_dictionary_hash_state.store( false, std::memory_order_release );

    if ( !executable_pointer( reinterpret_cast< void* >( get_names ) ) )
    {
      return false;
    }

    const auto* code = static_cast< const std::uint8_t* >( follow_direct_jumps( reinterpret_cast< void* >( get_names ) ) );

    if (!code)
    {
      return false;
    }

    __try
    {
      // GMS2 2.2 & earlier use an iterator instead of exposing the dictionary's entry array
      // Recognize the complete operation:
      //   map = object->members
      //   entry = iterate(map, &cursor_a, &cursor_b)
      //   name = name_from_slot(0, -1, cursor_b + variable_base)
      // This generation has variable_instance_get_names but no separate count built-in.
      for (std::size_t header = 0; header + 8 < 0x180; ++header)
      {
        if (
             code[ header + 0 ] != 0x8B ||
             code[ header + 1 ] != 0x4B ||
             code[ header + 3 ] != 0x85 ||
             code[ header + 4 ] != 0xC9
           )
        {
          continue;
        }

        const auto dictionary_offset = static_cast< std::int32_t >( code[ header + 2 ] );

        if ( dictionary_offset <= 0 || dictionary_offset > 0x100 )
        {
          continue;
        }

        MemberDictionaryIterator iterator{};

        for (std::size_t cursor = header + 5; cursor + 24 < std::min<std::size_t>( header + 0x80, 0x200 ); ++cursor)
        {
          std::size_t call_offset{};

          // Optimized builds either emit the two LEA/PUSH pairs contiguously or initialize each cursor between its LEA and PUSH.
          if (
               code[ cursor + 0 ] == 0x8D &&
               code[ cursor + 1 ] == 0x44 &&
               code[ cursor + 2 ] == 0x24 &&
               code[ cursor + 4 ] == 0x50 &&
               code[ cursor + 5 ] == 0x8D &&
               code[ cursor + 6 ] == 0x44 &&
               code[ cursor + 7 ] == 0x24 &&
               code[ cursor + 9 ] == 0x50 &&
               code[ cursor + 10 ] == 0xE8
             )
          {
            call_offset = cursor + 10;
          }
          else if (
                    code[ cursor + 0 ] == 0x8D &&
                    code[ cursor + 1 ] == 0x44 &&
                    code[ cursor + 2 ] == 0x24 &&
                    code[ cursor + 4 ] == 0x89 &&
                    code[ cursor + 5 ] == 0x6C &&
                    code[ cursor + 6 ] == 0x24 &&
                    code[ cursor + 8 ] == 0x50 &&
                    code[ cursor + 9 ] == 0x8D &&
                    code[ cursor + 10 ] == 0x44 &&
                    code[ cursor + 11 ] == 0x24 &&
                    code[ cursor + 13 ] == 0x89 &&
                    code[ cursor + 14 ] == 0x6C &&
                    code[ cursor + 15 ] == 0x24 &&
                    code[ cursor + 17 ] == 0x50 &&
                    code[ cursor + 18 ] == 0xE8
                  )
          {
            call_offset = cursor + 18;
          }

          if (call_offset)
          {
            std::int32_t relative{};

            std::memcpy( &relative, code + call_offset + 1, sizeof(relative) );

            iterator = reinterpret_cast< MemberDictionaryIterator >( const_cast< std::uint8_t* >( code + call_offset + 5 + relative ) );
            break;
          }
        }

        if ( !iterator || !executable_pointer( reinterpret_cast<void*>(iterator) ) )
        {
          continue;
        }

        VariableNameFromSlot name_from_slot{};
        std::int32_t variable_base{};

        for (std::size_t cursor = header + 5; cursor + 19 < std::min<std::size_t>( header + 0x100, 0x240 ); ++cursor)
        {
          if (
                code[ cursor + 0 ] != 0x8B ||
                code[ cursor + 1 ] != 0x44 ||
                code[ cursor + 2 ] != 0x24 ||
                code[ cursor + 4 ] != 0x05 ||
                code[ cursor + 9 ] != 0x50
              )
          {
            continue;
          }

          std::size_t zero_push{};

          if ( code[ cursor + 10 ] == 0x6A && code[ cursor + 11 ] == 0xFF )
          {
            zero_push = cursor + 12;
          }
          else if ( code[ cursor + 10 ] >= 0x50 && code[ cursor + 10 ] <= 0x57 )
          {
            zero_push = cursor + 11;
          }

          if ( zero_push && code[ zero_push ] == 0x6A && code[ zero_push + 1 ] == 0x00 && code[ zero_push + 2 ] == 0xE8 )
          {
            std::int32_t relative{};

            std::memcpy( &variable_base, code + cursor + 5, sizeof( variable_base ) );

            std::memcpy( &relative, code + zero_push + 3, sizeof( relative ) );

            name_from_slot = reinterpret_cast< VariableNameFromSlot >( const_cast< std::uint8_t* >( code + zero_push + 7 + relative ) );
            break;
          }
        }

        if ( !name_from_slot || !executable_pointer( reinterpret_cast<void*>(name_from_slot) ) || variable_base < 0 || variable_base > 10000000 )
        {
          continue;
        }

        g_member_dictionary_offset.store( dictionary_offset, std::memory_order_release );

        g_member_dictionary_iterator.store( iterator, std::memory_order_release );

        g_member_dictionary_variable_base.store( variable_base, std::memory_order_release );

        g_variable_name_from_slot.store( name_from_slot, std::memory_order_release );

        return true;
      }

      for (std::size_t header = 0; header + 15 < 0x180; ++header)
      {
        // mov ecx,[ebx+dictionary]
        // lea eax,[esi+esi*2]
        // inc esi
        // mov ebx,[ecx+entries]
        // mov edi,[ecx]
        // lea edx,[ebx+eax*4]
        if (
             code[ header + 0 ] != 0x8B ||
             code[ header + 1 ] != 0x4B ||
             code[ header + 3 ] != 0x8D ||
             code[ header + 4 ] != 0x04 ||
             code[ header + 5 ] != 0x76 ||
             code[ header + 6 ] != 0x46 ||
             code[ header + 7 ] != 0x8B ||
             code[ header + 8 ] != 0x59 ||
             code[ header + 10 ] != 0x8B ||
             code[ header + 11 ] != 0x39 ||
             code[ header + 12 ] != 0x8D ||
             code[ header + 13 ] != 0x14 ||
             code[ header + 14 ] != 0x83
           )
        {
          continue;
        }

        const auto dictionary_offset = static_cast< std::int32_t >( code[ header + 2 ] );
        const auto entries_offset = static_cast< std::int32_t >( code[ header + 9 ] );

        if ( dictionary_offset <= 0 || dictionary_offset > 0x100 || entries_offset <= 0 || entries_offset > 0x80 )
        {
          continue;
        }

        std::int32_t state_offset{-1};
        std::int32_t slot_offset{-1};

        VariableNameFromSlot name_from_slot{};

        for (std::size_t cursor = header + 15; cursor + 12 < 0x200; ++cursor)
        {
          if (
               state_offset < 0 &&
               code[ cursor + 0 ] == 0x8B &&
               code[ cursor + 1 ] == 0x4A &&
               code[ cursor + 3 ] == 0x85 &&
               code[ cursor + 4 ] == 0xC9
             )
          {
            state_offset = static_cast< std::int32_t >( code[ cursor + 2 ] );
          }

          if (
               code[ cursor + 0 ] == 0xFF &&
               code[ cursor + 1 ] == 0x72 &&
               code[ cursor + 3 ] == 0x6A &&
               code[ cursor + 4 ] == 0xFF &&
               code[ cursor + 5 ] == 0x6A &&
               code[ cursor + 6 ] == 0x00 &&
               code[ cursor + 7 ] == 0xE8
             )
          {
            std::int32_t relative{};

            std::memcpy( &relative, code + cursor + 8, sizeof( relative ) );

            slot_offset = static_cast< std::int32_t >( code[ cursor + 2 ] );

            name_from_slot = reinterpret_cast< VariableNameFromSlot >( const_cast< std::uint8_t* >( code + cursor + 12 + relative ) );
            break;
          }
        }

        if (
             state_offset < 0 ||
             state_offset > 0x20 ||
             slot_offset < 0 ||
             slot_offset > 0x20 ||
             state_offset == slot_offset ||
             !name_from_slot
           )
        {
          continue;
        }

        g_member_dictionary_offset.store( dictionary_offset, std::memory_order_release );

        g_member_dictionary_entries_offset.store( entries_offset, std::memory_order_release );

        g_member_dictionary_slot_offset.store( slot_offset, std::memory_order_release );

        g_member_dictionary_state_offset.store( state_offset, std::memory_order_release );

        g_member_dictionary_count_offset.store( 0, std::memory_order_release );

        g_member_dictionary_mask_offset.store( -1, std::memory_order_release );

        g_member_dictionary_hash_state.store( false, std::memory_order_release );

        g_variable_name_from_slot.store( name_from_slot, std::memory_order_release );

        return true;
      }

      // GMS2 2.3 x86 walks the same sparse map through iterator helpers rather
      // than inlining the newer dictionary loop.  Prove this generation with
      // two independent public built-ins:
      //   get_names   loads [object+map] and calls name_from_slot(0,-1,slot)
      //   names_count loads [object+map] and returns [map+used_count]
      const auto* count_code = static_cast< const std::uint8_t* >( follow_direct_jumps( reinterpret_cast<void*>(names_count) ) );

      if ( count_code )
      {
        for (std::size_t header = 0; header + 8 < 0x180; ++header)
        {
          if (
               code[ header + 0 ] != 0x8B ||
               code[ header + 1 ] != 0x4B ||
               code[ header + 3 ] != 0x85 ||
               code[ header + 4 ] != 0xC9
             )
          {
            continue;
          }

          const auto dictionary_offset = static_cast< std::int32_t >( code[ header + 2 ] );

          if ( dictionary_offset <= 0 || dictionary_offset > 0x100 )
          {
            continue;
          }

          constexpr std::int32_t CountOffset = 0x04;
          auto count_shape_valid = false;

          for (std::size_t cursor = 0; cursor + 10 < 0x100; ++cursor)
          {
            if (
                 count_code[ cursor + 0 ] == 0x8B &&
                 count_code[ cursor + 1 ] == 0x40 &&
                 count_code[ cursor + 2 ] == dictionary_offset
               )
            {
              for (std::size_t count_cursor = cursor + 3; count_cursor + 5 < std::min<std::size_t>( cursor + 0x30, 0x100 ); ++count_cursor)
              {
                if (
                     count_code[ count_cursor + 0 ] == 0x66 &&
                     count_code[ count_cursor + 1 ] == 0x0F &&
                     count_code[ count_cursor + 2 ] == 0x6E &&
                     count_code[ count_cursor + 3 ] == 0x40 &&
                     count_code[ count_cursor + 4 ] == CountOffset
                   )
                {
                  count_shape_valid = true;
                  break;
                }
              }
            }

            if (count_shape_valid) break;
          }

          if (!count_shape_valid) continue;

          VariableNameFromSlot name_from_slot{};

          for (std::size_t cursor = header + 5; cursor + 12 < std::min<std::size_t>( header + 0xA0, 0x200 ); ++cursor)
          {
            if (
                 code[ cursor + 0 ] == 0xFF &&
                 code[ cursor + 1 ] == 0x75 &&
                 code[ cursor + 3 ] == 0x6A &&
                 code[ cursor + 4 ] == 0xFF &&
                 code[ cursor + 5 ] == 0x6A &&
                 code[ cursor + 6 ] == 0x00 &&
                 code[ cursor + 7 ] == 0xE8
               )
            {
              std::int32_t relative{};
              std::memcpy( &relative, code + cursor + 8, sizeof(relative) );
              name_from_slot = reinterpret_cast< VariableNameFromSlot >( const_cast<std::uint8_t*>( code + cursor + 12 + relative ) );
              break;
            }
          }

          if ( !name_from_slot || !executable_pointer( reinterpret_cast<void*>(name_from_slot) ) ) continue;

          g_member_dictionary_offset.store( dictionary_offset, std::memory_order_release );
          g_member_dictionary_entries_offset.store( 0x10, std::memory_order_release );
          g_member_dictionary_slot_offset.store( 0x04, std::memory_order_release );
          g_member_dictionary_state_offset.store( 0x08, std::memory_order_release );
          g_member_dictionary_count_offset.store( CountOffset, std::memory_order_release );
          g_member_dictionary_mask_offset.store( 0x08, std::memory_order_release );
          g_member_dictionary_hash_state.store( true, std::memory_order_release );
          g_variable_name_from_slot.store( name_from_slot, std::memory_order_release );
          return true;
        }
      }
    }
    __except ( EXCEPTION_EXECUTE_HANDLER )
    {
      return false;
    }

    return false;
  }

#endif

  /// Infer DynamicArrayOfRValue::m_Array from the body of an array routine.
  ///
  /// The implementation looks for two nearby loads using the same base and displacement.
  /// Requiring repetition rejects most incidental object loads;
  /// the resulting offset is still validated against an array before use.
  std::int64_t array_offset_from_body(void* function)
  {
    const auto instructions = disassemble( follow_direct_jumps( function ), 0x180 );

    for (std::size_t separation = 1; separation <= 4; ++separation)
    {

      for (std::size_t index = 0; index + separation < instructions.size(); ++index)
      {
        const auto &first = instructions[ index ];

        const auto &second = instructions[ index + separation ];

        if (
              first.info.mnemonic != ZYDIS_MNEMONIC_MOV ||
              second.info.mnemonic != ZYDIS_MNEMONIC_MOV ||
              first.info.operand_count_visible < 2 ||
              second.info.operand_count_visible < 2
            )
        {
          continue;
        }

        const auto &first_source = first.operands[1];

        const auto &second_source = second.operands[1];

        if (
              first.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER ||
              second.operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER ||
              first_source.type != ZYDIS_OPERAND_TYPE_MEMORY ||
              second_source.type != ZYDIS_OPERAND_TYPE_MEMORY ||
              first_source.mem.base == ZYDIS_REGISTER_NONE ||
              second_source.mem.base == ZYDIS_REGISTER_NONE ||
              !first_source.mem.disp.has_displacement ||
              !second_source.mem.disp.has_displacement ||
              first_source.mem.disp.value != second_source.mem.disp.value
            )
        {
          continue;
        }

        const auto displacement = first_source.mem.disp.value;

        if (
              displacement >= static_cast< std::int64_t >( sizeof( void* ) ) &&
              displacement <= 0x80 &&
              displacement % static_cast< std::int64_t >( sizeof( void* ) ) == 0
            )
        {
          return displacement;
        }

      }

    }

    return -1;
  }

  /// Find the array-body helper called by array_equals and infer its storage.
  ///
  /// VM and YYC wrappers marshal arguments differently. The surrounding MOV / TEST shapes identify both variants without pinning a complete signature
  std::int64_t discover_array_storage_offset(void* array_equals)
  {
    if (!array_equals)
    {
      return -1;
    }

    array_equals = follow_direct_jumps( array_equals );

    const auto wrapper = disassemble( array_equals, 0x100 );

    for (std::size_t index = 0; index < wrapper.size(); ++index)
    {
      const auto &call = wrapper[ index ];

      if ( call.info.mnemonic != ZYDIS_MNEMONIC_CALL || call.info.operand_count_visible == 0 )
      {
        continue;
      }

      const auto vm_wrapper = index >= 1 &&
                              index + 1 < wrapper.size() &&
                              wrapper[ index - 1 ].info.mnemonic == ZYDIS_MNEMONIC_MOV &&
                              wrapper[ index + 1 ].info.mnemonic == ZYDIS_MNEMONIC_TEST;

      const auto yyc_wrapper = index >= 2 &&
                               wrapper[ index - 2 ].info.mnemonic == ZYDIS_MNEMONIC_MOV &&
                               wrapper[ index - 1 ].info.mnemonic == ZYDIS_MNEMONIC_MOV;

      if ( !vm_wrapper && !yyc_wrapper )
      {
        continue;
      }

      ZyanU64 target{};

      if ( ZYAN_SUCCESS( ZydisCalcAbsoluteAddress( &call.info, &call.operands[0], call.runtime_address, &target ) ) )
      {

        const auto offset = array_offset_from_body( reinterpret_cast< void* >( static_cast< std::uintptr_t >( target ) ) );

        if (offset >= 0)
        {
          return offset;
        }

      }

    }

    return array_offset_from_body( array_equals );
  }

  /// Reconstruct selected YYRunnerInterface entries from its initializer.
  ///
  /// Motivation: public runner functions have no stable exports.
  /// YYToolkit showed that extension initialization necessarily writes those functions into a versioned interface structure.
  /// We recover only the entries needed by GMDumper
  /// then validate frame coherence, slot distance, executable targets, neighboring function distance before publishing anything.
  bool discover_reflection(HMODULE module)
  {

    Section text{};

    if ( !image_section( module, ".text", text ) )
    {
      set_error( ".text section wasnt found" );
      return false;
    }

    DiscoveryProfile profile;
    {
      std::scoped_lock lock( g_discovery_mutex );
      
      profile = g_discovery_profile;
    }

    g_struct_get_member.store( nullptr, std::memory_order_release );

    g_struct_get_keys.store( nullptr, std::memory_order_release );

    g_yy_get_string.store( nullptr, std::memory_order_release );

    g_free_rvalue.store( nullptr, std::memory_order_release );

    g_find_variable_slot.store( nullptr, std::memory_order_release );

    g_struct_add_rvalue.store( nullptr, std::memory_order_release );

    g_member_get_names.store( nullptr, std::memory_order_release );

    g_member_names_count.store( nullptr, std::memory_order_release );

    g_script_find_id.store( nullptr, std::memory_order_release );

    g_script_perform.store( nullptr, std::memory_order_release );

    g_array_get_length.store( nullptr, std::memory_order_release );


    // reduce .text section to candidate interface writes.
    auto assignments = collect_stack_assignments( text );

    const auto text_start = reinterpret_cast< std::uintptr_t >( text.start );

    const auto text_end = text_start + text.size;

    // LoadLibraryEx(DONT_RESOLVE_DLL_REFERENCES) may leave x86 absolute immediates at the PE preferred base
    // A normally loaded target has already relocated them.
    // Normalize only targets that are outside the mapped .text but inside its preferred-base counterpart.
    const auto mapped_base = reinterpret_cast< std::uintptr_t >( module );

    const auto preferred_base = preferred_image_base(module);

    const auto preferred_text_start = preferred_base + ( text_start - mapped_base );

    const auto preferred_text_end = preferred_text_start + text.size;

    if ( preferred_base && preferred_base != mapped_base )
    {
      for (auto &assignment : assignments)
      {
        if ( ( assignment.target < text_start || assignment.target >= text_end ) && assignment.target >= preferred_text_start && assignment.target < preferred_text_end )
        {
          assignment.target = mapped_base + ( assignment.target - preferred_base );
        }
      }
    }

#if defined(_WIN64)

    // x64 initializers use stable RBP/RSP frames.
    // constraining each candidate to one bounded window is distinct
    // broader base-anchored search below is for x86 register-based initializers
    std::unordered_map< std::uintptr_t, std::uint32_t > key_scores;

    const auto key_score = [&](std::uintptr_t target)
    {
      const auto cached = key_scores.find( target );

      if ( cached != key_scores.end() )
      {
        return cached->second;
      }

      const auto score = target >= text_start && target < text_end ? struct_get_keys_score( reinterpret_cast<void*>(target) ) : 0u;

      key_scores.emplace( target, score );
      return score;
    };

    for (std::size_t start = 0; start < assignments.size(); ++start)
    {
      std::size_t finish = start;

      while ( finish < assignments.size() && assignments[ finish ].instruction - assignments[ start ].instruction <= profile.maximum_instruction_span )
      {
        ++finish;
      }

      std::vector< const Assignment* > frame_assignments;

      for (std::size_t index = start; index < finish; ++index)
      {
        if ( assignments[ index ].stack_base == assignments[ start ].stack_base ) frame_assignments.push_back( &assignments[ index ] );
      }

      if ( frame_assignments.size() < profile.minimum_assignments || frame_assignments.size() > profile.maximum_assignments )
      {
        continue;
      }

      const auto displacement_less = [](const auto* left, const auto* right)
      {
        return left->displacement < right->displacement;
      };

      const auto first = *std::min_element( frame_assignments.begin(), frame_assignments.end(), displacement_less );
      const auto last = *std::max_element( frame_assignments.begin(), frame_assignments.end(), displacement_less );

      if ( last->displacement - first->displacement > profile.maximum_stack_span )
      {
        continue;
      }

      // StructGetMember immediately precedes StructGetKeys in observed YYRunnerInterface revision, the absolute slot numbers shifted
      // figure out the key routine by behavior first, then require the adjacent interface assignment.
      for (const auto* keys_assignment : frame_assignments)
      {
        if ( key_score(keys_assignment->target) < 3 )
        {
          continue;
        }

        const auto member_displacement = keys_assignment->displacement - static_cast< std::ptrdiff_t >( sizeof( void* ) );

        for (const auto* member_assignment : frame_assignments)
        {
          if ( member_assignment->displacement != member_displacement )
          {
            continue;
          }

          if ( member_assignment->target < text_start || member_assignment->target >= text_end )
          {
            continue;
          }

          const auto distance = member_assignment->target > keys_assignment->target
                                ? member_assignment->target - keys_assignment->target
                                : keys_assignment->target - member_assignment->target;

          if ( distance > std::min<std::uintptr_t>(profile.maximum_function_distance, 0x100) )
          {
            continue;
          }

          g_struct_get_member.store( reinterpret_cast< StructGetMember >( member_assignment->target ), std::memory_order_release );

          g_struct_get_keys.store( reinterpret_cast< StructGetKeys >( keys_assignment->target ), std::memory_order_release );

          return true;
        }
      }

      for (const auto* member_assignment : frame_assignments)
      {

        const auto base = member_assignment->displacement - profile.struct_get_member_offset;
        const auto base_slack = first->displacement - base;

        if ( base > first->displacement || base_slack < 0 || base_slack > profile.maximum_base_slack || (base & 7) != 0 )
        {
          continue;
        }

        const auto target_at = [&](std::ptrdiff_t offset) -> std::uintptr_t
        {
          const auto displacement = base + offset;

          for (const auto* assignment : frame_assignments)
          {
            if ( assignment->displacement == displacement && assignment->target >= text_start && assignment->target < text_end )
            {
              return assignment->target;
            }
          }

          return 0;
        };

        const auto member = target_at( profile.struct_get_member_offset );
        const auto keys = target_at( profile.struct_get_keys_offset );

        if ( !member || !keys )
        {
          continue;
        }

        // require the key routine's member-map walk.
        if ( struct_get_keys_score( reinterpret_cast< void* >( keys )) < 3 )
        {
          continue;
        }

        const auto function_distance = member > keys ? member - keys : keys - member;

        if ( function_distance > profile.maximum_function_distance )
        {
          continue;
        }

        const auto script_find = target_at( profile.script_find_id_offset );
        const auto script_perform = target_at( profile.script_perform_offset );
        const auto array_length = target_at( profile.array_get_length_offset );

        if ( !script_find && !script_perform && !array_length )
        {
          continue;
        }

        g_struct_get_member.store( reinterpret_cast< StructGetMember >( member ), std::memory_order_release );
        g_struct_get_keys.store( reinterpret_cast< StructGetKeys >( keys ), std::memory_order_release );

        if (script_find)
        {
          g_script_find_id.store( reinterpret_cast< ScriptFindId >( script_find ), std::memory_order_release );
        }

        if (script_perform)
        {
          g_script_perform.store( reinterpret_cast< ScriptPerform >( script_perform ), std::memory_order_release );
        }

        if (array_length)
        {
          g_array_get_length.store( reinterpret_cast< ArrayGetLength >( array_length ), std::memory_order_release );
        }

        const auto yy_get_string = target_at( profile.yy_get_string_offset );
        const auto free_rvalue = target_at( profile.free_rvalue_offset );
        const auto struct_add = target_at( profile.struct_add_rvalue_offset );

        if ( yy_get_string && free_rvalue && struct_add )
        {
          const auto find_slot = discover_find_variable_slot( reinterpret_cast< void* >( struct_add ) );

          if (find_slot)
          {
            g_yy_get_string.store( reinterpret_cast< YYGetString >( yy_get_string ), std::memory_order_release );

            g_free_rvalue.store( reinterpret_cast< FreeRValue >( free_rvalue ), std::memory_order_release );

            g_find_variable_slot.store( find_slot, std::memory_order_release );
            g_struct_add_rvalue.store( reinterpret_cast< Routine >( struct_add ), std::memory_order_release );
          }
        }

        return true;
      }
    }

    set_error( "YYRunnerInterface x64 initializer wasnt recognized" );
    return false;

#endif

    // Every assignment at the configured StructGetMember slot proposes an interface base.
    // Validate the surrounding pointer slots relative to that base.
    // This ignores unrelated compiler locals below/above the structure (common in x86 initializers & made min/max-stack heuristics unreliable)
    std::size_t maximum_unique_slots{};

    std::size_t adjacent_reflection_pairs{};
    
    std::size_t corroborated_interfaces{};

    bool direct_reflection_discovered{};

    std::uintptr_t selected_member{};

    std::uintptr_t selected_keys{};

    std::uintptr_t selected_script_find{};

    std::uintptr_t selected_script_perform{};

    std::uintptr_t selected_array_length{};

    std::uintptr_t selected_yy_get_string{};

    std::uintptr_t selected_free_rvalue{};

    std::uintptr_t selected_struct_add{};

    std::uintptr_t selected_function_distance{ std::numeric_limits< std::uintptr_t >::max() };

    for (const auto &member_assignment : assignments)
    {
      if ( member_assignment.target < text_start || member_assignment.target >= text_end )
      {
        continue;
      }

      const auto base = member_assignment.displacement - profile.struct_get_member_offset;

      if ( base % static_cast< std::ptrdiff_t >( sizeof(void*) ) != 0 )
      {
        continue;
      }

      std::vector< const Assignment* > interface_assignments;

      for (const auto &assignment : assignments)
      {
        const auto instruction_distance = assignment.instruction > member_assignment.instruction
                                          ? assignment.instruction - member_assignment.instruction
                                          : member_assignment.instruction - assignment.instruction;

        if (
             assignment.stack_base == member_assignment.stack_base &&
             instruction_distance <= profile.maximum_instruction_span &&
             assignment.displacement >= base - profile.maximum_base_slack &&
             assignment.displacement <= base + profile.maximum_stack_span &&
             assignment.target >= text_start &&
             assignment.target < text_end
           )
        {
          interface_assignments.push_back( &assignment );
        }
      }

      // Count unique populated pointer slots.
      // Duplicate writes are accepted only when they publish the same function address.
      std::sort(
                  interface_assignments.begin(),
                  interface_assignments.end(),
                  [](const auto* left, const auto* right)
                  {
                    if ( left->displacement != right->displacement )
                    {
                      return left->displacement < right->displacement;
                    }

                    return left->instruction < right->instruction;
                  }
                );

      std::vector< const Assignment* > unique_assignments;
      bool conflicting_slot{};

      for (const auto* assignment : interface_assignments)
      {
        if ( unique_assignments.empty() || unique_assignments.back()->displacement != assignment->displacement )
        {
          unique_assignments.push_back( assignment );
        }

        else if ( unique_assignments.back()->target != assignment->target )
        {
          conflicting_slot = true;
          break;
        }
      }

      maximum_unique_slots = std::max( maximum_unique_slots, unique_assignments.size() );

      if ( conflicting_slot || unique_assignments.size() < profile.minimum_assignments || unique_assignments.size() > profile.maximum_assignments )
      {
        continue;
      }

      const auto target_at = [&](std::ptrdiff_t offset) -> std::uintptr_t
      {
        const auto displacement = base + offset;

        for (const auto* assignment : unique_assignments)
        {
          if ( assignment->displacement == displacement )
          {
            return assignment->target;
          }
        }

        return 0;
      };

      // Reflection is mandatory.
      // Script/array entries are optional, but at least 1 must independently identify this as YYRunnerInterface.
      const auto member = target_at( profile.struct_get_member_offset );
      const auto keys = target_at( profile.struct_get_keys_offset );

      if ( !member || !keys )
      {
        continue;
      }

      ++adjacent_reflection_pairs;

      const auto function_distance = member > keys ? member - keys : keys - member;

      if ( function_distance > profile.maximum_function_distance )
      {
        continue;
      }

      const auto script_find = target_at( profile.script_find_id_offset );

      const auto script_perform = target_at( profile.script_perform_offset );

      const auto array_length = target_at( profile.array_get_length_offset );

      const auto yy_get_string = target_at( profile.yy_get_string_offset );

      const auto free_rvalue = target_at( profile.free_rvalue_offset );

      const auto struct_add = target_at( profile.struct_add_rvalue_offset );

      if ( !script_find && !script_perform && !array_length )
      {
        continue;
      }

      ++corroborated_interfaces;

      // StructGetMember & StructGetKeys are neighbors.
      // Rank every coherent candidate by the distance between these adjacent functions & publish only the best one.
      if ( function_distance < selected_function_distance )
      {
        selected_member = member;
        selected_keys = keys;
        selected_script_find = script_find;
        selected_script_perform = script_perform;
        selected_array_length = array_length;
        selected_yy_get_string = yy_get_string;
        selected_free_rvalue = free_rvalue;
        selected_struct_add = struct_add;
        selected_function_distance = function_distance;
      }
    }

    if ( selected_member && selected_keys )
    {
      g_struct_get_member.store( reinterpret_cast< StructGetMember >( selected_member ), std::memory_order_release );

      g_struct_get_keys.store( reinterpret_cast< StructGetKeys >( selected_keys ), std::memory_order_release );

      if (selected_script_find)
      {
        g_script_find_id.store( reinterpret_cast< ScriptFindId >( selected_script_find ), std::memory_order_release );
      }

      if (selected_script_perform)
      {
        g_script_perform.store( reinterpret_cast< ScriptPerform >( selected_script_perform ), std::memory_order_release );
      }

      if (selected_array_length)
      {
        g_array_get_length.store( reinterpret_cast< ArrayGetLength >( selected_array_length ), std::memory_order_release );
      }

      if ( selected_yy_get_string && selected_free_rvalue && selected_struct_add )
      {
        const auto find_slot = discover_find_variable_slot( reinterpret_cast< void* >( selected_struct_add ) );

        if (find_slot)
        {
          g_yy_get_string.store( reinterpret_cast< YYGetString >( selected_yy_get_string ), std::memory_order_release );

          g_free_rvalue.store( reinterpret_cast< FreeRValue >( selected_free_rvalue ), std::memory_order_release );

          g_find_variable_slot.store( find_slot, std::memory_order_release );

          g_struct_add_rvalue.store( reinterpret_cast< Routine >( selected_struct_add ), std::memory_order_release );

        }
      }

      direct_reflection_discovered = true;
    }

    // Older YYRunnerInterface revisions predate StructGetMember/StructGetKeys.
    // Anchor the same structure at Script_Find_Id instead & recover stable helpers needed by the built-in name-enumeration fallback.
    std::size_t maximum_fallback_slots{};
    std::size_t fallback_script_pairs{};
    std::size_t fallback_helper_sets{};

    for (const auto &script_assignment : assignments)
    {
      if ( script_assignment.target < text_start || script_assignment.target >= text_end )
      {
        continue;
      }

      const auto base = script_assignment.displacement - profile.script_find_id_offset;

      if ( base % static_cast< std::ptrdiff_t >( sizeof(void*) ) != 0 )
      {
        continue;
      }

      std::vector< const Assignment* > interface_assignments;

      for (const auto &assignment : assignments)
      {
        const auto instruction_distance = assignment.instruction > script_assignment.instruction
                                          ? assignment.instruction - script_assignment.instruction
                                          : script_assignment.instruction - assignment.instruction;

        if (
             assignment.stack_base == script_assignment.stack_base &&
             instruction_distance <= profile.maximum_instruction_span &&
             assignment.displacement >= base - profile.maximum_base_slack &&
             assignment.displacement <= base + profile.maximum_stack_span &&
             assignment.target >= text_start &&
             assignment.target < text_end
           )
        {
          interface_assignments.push_back( &assignment );
        }
      }

      std::sort(
                  interface_assignments.begin(),
                  interface_assignments.end(),
                  [](const auto* left, const auto* right)
                  {
                    if ( left->displacement != right->displacement )
                    {
                      return left->displacement < right->displacement;
                    }

                    return left->instruction < right->instruction;
                  }
                );

      std::vector< const Assignment* > unique_assignments;

      bool conflicting_slot{};

      for (const auto* assignment : interface_assignments)
      {
        if ( unique_assignments.empty() || unique_assignments.back()->displacement != assignment->displacement )
        {
          unique_assignments.push_back( assignment );
        }
        else if ( unique_assignments.back()->target != assignment->target )
        {
          conflicting_slot = true;
          break;
        }

      }

      maximum_fallback_slots = std::max( maximum_fallback_slots, unique_assignments.size() );

      if (
           conflicting_slot ||
           unique_assignments.size() < profile.minimum_assignments ||
           unique_assignments.size() > profile.maximum_assignments
         )
      {
        continue;
      }

      const auto target_at = [&](std::ptrdiff_t offset) -> std::uintptr_t
      {
        const auto displacement = base + offset;

        for (const auto* assignment : unique_assignments)
        {
          if ( assignment->displacement == displacement ) return assignment->target;
        }

        return 0;
      };

      const auto yy_get_string = target_at( profile.yy_get_string_offset );
      const auto free_rvalue = target_at( profile.free_rvalue_offset );
      const auto script_find = target_at( profile.script_find_id_offset );
      const auto script_perform = target_at( profile.script_perform_offset );
      const auto struct_add = target_at( profile.struct_add_rvalue_offset );

      if (script_find && script_perform)
      {
        ++fallback_script_pairs;
      }

      if ( !yy_get_string || !free_rvalue || !script_find || !script_perform || !struct_add )
      {
        continue;
      }

      ++fallback_helper_sets;

      const auto find_slot = discover_find_variable_slot( reinterpret_cast< void* >( struct_add ) );

      if (!find_slot)
      {
        continue;
      }

      g_yy_get_string.store( reinterpret_cast< YYGetString >( yy_get_string ), std::memory_order_release );

      g_free_rvalue.store( reinterpret_cast< FreeRValue >( free_rvalue ), std::memory_order_release );

      g_find_variable_slot.store( find_slot, std::memory_order_release );

      g_struct_add_rvalue.store( reinterpret_cast< Routine >( struct_add ), std::memory_order_release );

      g_script_find_id.store( reinterpret_cast< ScriptFindId >( script_find ), std::memory_order_release );

      g_script_perform.store( reinterpret_cast< ScriptPerform >( script_perform ), std::memory_order_release );


      return true;
    }

    // A direct pair is sufficient for newer runners.
    // Reaching this point means the optional legacy-helper scan found nothing
    if ( direct_reflection_discovered )
    {
      return true;
    }
    
    set_error(
      "YYRunnerInterface initializer wasnt recognized (" + std::to_string( assignments.size() ) + " candidate stack assignments, max " +
      std::to_string( maximum_unique_slots ) + " coherent slots, " + std::to_string( adjacent_reflection_pairs ) + " adjacent reflection pairs, " +
      std::to_string( corroborated_interfaces ) + " corroborated; fallback max " + std::to_string( maximum_fallback_slots ) + " slots, " +
      std::to_string( fallback_script_pairs ) + " script pairs, " + std::to_string( fallback_helper_sets ) +
      " helper sets); configure StructGetKeys/StructGetMember manually"
    );

    return false;
  } // func end

  // ----------------------- Guarded runner API calls ----------------------------

  // Every recovered pointer is structurally validated before publication,
  // but the pointed-to object may disappear between queueing & execution.
  // SEH is therefore the final containment boundary around runner-owned memory/code.

  /// Query the number of keys using StructGetKeys' count-only convention.
  bool call_keys_count(StructGetKeys function, RValue* object, int &count)
  {
    __try
    {
      count = function( object, nullptr, nullptr );
      return true;
    }
    __except ( EXCEPTION_EXECUTE_HANDLER )
    {
      return false;
    }
  }

  /// Fill a caller-sized key array through StructGetKeys.
  bool call_keys(StructGetKeys function, RValue* object, const char** keys, int &count)
  {
    __try
    {
      function( object, keys, &count );
      return true;
    }
    __except ( EXCEPTION_EXECUTE_HANDLER )
    {
      return false;
    }
  }

  /// Resolve one reflected member to its runner-owned live RValue.
  bool call_member(StructGetMember function, RValue* object, const char* key, RValue* &result)
  {
    __try
    {
      result = function( object, key );
      return true;
    }
    __except ( EXCEPTION_EXECUTE_HANDLER )
    {
      return false;
    }
  }

  /// Resolve a user-defined GML function name to its runtime script ID.
  bool call_script_find(ScriptFindId function, const char* name, int &result)
  {
    __try
    {
      result = function( name );
      return true;
    }
    __except ( EXCEPTION_EXECUTE_HANDLER )
    {
      return false;
    }
  }

  /// Execute a resolved script through the runner-interface ABI.
  bool call_script_perform( ScriptPerform function, int id, void* self, void* other, int count, RValue* result, RValue* arguments )
  {
    __try
    {
      return function( id, self, other, count, result, arguments );
    }
    __except ( EXCEPTION_EXECUTE_HANDLER )
    {
      return false;
    }
  }

  /// Invoke a regular GML built-in routine using the VM/YYC shared ABI.
  bool call_routine(Routine function, RValue &result, void* self, void* other, int count, RValue* arguments)
  {
    __try
    {
      function( result, self, other, count, arguments );
      return true;
    }
    __except ( EXCEPTION_EXECUTE_HANDLER )
    {
      return false;
    }
  }

  /// Convert RValue string through the runner interface.
  bool call_get_string(YYGetString function, const RValue* value, const char* &result)
  {
    __try
    {
      result = function( value, 0 );
      return result != nullptr;
    }
    __except ( EXCEPTION_EXECUTE_HANDLER )
    {
      return false;
    }
  }

  /// Release a temp RValue returned by a built-in.
  bool call_free_rvalue(FreeRValue function, RValue* value)
  {
    __try
    {
      function(value);
      return true;
    }
    __except ( EXCEPTION_EXECUTE_HANDLER )
    {
      return false;
    }
  }

  /// Resolve an existing reflected name to its live runtime slot.
  bool call_find_variable_slot(FindVariableSlot function, void* object, const char* name, int &slot)
  {
    __try
    {
      slot = function( object, name );
      return slot >= 0;
    }
    __except ( EXCEPTION_EXECUTE_HANDLER )
    {
      return false;
    }
  }

  /// Query array length through YYRunnerInterface when that entry is available.
  bool call_array_get_length(ArrayGetLength function, RValue* array, int &length)
  {
    __try
    {
      length = function( array );
      return length >= 0;
    }
    __except ( EXCEPTION_EXECUTE_HANDLER )
    {
      return false;
    }
  }

  /// Query array length through the public built-in as a compatibility fallback.
  bool call_array_length_routine(Routine function, RValue* array, int &length)
  {
    RValue result{};

    result.kind = 5;

    RValue argument =* array;

    if ( !call_routine( function, result, nullptr, nullptr, 1, &argument ) )
    {
      return false;
    }

    std::int64_t candidate{};

    if ( result.kind == 0 )
    {
      if ( !( result.value.real >= 0.0 && result.value.real <= 2147483647.0 ) ) // 7FFFFFFF
      {
        return false;
      }

      candidate = static_cast< std::int64_t >( result.value.real );
    }
    else if ( result.kind == 7 )
    {
      candidate = result.value.i32;
    }
    else if ( result.kind == 10 )
    {
      candidate = result.value.i64;
    }
    else
    {
      return false;
    }

    if ( candidate < 0 || candidate > 2147483647 ) // 7FFFFFFF
    {
      return false;
    }

    length = static_cast< int >( candidate );

    return true;
  }

  // ----------------------------- Array storage --------------------------------

  /// Test whether an integer can be a modern GameMaker RValue kind.
  bool plausible_rvalue_kind(std::int32_t kind)
  {
    return ( kind >= 0 && kind <= 15 ) || kind == 0x00FFFFFF; // TODO: defines
  }

  /// Validate one candidate DynamicArrayOfRValue::m_Array offset.
  ///
  /// A readable pointer isn't enough;
  // it must be aligned, remain inside one committed region for the sampled elements, and contain plausible RValue kinds.
  bool validate_array_storage(void* array_object, std::int64_t offset, int length, RValue* &elements)
  {
    __try
    {
      elements =* reinterpret_cast< RValue** >( static_cast< std::byte* >( array_object ) + offset );

      if ( length == 0 )
      {
        return true;
      }

      if ( !elements || ( reinterpret_cast< std::uintptr_t >( elements ) & ( alignof( void* ) - 1) ) != 0 )
      {
        return false;
      }

      MEMORY_BASIC_INFORMATION region{};

      if ( !VirtualQuery( elements, &region, sizeof( region ) ) || region.State != MEM_COMMIT || ( region.Protect & ( PAGE_GUARD | PAGE_NOACCESS ) ) != 0 )
      {
        return false;
      }

      const auto sample_count = std::min( length, 8 );

      const auto region_end = reinterpret_cast< std::uintptr_t >( region.BaseAddress ) + region.RegionSize;

      const auto sample_end = reinterpret_cast< std::uintptr_t >( elements ) + static_cast< std::uintptr_t >( sample_count )*  sizeof( RValue );
      
      if ( sample_end > region_end )
      {
        return false;
      }

      for (int index = 0; index < sample_count; ++index)
      {
        if ( !plausible_rvalue_kind( elements[ index ].kind ) )
        {
          return false;
        }

      }

      return true;
    }
    __except ( EXCEPTION_EXECUTE_HANDLER )
    {
      elements = nullptr;
      return false;
    }

  }

  /// Discover array storage from a non-empty array.
  ///
  /// Using 1 candidate. Ambiguity fails closed because an incorrect element base would make writes through generated records unsafe.
  bool discover_live_array_storage(void* array_object, int length, std::int64_t &offset, RValue* &elements)
  {
    if ( !array_object || length <= 0 )
    {
      return false;
    }

    std::int64_t selected_offset = -1;

    RValue* selected_elements{};

    for (std::int64_t candidate = sizeof( void* ); candidate <= 0x80; candidate += sizeof( void* ) )
    {
      RValue* candidate_elements{};

      if ( !validate_array_storage( array_object, candidate, length, candidate_elements ) )
      {
        continue;
      }

      if ( selected_offset >= 0 )
      {
        return false;
      }

      selected_offset = candidate;
      selected_elements = candidate_elements;
    }

    if ( selected_offset < 0 )
    {
      return false;
    }

    offset = selected_offset;

    elements = selected_elements;

    g_array_storage_offset.store( offset, std::memory_order_release );

    return true;
  }

  // -------------------------- Result materialization ---------------------------

  /// Copy 1 runner-owned member name into the fixed public ABI record.
  bool copy_name(const char* source, char (&destination)[256])
  {
    __try
    {
      const auto length = strnlen_s( source, sizeof( destination ) );
      
      if ( length == 0 || length >= sizeof( destination ) )
      {
        return false;
      }

      std::memcpy( destination, source, length );
      destination[ length ] = '\0';

      return true;
    }
    __except ( EXCEPTION_EXECUTE_HANDLER )
    {
      return false;
    }
  }

  /// Read RValue kind safely
  std::int32_t read_kind(RValue* value)
  {
    __try
    {
      return value->kind;
    }
    __except ( EXCEPTION_EXECUTE_HANDLER )
    {
      return -1;
    }
  }

  /// Copy across the CE/bridge boundary safely
  bool safe_copy(void* destination, const void* source, std::size_t size)
  {
    __try
    {
      if (size)
      {
        std::memcpy( destination, source, size );
      }

      return true;
    }
    __except ( EXCEPTION_EXECUTE_HANDLER )
    {
      return false;
    }
  }

#if !defined(_WIN64)

  bool read_pointer32(const void* address, const std::uint8_t* &value)
  {
    __try
    {
      value = *static_cast< std::uint8_t* const* >( address );
      return true;
    }
    __except ( EXCEPTION_EXECUTE_HANDLER )
    {
      return false;
    }
  }

  bool read_integer32(const void* address, std::int32_t &value)
  {
    __try
    {
      value = *static_cast< const std::int32_t* >( address );
      return true;
    }
    __except ( EXCEPTION_EXECUTE_HANDLER )
    {
      return false;
    }
  }

  bool call_variable_name(VariableNameFromSlot function, int slot, const char* &name)
  {
    __try
    {
      name = function( 0, -1, slot );
      return name != nullptr;
    }
    __except ( EXCEPTION_EXECUTE_HANDLER )
    {
      return false;
    }
  }

  bool call_member_iterator(MemberDictionaryIterator function, void* dictionary, int &cursor_a, int &cursor_b, void* &entry)
  {
    __try
    {
      entry = function( dictionary, &cursor_a, &cursor_b );
      return true;
    }
    __except ( EXCEPTION_EXECUTE_HANDLER )
    {
      return false;
    }
  }

  /// Enumerate the iterator-backed member dictionary used by GMS2 2.2 & earlier.
  ///
  /// performs on the runner thread (dicts can mutate with GML execution)
  /// The recovered slot is returned without dereferencing the instance RValue map
  bool execute_members_iterator(Request &request)
  {
    const auto iterator = g_member_dictionary_iterator.load( std::memory_order_acquire );

    const auto name_from_slot = g_variable_name_from_slot.load( std::memory_order_acquire );

    const auto dictionary_offset = g_member_dictionary_offset.load( std::memory_order_acquire );

    const auto variable_base = g_member_dictionary_variable_base.load( std::memory_order_acquire );


    if ( !iterator || !name_from_slot || dictionary_offset < 0 )
    {
      return false;
    }

    const auto* object = static_cast< const std::uint8_t* >( request.object );

    const std::uint8_t* dictionary{};

    if ( !read_pointer32( object + dictionary_offset, dictionary ) || !dictionary )
    {
      request.error = "Object member dictionary is null / unreadable";
      request.status.store( GmdRequestStatus::Failed, std::memory_order_release );
      return true;
    }

    request.members.clear();

    request.members.reserve( std::min<std::uint32_t>( request.maximum, 64 ) );

    std::unordered_set< std::string > seen_names;

    std::unordered_set< int > seen_slots;

    int cursor_a{};
    int cursor_b{};

    // Sparse dictionaries may visit tombstones. the traversal limit is larger than the accepted-member limit while remaining bounded against corrupt state.
    const auto traversal_limit = std::min<std::uint32_t>( MaximumMemberLimit * 16, std::max<std::uint32_t>( request.maximum * 16, 256 ) );

    for (std::uint32_t iteration = 0; iteration < traversal_limit; ++iteration)
    {
      void* entry{};

      if ( !call_member_iterator( iterator, const_cast<std::uint8_t*>(dictionary), cursor_a, cursor_b, entry ) )
      {
        request.members.clear();
        request.error = "Object member dictionary iterator raised an exception";
        request.status.store( GmdRequestStatus::Failed, std::memory_order_release );
        return true;
      }

      if (!entry)
      {
        request.status.store( GmdRequestStatus::Completed, std::memory_order_release );
        return true;
      }

      const std::uint8_t* value{};
      std::int32_t kind{};

      // Match the runner's own get-names filter: an iterator result points to a value pointer and kind 0x00FFFFFF marks a vacant/tombstone entry.
      if ( !read_pointer32( entry, value ) || !value || !read_integer32( value + 0x0C, kind ) )
      {
        request.members.clear();
        request.error = "Object member dictionary iterator returned an unreadable entry";
        request.status.store( GmdRequestStatus::Failed, std::memory_order_release );
        return true;
      }

      if ( (kind & 0x00FFFFFF) == 0x00FFFFFF )
      {
        continue;
      }

      // The dictionary key is the raw slot used by YYObjectBase's sparse map.
      // This runner adds its variable-base constant only while translating the key through Code_Variable_Name
      // exposing that adjusted lookup ID would prevent CE's raw storage walk from matching the reflected member.
      const auto raw_slot64 = static_cast< std::int64_t >( cursor_b );

      const auto lookup_slot64 = raw_slot64 + variable_base;

      if (
           raw_slot64 < 0 ||
           raw_slot64 > std::numeric_limits< int >::max() ||
           lookup_slot64 < 0 ||
           lookup_slot64 > std::numeric_limits< int >::max()
         )
      {
        request.members.clear();
        request.error = "Object member dictionary iterator returned an invalid slot";
        request.status.store( GmdRequestStatus::Failed, std::memory_order_release );
        return true;
      }

      const auto raw_slot = static_cast< int >( raw_slot64 );
      
      const auto lookup_slot = static_cast< int >( lookup_slot64 );
      
      const char* name{};
      
      GmdMemberRecord record{};
      record.kind = -1;

      if (
           !call_variable_name( name_from_slot, lookup_slot, name ) ||
           !copy_name( name, record.name ) ||
           !seen_names.emplace( record.name ).second ||
           !seen_slots.emplace( raw_slot ).second
         )
      {
        request.members.clear();
        request.error = "Object member dictionary iterator returned an invalid / duplicate slot or name";
        request.status.store( GmdRequestStatus::Failed, std::memory_order_release );
        return true;
      }

      if ( request.members.size() >= request.maximum )
      {
        request.members.clear();
        request.error = "Object member dictionary exceeded the caller policy limit";
        request.status.store( GmdRequestStatus::Failed, std::memory_order_release );
        return true;
      }

      record.slot = raw_slot;
      request.members.push_back(record);
    }

    request.members.clear();
    request.error = "Object member dictionary iterator didnt terminate within its safety limit";
    request.status.store( GmdRequestStatus::Failed, std::memory_order_release );
    return true;
  }

  /// Enumerate x86 GMS2 names & runtime slots from the dictionary traversed by variable_instance_get_names.
  ///
  /// Returning slots directly avoids guessing the private name-to-slot helper & decoding temporary GML array produced by the built-in.
  /// The active-entry count must equal variable_instance_names_count before any result is accepted.
  bool execute_members_dictionary(Request &request, std::int64_t expected_count)
  {
    const auto name_from_slot = g_variable_name_from_slot.load( std::memory_order_acquire );

    const auto dictionary_offset = g_member_dictionary_offset.load( std::memory_order_acquire );

    const auto entries_offset = g_member_dictionary_entries_offset.load( std::memory_order_acquire );

    const auto slot_offset = g_member_dictionary_slot_offset.load( std::memory_order_acquire );

    const auto state_offset = g_member_dictionary_state_offset.load( std::memory_order_acquire );

    const auto count_offset = g_member_dictionary_count_offset.load( std::memory_order_acquire );

    const auto mask_offset = g_member_dictionary_mask_offset.load( std::memory_order_acquire );

    const auto hash_state = g_member_dictionary_hash_state.load( std::memory_order_acquire );


    if ( !name_from_slot || dictionary_offset < 0 || entries_offset < 0 || slot_offset < 0 || state_offset < 0 || count_offset < 0 )
    {
      return false;
    }

    request.members.clear();
    request.members.reserve( static_cast<std::size_t>( expected_count ) );

    std::unordered_set< std::string > seen_names;

    std::unordered_set< int > seen_slots;

    const auto* object = static_cast< const std::uint8_t* >( request.object );

    const std::uint8_t* dictionary{};

    if ( !read_pointer32( object + dictionary_offset, dictionary ) || !dictionary )
    {
      request.error = "Object member dictionary is null / unreadable";
      request.status.store( GmdRequestStatus::Failed, std::memory_order_release );
      return true;
    }

    std::int32_t entry_count{};
    
    const std::uint8_t* entries{};

    if (
         !read_integer32( dictionary + count_offset, entry_count ) ||
         !read_pointer32( dictionary + entries_offset, entries ) ||
         entry_count < 0 ||
         entry_count > static_cast< std::int32_t >( MaximumMemberLimit ) ||
         ( entry_count > 0 && !entries )
       )
    {
      request.error = "Object member dictionary header failed validation";
      request.status.store( GmdRequestStatus::Failed, std::memory_order_release );
      return true;
    }

    auto scan_count = entry_count;

    if ( mask_offset >= 0 )
    {
      std::int32_t mask{};

      if ( !read_integer32( dictionary + mask_offset, mask ) || mask < 0 || mask >= static_cast< std::int32_t >( MaximumMemberLimit * 16 ) )
      {
        request.error = "Object member dictionary mask failed validation";
        request.status.store( GmdRequestStatus::Failed, std::memory_order_release );
        return true;
      }

      scan_count = mask + 1;
    }

    constexpr std::size_t EntryStride = 12;

    for (std::int32_t index = 0; index < scan_count; ++index)
    {
      const auto* entry = entries + static_cast< std::size_t >( index ) * EntryStride;
      std::int32_t state{};

      if ( !read_integer32( entry + state_offset, state ) )
      {
        request.members.clear();
        request.error = "Object member dictionary entry couldnt be read safely";
        request.status.store( GmdRequestStatus::Failed, std::memory_order_release );
        return true;
      }

      if ( hash_state ? state == 0 : state <= 0 )
      {
        continue;
      }

      std::int32_t slot{};
      const char* name{};

      GmdMemberRecord record{};
      record.kind = -1;

      if (
           !read_integer32( entry + slot_offset, slot ) ||
           slot < 0 ||
           !call_variable_name( name_from_slot, slot, name ) ||
           !copy_name( name, record.name ) ||
           !seen_names.emplace( record.name ).second ||
           !seen_slots.emplace( slot ).second
         )
      {
        request.members.clear();
        request.error = "Object member dictionary returned an invalid / duplicate slot or name";
        request.status.store( GmdRequestStatus::Failed, std::memory_order_release );
        return true;
      }

      record.slot = slot;
      request.members.push_back( record );

      if ( request.members.size() > static_cast< std::size_t >( expected_count ) )
      {
        request.members.clear();
        request.error = "Object member dictionary exceeded the reflected member count";
        request.status.store( GmdRequestStatus::Failed, std::memory_order_release );
        return true;
      }
    }

    if ( request.members.size() != static_cast< std::size_t >( expected_count ) )
    {
      request.members.clear();
      request.error = "Object member dictionary count disagrees with runtime reflection";
      request.status.store( GmdRequestStatus::Failed, std::memory_order_release );
      return true;
    }

    request.status.store( GmdRequestStatus::Completed, std::memory_order_release );
    return true;
  }

#endif

  // ------------------------- Game-thread operations ----------------------------

  /// Enumerate names through variable_struct_get_names on interfaces that predate StructGetKeys
  // Each name is resolved back to the runner's runtime variable slot
  // CE accepts it only when that slot exists in the raw map
  void execute_members_fallback(Request &request, RValue &object)
  {
    const auto get_names = g_member_get_names.load( std::memory_order_acquire );

    const auto names_count = g_member_names_count.load( std::memory_order_acquire );

    const auto get_string = g_yy_get_string.load( std::memory_order_acquire );

    const auto free_rvalue = g_free_rvalue.load( std::memory_order_acquire );

    const auto find_slot = g_find_variable_slot.load( std::memory_order_acquire );

    auto dictionary_available = false;

#if !defined(_WIN64)

    dictionary_available = g_variable_name_from_slot.load( std::memory_order_acquire ) != nullptr;

    // GMS2 2.2 has no names-count built-in.
    // Its validated iterator supplies the termination condition and therefore must run before the count-based paths.
    if ( g_member_dictionary_iterator.load( std::memory_order_acquire ) )
    {
      execute_members_iterator(request);
      return;
    }

#endif

    if ( !get_names || !names_count || ( !dictionary_available && (!get_string || !free_rvalue || !find_slot) ) )
    {
      request.error = "Direct reflection & validated member-name fallback unavailable";
      request.status.store( GmdRequestStatus::Failed, std::memory_order_release );
      return;
    }

    RValue count_result{};
    count_result.kind = 5;

    RValue argument = object;

    if ( !call_routine( names_count, count_result, nullptr, nullptr, 1, &argument ) )
    {
      request.error = "variable_struct_names_count failed";
      request.status.store( GmdRequestStatus::Failed, std::memory_order_release );
      return;
    }

    std::int64_t count{-1};

    if (
         count_result.kind == 0 &&
         std::isfinite( count_result.value.real ) &&
         count_result.value.real >= 0.0 &&
         count_result.value.real <= static_cast< double >( MaximumMemberLimit )
       )
    {
      count = static_cast< std::int64_t >( count_result.value.real );
    }
    else if ( count_result.kind == 7 )
    {
      count = count_result.value.i32;
    }
    else if ( count_result.kind == 10 )
    {
       count = count_result.value.i64;
    }

    if ( count < 0 || count > MaximumMemberLimit || static_cast< std::uint64_t >( count ) > request.maximum )
    {
      request.error = "variable_struct_names_count returned an invalid / policy-limited count";
      request.status.store( GmdRequestStatus::Failed, std::memory_order_release );
      return;
    }

    if (count == 0)
    {
      request.status.store( GmdRequestStatus::Completed, std::memory_order_release );
      return;
    }

#if !defined(_WIN64)

    // GMS2 x86's member dictionary is the slot/name source
    // If its validated pattern is present, dont use the older inferred Code_Variable_FindAlloc helper / temporary-array storage.
    if ( execute_members_dictionary( request, count ) )
    {
      return;
    }

#endif

    RValue names{};
    names.kind = 5;

    if ( !call_routine( get_names, names, nullptr, nullptr, 1, &argument ) )
    {
      request.error = "variable_struct_get_names failed";
      request.status.store( GmdRequestStatus::Failed, std::memory_order_release );
      return;
    }

    if ( names.kind != 2 || !names.value.pointer )
    {
      call_free_rvalue( free_rvalue, &names );
      request.error = "variable_struct_get_names didnt return an array";
      request.status.store( GmdRequestStatus::Failed, std::memory_order_release );
      return;
    }

    auto storage_offset = g_array_storage_offset.load( std::memory_order_acquire );
    RValue* elements{};

    if ( storage_offset >= 0 && !validate_array_storage( names.value.pointer, storage_offset, static_cast<int>(count), elements ) )
    {
      storage_offset = -1;
      g_array_storage_offset.store( -1, std::memory_order_release );
    }

    if ( storage_offset < 0 && !discover_live_array_storage( names.value.pointer, static_cast<int>(count), storage_offset, elements ) )
    {
      call_free_rvalue( free_rvalue, &names );
      request.error = "Member-name array storage couldnt be validated";
      request.status.store( GmdRequestStatus::Failed, std::memory_order_release );
      return;
    }

    std::unordered_set< std::string > seen_names;

    std::unordered_set< int > seen_slots;

    request.members.reserve( static_cast< std::size_t >( count ) );

    for (std::int64_t index = 0; index < count; ++index)
    {
      const auto &name_value = elements[index];
      const char* name{};

      if ( name_value.kind != 1 || !call_get_string( get_string, &name_value, name ) )
      {
        call_free_rvalue( free_rvalue, &names );
        request.members.clear();
        request.error = "Member-name array contains a non-string / unreadable value";
        request.status.store( GmdRequestStatus::Failed, std::memory_order_release );
        return;
      }

      GmdMemberRecord record{};
      record.kind = -1;
      record.slot = -1;

      if ( !copy_name( name, record.name ) || !call_find_variable_slot( find_slot, request.object, record.name, record.slot ) )
      {
        call_free_rvalue( free_rvalue, &names );
        request.members.clear();
        request.error = "A reflected member name couldnt be resolved to its live runtime slot";
        request.status.store( GmdRequestStatus::Failed, std::memory_order_release );
        return;
      }

      if ( !seen_names.emplace( record.name ).second || !seen_slots.emplace( record.slot ).second )
      {
        call_free_rvalue( free_rvalue, &names );
        request.members.clear();
        request.error = "Member-name fallback returned duplicate names / runtime slots";
        request.status.store( GmdRequestStatus::Failed, std::memory_order_release );
        return;
      }

      request.members.push_back(record);
    }

    if ( !call_free_rvalue( free_rvalue, &names ) )
    {
      request.members.clear();
      request.error = "Member-name array couldnt be released safely";
      request.status.store( GmdRequestStatus::Failed, std::memory_order_release );
      return;
    }

    request.status.store( GmdRequestStatus::Completed, std::memory_order_release );
  }

  /// Reflect all requested members of an object
  ///
  /// returned names are copied, addresses remain pointers to runner-owned RValues.
  // CE later accepts a name only when this ptr matches a slot already found by memory-structure enumeration
  void execute_members(Request &request)
  {
    const auto keys_function = g_struct_get_keys.load( std::memory_order_acquire );

    const auto member_function = g_struct_get_member.load( std::memory_order_acquire );

    auto fallback_available = g_member_get_names.load( std::memory_order_acquire ) &&
                              g_member_names_count.load( std::memory_order_acquire ) &&
                              g_yy_get_string.load( std::memory_order_acquire ) &&
                              g_free_rvalue.load( std::memory_order_acquire ) &&
                              g_find_variable_slot.load( std::memory_order_acquire );

#if !defined(_WIN64)

    fallback_available = fallback_available ||
                         (
                           g_member_get_names.load( std::memory_order_acquire ) &&
                           g_variable_name_from_slot.load( std::memory_order_acquire ) &&
                           (
                             g_member_names_count.load( std::memory_order_acquire ) ||
                             g_member_dictionary_iterator.load( std::memory_order_acquire )
                           )
                         );

#endif

    // StructGetKeys expects RValue whose payload is the YYObjectBase pointer, not the raw object pointer passed to the bridge ABI.
    RValue object{};

    object.value.pointer = request.object;
    object.kind = 6;

    const auto use_fallback = [&]()
    {
      request.members.clear();
      request.error.clear();
      execute_members_fallback( request, object );
    };

#if !defined(_WIN64)

    // GMS2 x86 interface revisions reuse/shift slots that later became direct reflection entries.
    if (fallback_available)
    {
      use_fallback();
      return;
    }

#endif

    if ( !keys_function || !member_function )
    {
      use_fallback();
      return;
    }

    // First ask for the count, then allocate exactly that many key pointers.
    // request.maximum is a caller policy limit
    int count{};

    if ( !call_keys_count( keys_function, &object, count ) || count < 0 || static_cast< std::uint32_t >( count ) > MaximumMemberLimit )
    {
      if (fallback_available)
      {
        use_fallback();
        return;
      }

      request.error = "StructGetKeys count query failed";

      request.status.store( GmdRequestStatus::Failed, std::memory_order_release );

      return;
    }

    // Zero is also the characteristic false-positive result from older YYRunnerInterface layouts whose slots 91/92 contain unrelated functions.
    // The built-in fallback is fine for both genuinely empty & legacy objects, use it whenever it is available
    if (count == 0 && fallback_available)
    {
      use_fallback();
      return;
    }

    if ( static_cast< std::uint32_t >( count ) > request.maximum )
    {
      if (fallback_available)
      {
        use_fallback();
        return;
      }

      request.error = "StructGetKeys count exceeds the caller policy limit";
      request.status.store( GmdRequestStatus::Failed, std::memory_order_release );
      return;
    }

    std::vector< const char* > names( static_cast< std::size_t >( count ) );

    int filled = count;

    if ( count && (!call_keys( keys_function, &object, names.data(), filled ) || filled != count ) )
    {
      if (fallback_available)
      {
        use_fallback();
        return;
      }

      request.error = "StructGetKeys enumeration failed";

      request.status.store( GmdRequestStatus::Failed, std::memory_order_release );

      return;
    }

    // StructGetMember is called for every copied key so the record contains the authoritative RValue address AND name.
    request.members.reserve( static_cast< std::size_t >( filled ) );

    for (int index = 0; index < filled; ++index)
    {
      const char* name = names[ static_cast< std::size_t >( index ) ];

      if (!name)
      {
        if (fallback_available)
        {
          use_fallback();
          return;
        }

        request.error = "StructGetKeys returned a null name";
        request.members.clear();
        request.status.store( GmdRequestStatus::Failed, std::memory_order_release );
        return;
      }

      GmdMemberRecord record{};
      record.slot = -1;

      if ( !copy_name( name, record.name ) )
      {
        if (fallback_available)
        {
          use_fallback();
          return;
        }

        request.error = "StructGetKeys returned an invalid or oversized name";
        request.members.clear();
        request.status.store( GmdRequestStatus::Failed, std::memory_order_release );
        return;
      }

      RValue* value{};

      if ( !call_member( member_function, &object, name, value ) || !value )
      {
        if (fallback_available)
        {
          use_fallback();
          return;
        }

        request.error = "StructGetMember failed for a reflected name";
        request.members.clear();
        request.status.store( GmdRequestStatus::Failed, std::memory_order_release );
        return;
      }

      record.address = reinterpret_cast< std::uint64_t >( value );
      
      record.kind = read_kind( value );
      
      request.members.push_back( record );
    }

    request.status.store( GmdRequestStatus::Completed, std::memory_order_release );
  }

  /// Resolve & execute a user-defined GML function on the runner thread.
  void execute_script(Request &request)
  {
    const auto find_function = g_script_find_id.load( std::memory_order_acquire );

    const auto perform_function = g_script_perform.load( std::memory_order_acquire );

    const auto configured_script_execute = g_script_execute.load( std::memory_order_acquire );

    if ( !find_function || (!perform_function && !configured_script_execute) )
    {
      request.error = "Script_Find_Id/Script_Perform are unavailable in this runner interface";
      request.status.store( GmdRequestStatus::Failed, std::memory_order_release );
      
      return;
    }

    if ( !call_script_find( find_function, request.script_name.c_str(), request.script_id ) )
    {
      request.error = "An exception occurred while resolving the user-defined function";
      request.status.store( GmdRequestStatus::Failed, std::memory_order_release );

      return;
    }

    if ( request.script_id < 0 )
    {
      request.error = "User-defined function was not found";
      request.status.store( GmdRequestStatus::Failed, std::memory_order_release );

      return;
    }

    request.result = {};

    bool called{};

    // Newer runners expose script_execute as a normal built-in.
    // It expects resolved script ID as argument zero.
    // Older interfaces provide the direct Script_Perform entry instead, so both paths share one request format.
    if (configured_script_execute)
    {
      std::vector<RValue> arguments;

      arguments.reserve( request.arguments.size() + 1 );

      RValue script{};

      script.value.real = static_cast< double >( request.script_id );
      script.kind = 0;

      arguments.push_back( script );

      arguments.insert( arguments.end(), request.arguments.begin(), request.arguments.end() );
      
      called = call_routine( 
                             configured_script_execute,
                             request.result,
                             request.self,
                             request.other,
                             static_cast<int>( arguments.size()), arguments.data()
                            );
    }
    else
    {
      called = call_script_perform(
                                    perform_function,
                                    request.script_id,
                                    request.self,
                                    request.other,
                                    static_cast<int>( request.arguments.size() ),
                                    &request.result,
                                    request.arguments.empty() ? nullptr : request.arguments.data()
                                  );
    }

    if (!called)
    {
      request.error = "The user-defined function call failed or raised an exception";
      request.status.store( GmdRequestStatus::Failed, std::memory_order_release );
      return;
    }

    request.status.store( GmdRequestStatus::Completed, std::memory_order_release );
  }

  /// Execute a caller-validated runner routine on the GameMaker thread.
  ///
  /// This is used for special built-ins such as @@GlobalScope@@ whose returned
  /// RValue exposes runtime state that is not reachable from the room list.
  void execute_routine(Request &request)
  {
    if ( !request.routine )
    {
      request.error = "Runner routine unavailable";
      request.status.store( GmdRequestStatus::Failed, std::memory_order_release );
      return;
    }

    request.result = {};

    if ( !call_routine(
                        request.routine,
                        request.result,
                        request.self,
                        request.other,
                        static_cast<int>( request.arguments.size() ),
                        request.arguments.empty() ? nullptr : request.arguments.data()
                      )
        )
    {
      request.error = "The runner routine raised an exception";
      request.status.store( GmdRequestStatus::Failed, std::memory_order_release );
      return;
    }

    request.status.store( GmdRequestStatus::Completed, std::memory_order_release );
  }

  /// Enumerate one live GameMaker array on the runner thread.
  void execute_array(Request &request)
  {
    const auto length_function = g_array_get_length.load( std::memory_order_acquire );

    const auto length_routine = g_array_length_routine.load( std::memory_order_acquire );

    if ( !length_function && !length_routine )
    {
      request.error = "YYArrayGetLength and the array_length built-in are unavailable";
      request.status.store( GmdRequestStatus::Failed, std::memory_order_release );
      return;
    }

    auto* array = static_cast< RValue* >( request.object );
    __try
    {
      if ( !array || array->kind != 2 || !array->value.pointer )
      {
        request.error = "The requested RValue is not a live array";
        request.status.store( GmdRequestStatus::Failed, std::memory_order_release );
        return;
      }

      // Length comes from runner code. The element ptr is obtained separately because DynamicArrayOfRValue isnt ABI-stable
      int length = -1;

      const auto have_length = ( length_function && call_array_get_length( length_function, array, length ) ) ||
                               ( length_routine && call_array_length_routine( length_routine, array, length ) );

      if (!have_length)
      {
        request.error = "The runner rejected both array-length queries";
        request.status.store( GmdRequestStatus::Failed, std::memory_order_release );
        return;
      }

      if (length == 0)
      {
        request.status.store( GmdRequestStatus::Completed, std::memory_order_release );
        return;
      }

      // Prefer statically inferred offset, invalidate it if this array does not validate, then make a bounded layout discovery attempt.
      auto storage_offset = g_array_storage_offset.load( std::memory_order_acquire );

      RValue* elements{};

      if ( storage_offset >= 0 && !validate_array_storage( array->value.pointer, storage_offset, length, elements ) )
      {
        storage_offset = -1;
        g_array_storage_offset.store( -1, std::memory_order_release );
      }

      if ( storage_offset < 0 && !discover_live_array_storage( array->value.pointer, length, storage_offset, elements ) )
      {
        request.error = length == 0 ? "array-storage offset unavailable & cant be inferred from empty array" : "array-storage offset couldnt be validated from the array";
        request.status.store( GmdRequestStatus::Failed, std::memory_order_release );
        return;
      }

      if ( length && !elements )
      {
        request.error = "The array element storage is null";
        request.status.store( GmdRequestStatus::Failed, std::memory_order_release );
        return;
      }

      const auto count = std::min< std::uint32_t >( static_cast< std::uint32_t >( length ), request.maximum );

      request.members.reserve( count );

      for (std::uint32_t index = 0; index < count; ++index)
      {
        GmdMemberRecord record{};

        record.address = reinterpret_cast< std::uint64_t >( &elements[index] );
        record.kind = elements[index].kind;

        _snprintf_s( record.name, sizeof( record.name ), _TRUNCATE, "[%u]", index );
        request.members.push_back( record );
      }
    }
    __except ( EXCEPTION_EXECUTE_HANDLER )
    {
      request.error = "An exception occurred while enumerating the array";
      request.status.store( GmdRequestStatus::Failed, std::memory_order_release );
      return;
    }

    request.status.store( GmdRequestStatus::Completed, std::memory_order_release );
  }

  /// Dispatch a request whose status has already transitioned to Running.
  void execute_request(Request &request)
  {
    if      ( request.kind == RequestKind::Script )
    {
      execute_script(request);
    }
    else if ( request.kind == RequestKind::Routine )
    {
      execute_routine(request);
    }
    else if ( request.kind == RequestKind::Array )
    {
      execute_array(request);
    }
    else
    {
      execute_members(request);
    }

    if ( request.status.load( std::memory_order_acquire ) == GmdRequestStatus::Failed )
    {
      set_error( request.error );
    }

  }

  // ---------------------------- Queue dispatcher -------------------------------

  /// Detach queued requests with mutex, then execute them without it.
  ///
  /// Runner calls can re-enter hooked code
  /// Releasing g_mutex before execution prevents that re-entry from deadlocking queue/status operations.
  void drain_queue()
  {
    std::deque< Request* > ready;
    {
      std::scoped_lock lock( g_mutex );

      while ( !g_queue.empty() )
      {
        auto* request = g_queue.front();

        g_queue.pop_front();

        g_pending_requests.fetch_sub( 1, std::memory_order_release );

        auto expected = GmdRequestStatus::Queued;

        if ( request->status.compare_exchange_strong( expected, GmdRequestStatus::Running, std::memory_order_acq_rel ) )
        {
          ready.push_back(request);
        }

      }
    }

    for (auto* request : ready)
    {
      execute_request(* request );
    }

  }

  /// Code_Execute detour
  ///
  /// The first thread reaching the detour becomes the scheduler.
  /// Worker / rendering threads may also call Code_Execute in some runners;
  /// they always forward to the original function but never drain reflection requests.
  bool GMD_CODE_EXECUTE_CONVENTION dispatch_code_execute(void* self, void* other, void* code, RValue* arguments, int flags)
  {
    g_active_dispatches.fetch_add( 1, std::memory_order_acquire );

    DWORD expected{};

    g_scheduler_thread.compare_exchange_strong( expected, GetCurrentThreadId(), std::memory_order_acq_rel );

    if ( g_pending_requests.load( std::memory_order_acquire ) != 0 && GetCurrentThreadId() == g_scheduler_thread.load( std::memory_order_acquire ) )
    {
      drain_queue();
    }

    const bool result = g_code_execute_original( self, other, code, arguments, flags );

    g_active_dispatches.fetch_sub( 1, std::memory_order_release );

    return result;
  }

  /// Initialize MinHook once for the lifetime of the injected DLL.
  bool initialize_minhook()
  {
    if ( g_minhook_initialized )
    {
      return true;
    }

    const auto status = MH_Initialize();

    if ( status != MH_OK && status != MH_ERROR_ALREADY_INITIALIZED )
    {
      set_error( std::string( "MinHook initialization failed: " ) + MH_StatusToString( status ) );
      return false;
    }

    g_minhook_initialized = true;

    return true;
  }

  /// Transfer a request into bridge ownership.
  ///
  /// Construction & validation happen before this function.
  ///  Once inserted, the raw ptr is stable until the caller releases its opaque handle.
  Request* enqueue_request(std::unique_ptr<Request> request)
  {
    std::scoped_lock lock( g_mutex );

    if ( !g_hook_created )
    {
      set_error( "Code_Execute dispatcher is not configured" );
      return nullptr;
    }

    auto* handle = request.release();

    g_requests.insert( handle );

    g_queue.push_back( handle );

    g_pending_requests.fetch_add( 1, std::memory_order_release );

    return handle;
  }

  /// Validate an opaque C handle against bridge-owned request storage.
  Request* checked_request(void* handle)
  {
    if (!handle)
    {
      return nullptr;
    }

    std::scoped_lock lock( g_mutex );

    auto* request = static_cast< Request* >( handle );
    
    return g_requests.contains( request ) ? request : nullptr;
  }
} // namespace gmd::bridge::detail

using namespace gmd::bridge::detail; // to match the C ABI declared by GMDumperBridge.h.

// =============================================================================
// Public C ABI: version and configuration
// =============================================================================

/// Return the implementation version used for stale-DLL detection.
std::uint32_t gmd_bridge_version()
{
  return 0x00010000u;
}

/// Return ABI generation
std::uint32_t gmd_bridge_abi()
{
  return BridgeAbi;
}

/// Return the target pointer size used by this bridge binary.
std::uint32_t gmd_bridge_pointer_size()
{
  return static_cast< std::uint32_t >( sizeof(void*) );
}

/// Configure version-specific YYRunnerInterface slots and validation bounds.
///
/// The profile doesnt publish any runner pointers, only constrains the subsequent scanner pass;
/// all candidate functions still require structural validation.
std::uint32_t gmd_configure_discovery_profile(
                                                std::uint32_t yy_get_string_offset,
                                                std::uint32_t free_rvalue_offset,
                                                std::uint32_t script_find_id_offset,
                                                std::uint32_t script_perform_offset,
                                                std::uint32_t struct_add_rvalue_offset,
                                                std::uint32_t struct_get_member_offset,
                                                std::uint32_t struct_get_keys_offset,
                                                std::uint32_t array_get_length_offset,
                                                std::uint32_t minimum_assignments,
                                                std::uint32_t maximum_assignments,
                                                std::uint32_t maximum_stack_span,
                                                std::uint32_t maximum_instruction_span,
                                                std::uint32_t maximum_function_distance,
                                                std::uint32_t maximum_base_slack
                                              )
{
  clear_error();

  const auto aligned = [](std::uint32_t value)
  {
    return value <= 0x2000 && value % sizeof(void*) == 0;
  };

  if (
       !aligned( yy_get_string_offset ) ||
       !aligned( free_rvalue_offset ) ||
       !aligned( script_find_id_offset ) ||
       !aligned( script_perform_offset ) ||
       !aligned( struct_add_rvalue_offset ) ||
       !aligned( struct_get_member_offset ) ||
       !aligned( struct_get_keys_offset ) ||
       !aligned( array_get_length_offset ) ||
       struct_get_member_offset == struct_get_keys_offset ||
       minimum_assignments < 8 ||
       maximum_assignments < minimum_assignments ||
       maximum_assignments > 1024 ||
       maximum_stack_span < 0x80 ||
       maximum_stack_span > 0x4000 ||
       maximum_instruction_span < 0x100 ||
       maximum_instruction_span > 0x10000 ||
       maximum_function_distance < 0x20 ||
       maximum_function_distance > 0x10000 ||
       maximum_base_slack > 0x1000
    )
  {
    set_error( "Invalid runner-interface discovery profile" );
    return 0;
  }

  std::scoped_lock lock( g_discovery_mutex );
  
  g_discovery_profile =
  {
    static_cast< std::ptrdiff_t >( yy_get_string_offset ),
    static_cast< std::ptrdiff_t >( free_rvalue_offset ),
    static_cast< std::ptrdiff_t >( script_find_id_offset ),
    static_cast< std::ptrdiff_t >( script_perform_offset ),
    static_cast< std::ptrdiff_t >( struct_add_rvalue_offset ),
    static_cast< std::ptrdiff_t >( struct_get_member_offset ),
    static_cast< std::ptrdiff_t >( struct_get_keys_offset ),
    static_cast< std::ptrdiff_t >( array_get_length_offset ),
    minimum_assignments,
    maximum_assignments,
    maximum_stack_span,
    maximum_instruction_span,
    maximum_function_distance,
    maximum_base_slack,
  };

  return 1;
}

/// Install Code_Execute detour used by queued requests.
std::uint32_t gmd_configure_dispatcher(void* code_execute)
{
  clear_error();

  if (!code_execute)
  {
    set_error( "Invalid Code_Execute address" );
    return 0;
  }

  std::scoped_lock lock( g_mutex );
  
  if ( g_hook_created && code_execute == g_code_execute_target )
  {
    return 1;
  }

  if ( g_hook_created )
  {
    set_error( "A different Code_Execute dispatcher is already configured" );
    return 0;
  }

  if ( !initialize_minhook() )
  {
    return 0;
  }

  const auto created = MH_CreateHook( code_execute, reinterpret_cast< void* >( &dispatch_code_execute ), reinterpret_cast< void** >( &g_code_execute_original ) );
  
  if ( created != MH_OK )
  {
    set_error( std::string( "Could not create Code_Execute detour: " ) + MH_StatusToString( created ) );
    return 0;
  }

  const auto enabled = MH_EnableHook( code_execute );

  if ( enabled != MH_OK && enabled != MH_ERROR_ENABLED )
  {
    MH_RemoveHook( code_execute );

    g_code_execute_original = nullptr;

    set_error( std::string( "Could not enable Code_Execute detour: " ) + MH_StatusToString( enabled ) );

    return 0;
  }

  g_code_execute_target = code_execute;

  g_hook_created = true;

  return 1;
}

/// Discover reflection functions in the process main module.
std::uint32_t gmd_discover_reflection()
{
  clear_error();
  return discover_reflection( GetModuleHandleW(nullptr) ) ? 1u : 0u;
}

/// Discover reflection functions in an explicitly supplied runner module.
std::uint32_t gmd_discover_reflection_at(void* module)
{
  clear_error();
  return discover_reflection( static_cast< HMODULE >( module ) ) ? 1u : 0u;
}

/// Supply already validated StructGetKeys and StructGetMember addresses.
std::uint32_t gmd_configure_reflection(void* keys, void* member)
{
  if ( !keys || !member )
  {
    set_error( "StructGetKeys & StructGetMember must both be non-null" );
    return 0;
  }

  g_struct_get_keys.store( reinterpret_cast< StructGetKeys >( keys ), std::memory_order_release );

  g_struct_get_member.store( reinterpret_cast< StructGetMember >( member ), std::memory_order_release );

  return 1;
}

/// Restore YYRunnerInterface helper from cache
std::uint32_t gmd_configure_cached_interface(
                                              void* yy_get_string,
                                              void* free_rvalue,
                                              void* script_find_id,
                                              void* script_perform,
                                              void* struct_add_rvalue,
                                              void* struct_get_member,
                                              void* struct_get_keys,
                                              void* array_get_length
                                            )
{
  clear_error();

  const std::array< void*, 8 > helpers
  {
    yy_get_string,
    free_rvalue,
    script_find_id,
    script_perform,
    struct_add_rvalue,
    struct_get_member,
    struct_get_keys,
    array_get_length,
  };

  for ( const auto helper : helpers )
  {
    if ( !executable_pointer( helper ) )
    {
      set_error( "Cached YYRunnerInterface contains a non-executable helper" );
      return 0;
    }
  }

  g_yy_get_string.store( reinterpret_cast< YYGetString >( yy_get_string ), std::memory_order_release );

  g_free_rvalue.store( reinterpret_cast< FreeRValue >( free_rvalue ), std::memory_order_release );

  g_script_find_id.store( reinterpret_cast< ScriptFindId >( script_find_id ), std::memory_order_release );

  g_script_perform.store( reinterpret_cast< ScriptPerform >( script_perform ), std::memory_order_release );

  g_struct_add_rvalue.store( reinterpret_cast< Routine >( struct_add_rvalue ), std::memory_order_release );

  g_find_variable_slot.store( discover_find_variable_slot(struct_add_rvalue), std::memory_order_release );

  g_struct_get_member.store( reinterpret_cast< StructGetMember >( struct_get_member ), std::memory_order_release );

  g_struct_get_keys.store( reinterpret_cast< StructGetKeys >( struct_get_keys ), std::memory_order_release );

  g_array_get_length.store( reinterpret_cast< ArrayGetLength >( array_get_length ), std::memory_order_release );

  return 1;
}

/// Configure public built-ins used when the runner interface predates direct StructGetKeys/StructGetMember entries
std::uint32_t gmd_configure_member_fallback(void* get_names, void* names_count)
{
  clear_error();

  if (!get_names)
  {
    set_error( "Member-name fallback requires a get-names routine" );
    return 0;
  }

  g_member_get_names.store( reinterpret_cast< Routine >( get_names ), std::memory_order_release );
  g_member_names_count.store( reinterpret_cast< Routine >( names_count ), std::memory_order_release );

  const auto legacy_helpers = names_count &&
                              g_yy_get_string.load( std::memory_order_acquire ) &&
                              g_free_rvalue.load( std::memory_order_acquire ) &&
                              g_find_variable_slot.load( std::memory_order_acquire );

  auto dictionary_helpers = false;

#if !defined(_WIN64)

  dictionary_helpers = discover_x86_member_dictionary( reinterpret_cast< Routine >( get_names ), reinterpret_cast< Routine >( names_count ) );

#endif

  if ( !legacy_helpers && !dictionary_helpers )
  {
    g_member_get_names.store( nullptr, std::memory_order_release );
    g_member_names_count.store( nullptr, std::memory_order_release );

    set_error( "Runner lacks a validated member dictionary & legacy reflection helpers" );
    return 0;
  }

  return 1;
}

/// Configure array helpers & infer the internal element-storage offset.
std::uint32_t gmd_configure_array_access(void* array_equals, void* array_length)
{
  g_array_length_routine.store( reinterpret_cast< Routine >( array_length ), std::memory_order_release );

  const auto offset = discover_array_storage_offset( array_equals );

  if ( offset < 0 )
  {
    set_error( "array_equals routine didnt reveal DynamicArrayOfRValue::m_Array" );
    return 0;
  }

  g_array_storage_offset.store( offset, std::memory_order_release );

  return 1;
}

/// Configure the optional script_execute built-in fallback.
std::uint32_t gmd_configure_script_execute(void* script_execute)
{
  if ( !script_execute )
  {
    set_error( "script_execute routine is null" );
    return 0;
  }

  g_script_execute.store( reinterpret_cast< Routine >( script_execute ), std::memory_order_release );

  return 1;
}

// =============================================================================
// Public C ABI: discovered capability queries
// =============================================================================

/// Return the discovered StructGetKeys address, or zero when unavailable.
std::uint64_t gmd_get_struct_get_keys()
{
  return reinterpret_cast< std::uint64_t >( g_struct_get_keys.load( std::memory_order_acquire ) );
}

/// Return the discovered StructGetMember address, or zero when unavailable.
std::uint64_t gmd_get_struct_get_member()
{
  return reinterpret_cast< std::uint64_t >( g_struct_get_member.load( std::memory_order_acquire ) );
}

/// Return the discovered YYGetString address, or zero when unavailable.
std::uint64_t gmd_get_yy_get_string()
{
  return reinterpret_cast< std::uint64_t >( g_yy_get_string.load( std::memory_order_acquire ) );
}

/// Return the discovered FREE_RValue address, or zero when unavailable.
std::uint64_t gmd_get_free_rvalue()
{
  return reinterpret_cast< std::uint64_t >( g_free_rvalue.load( std::memory_order_acquire ) );
}

/// Return the discovered StructAddRValue address, or zero when unavailable.
std::uint64_t gmd_get_struct_add_rvalue()
{
  return reinterpret_cast< std::uint64_t >( g_struct_add_rvalue.load( std::memory_order_acquire ) );
}

/// Return the discovered Script_Find_Id address, or zero when unavailable.
std::uint64_t gmd_get_script_find_id()
{
  return reinterpret_cast< std::uint64_t >( g_script_find_id.load( std::memory_order_acquire ) );
}

/// Return the discovered Script_Perform address, or zero when unavailable.
std::uint64_t gmd_get_script_perform()
{
  return reinterpret_cast< std::uint64_t >( g_script_perform.load( std::memory_order_acquire ) );
}

/// Return the discovered YYArrayGetLength address, or zero when unavailable.
std::uint64_t gmd_get_array_length()
{
  return reinterpret_cast< std::uint64_t >( g_array_get_length.load( std::memory_order_acquire ) );
}

/// Return the validated DynamicArrayOfRValue element offset, or -1.
std::int64_t gmd_get_array_storage_offset()
{
  return g_array_storage_offset.load( std::memory_order_acquire );
}

/// Return the thread selected to drain bridge requests.
std::uint32_t gmd_get_scheduler_thread_id()
{
  return g_scheduler_thread.load( std::memory_order_acquire );
}

// =============================================================================
// Public C ABI: request creation
// =============================================================================

/// Queue runtime member reflection for one YYObjectBase pointer.
void* gmd_queue_members(void* object, std::uint32_t maximum)
{
  if ( !object || maximum == 0 || maximum > MaximumMemberLimit )
  {
    set_error( "Invalid object or member limit" );
    return nullptr;
  }

  auto request = std::make_unique< Request >();

  request->object = object;
  request->maximum = maximum;

  return enqueue_request( std::move(request) );
}

/// Queue enumeration of an array RValue.
void* gmd_queue_array(GmdRValue* array, std::uint32_t maximum)
{
  if ( !array || maximum == 0 || maximum > MaximumMemberLimit )
  {
    set_error( "Invalid array/element limit" );
    return nullptr;
  }

  auto request = std::make_unique< Request >();

  request->kind = RequestKind::Array;
  request->object = array;
  request->maximum = maximum;

  return enqueue_request( std::move(request) );
}

/// @brief Queue one user-defined GML call for the GameMaker thread.
void* gmd_queue_script( const char* name, void* self, void* other, const GmdRValue* arguments, std::uint32_t argument_count )
{
  if ( !name || argument_count > MaximumArgumentCount || ( argument_count && !arguments ) )
  {
    set_error( "Invalid script call request" );
    return nullptr;
  }

  auto request = std::make_unique< Request >();

  request->kind = RequestKind::Script;
  request->self = self;
  request->other = other;

  char copied_name[512]{};

  if ( !safe_copy( copied_name, name, sizeof( copied_name ) - 1 ) )
  {
    set_error( "Script name unreadable" );
    return nullptr;
  }

  copied_name[ sizeof( copied_name ) - 1 ] = '\0';

  const auto name_length = strnlen_s( copied_name, sizeof( copied_name ) );

  if ( name_length == 0 || name_length == sizeof( copied_name ) )
  {
    set_error("Script name empty / too long");
    return nullptr;
  }

  request->script_name.assign( copied_name, name_length );
  request->arguments.resize( argument_count );

  if ( argument_count && !safe_copy( request->arguments.data(), arguments, argument_count*  sizeof( RValue ) ) )
  {
    set_error( "Script arguments unreadable" );
    return nullptr;
  }

  return enqueue_request( std::move(request) );
}

/// @brief Queue one resolved built-in routine for the GameMaker thread.
void* gmd_queue_routine( void* routine, void* self, void* other, const GmdRValue* arguments, std::uint32_t argument_count )
{
  if ( !routine || argument_count > MaximumArgumentCount || ( argument_count && !arguments ) )
  {
    set_error( "Invalid runner routine request" );
    return nullptr;
  }

  auto request = std::make_unique< Request >();

  request->kind = RequestKind::Routine;
  request->routine = reinterpret_cast< Routine >( routine );
  request->self = self;
  request->other = other;
  request->arguments.resize( argument_count );

  if ( argument_count && !safe_copy( request->arguments.data(), arguments, argument_count*  sizeof( RValue ) ) )
  {
    set_error( "Runner routine arguments unreadable" );
    return nullptr;
  }

  return enqueue_request( std::move(request) );
}

// =============================================================================
// Public C ABI: request observation and ownership
// =============================================================================

/// Read the current status of an opaque request handle.
std::uint32_t gmd_get_request_status(void* handle)
{
  auto* request = checked_request( handle );
  
  if (!request)
  {
    set_error( "Invalid request handle" );
    return 0;
  }

  if ( request->status.load( std::memory_order_acquire ) == GmdRequestStatus::Failed )
  {
    set_error( request->error );
  }

  return static_cast< std::uint32_t >( request->status.load( std::memory_order_acquire ) );
}

/// Return the number of materialized member/array records.
std::uint32_t gmd_get_member_count(void* handle)
{
  auto* request = checked_request( handle );

  if ( !request || request->status.load( std::memory_order_acquire ) != GmdRequestStatus::Completed )
  {
    set_error( "Request is not complete" );
    return 0;
  }

  return static_cast< std::uint32_t >( request->members.size() );
}

/// Copy completed member/array records into CE-allocated target memory.
std::uint32_t gmd_copy_members(void* handle, GmdMemberRecord* destination, std::uint32_t capacity)
{
  auto* request = checked_request( handle );

  if (
        !request ||
        request->status.load( std::memory_order_acquire ) != GmdRequestStatus::Completed ||
        capacity < request->members.size() ||
        ( !destination && !request->members.empty() )
      )
  {
    set_error( "Invalid completed request / output capacity" );
    return 0;
  }

  if ( !safe_copy( destination, request->members.data(), request->members.size() * sizeof( GmdMemberRecord ) ) )
  {
    set_error( "Output buffer isnt writable" );
    return 0;
  }

  return static_cast< std::uint32_t >( request->members.size() );
}

/// Copy a completed script/routine result into CE-allocated target memory.
std::uint32_t gmd_copy_call_result(void* handle, GmdRValue* destination)
{
  auto* request = checked_request( handle );

  if (
        !request ||
        ( request->kind != RequestKind::Script && request->kind != RequestKind::Routine ) ||
        request->status.load( std::memory_order_acquire ) != GmdRequestStatus::Completed ||
        !destination
      )
  {
    set_error( "Invalid completed call request / result buffer" );
    return 0;
  }

  if ( !safe_copy( destination, &request->result, sizeof( request->result ) ) )
  {
    set_error( "Result buffer isnt writable" );
    return 0;
  }

  return 1;
}

/// Cancel a request only while it is still queued.
std::uint32_t gmd_cancel_request(void* handle)
{
  std::scoped_lock lock( g_mutex );

  auto* request = static_cast< Request* >( handle );

  if ( !request || !g_requests.contains( request ) )
  {
    set_error( "Invalid request handle" );
    return 0;
  }

  auto expected = GmdRequestStatus::Queued;

  if ( !request->status.compare_exchange_strong( expected, GmdRequestStatus::Cancelled, std::memory_order_acq_rel ) )
  {
    set_error( "Request already running / terminal" );
    return 0;
  }

  if ( std::erase( g_queue, request ) != 0 )
  {
    g_pending_requests.fetch_sub( 1, std::memory_order_release );
  }

  return 1;
}

/// Release a terminal request & invalidate its opaque handle.
std::uint32_t gmd_release_request(void* handle)
{
  std::scoped_lock lock( g_mutex );

  auto* request = static_cast< Request* >( handle );

  if ( !request || !g_requests.contains( request ) )
  {
    set_error( "Invalid request handle" );
    return 0;
  }

  const auto status = request->status.load( std::memory_order_acquire );

  if ( status == GmdRequestStatus::Queued || status == GmdRequestStatus::Running )
  {
    set_error( "Request isnt terminal" );
    return 0;
  }

  g_requests.erase( request );

  if ( std::erase( g_queue, request ) != 0 )
  {
    g_pending_requests.fetch_sub( 1, std::memory_order_release );
  }

  delete request;
  return 1;
}

// =============================================================================
// Public C ABI: teardown and errors
// =============================================================================

/// Remove the Code_Execute detour after all requests and callbacks are idle.
std::uint32_t gmd_remove_dispatcher()
{
  std::scoped_lock lock( g_mutex );

  if ( !g_hook_created )
  {
    return 1;
  }

  if ( !g_queue.empty() || g_active_dispatches.load( std::memory_order_acquire ) != 0 )
  {
    set_error( "Dispatcher is active / requests are queued" );
    return 0;
  }

  const auto disabled = MH_DisableHook( g_code_execute_target );

  if ( disabled != MH_OK && disabled != MH_ERROR_DISABLED )
  {
    set_error( MH_StatusToString( disabled ) );
    return 0;
  }
  const auto removed = MH_RemoveHook( g_code_execute_target );

  if ( removed != MH_OK && removed != MH_ERROR_NOT_CREATED )
  {
    set_error( MH_StatusToString( removed ) );
    return 0;
  }

  g_hook_created = false;
  g_code_execute_target = nullptr;
  g_code_execute_original = nullptr;

  g_scheduler_thread.store( 0, std::memory_order_release );

  return 1;
}

/// Copy the last bridge diagnostic and return its required buffer size.
std::uint32_t gmd_get_last_error(char* buffer, std::uint32_t capacity)
{
  std::scoped_lock lock( g_error_mutex );

  const auto required = static_cast< std::uint32_t >( g_last_error.size() + 1 );

  if ( buffer && capacity )
  {
    const auto count = std::min< std::size_t >( g_last_error.size(), capacity - 1 ); // to fit the message

    std::memcpy( buffer, g_last_error.data(), count );

    buffer[count] = '\0'; // null terminator
  }
  
  return required;
}