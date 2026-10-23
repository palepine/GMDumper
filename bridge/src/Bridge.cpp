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
#include <atomic>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
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
    std::ptrdiff_t script_find_id_offset{ 0xF0 };
    std::ptrdiff_t script_perform_offset{ 0xF8 };
    std::ptrdiff_t struct_get_member_offset{ 0x2D8 };
    std::ptrdiff_t struct_get_keys_offset{ 0x2E0 };
    std::ptrdiff_t array_get_length_offset{ 0x310 };
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
      void *pointer;
    } value{};

    std::uint32_t flags{};
    std::int32_t kind{ 5 };
  };

#pragma pack(pop)

  static_assert( sizeof(RValue) == 16 );

  static_assert( sizeof(GmdRValue) == sizeof(RValue) );

  using CodeExecute = bool( __fastcall* )( void*, void*, void*, RValue*, int );

  using StructGetKeys = int (*)( RValue*, const char**, int* );

  using StructGetMember = RValue *(*)( RValue*, const char* );

  using ScriptFindId = int (*)( const char* );

  using ScriptPerform = bool (*)( int, void*, void*, int, RValue*, RValue* );

  using ArrayGetLength = int (*)( RValue* );

  using Routine = void (*)( RValue&, void*, void*, int, RValue* );

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

    void *object{};

    std::uint32_t maximum{};

    std::atomic< GmdRequestStatus > status{ GmdRequestStatus::Queued };

    std::vector< GmdMemberRecord > members;

    std::string script_name;

    Routine routine{};

    void *self{};

    void *other{};

    std::vector<RValue> arguments;

    RValue result;

    int script_id{ -1 };

    std::string error;
  };

  // ------------------------- Disassembly observations --------------------------

  struct Section
  {
    std::byte *start{};
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

  std::atomic< ScriptFindId > g_script_find_id{};

  std::atomic< ScriptPerform > g_script_perform{};

  std::atomic< ArrayGetLength > g_array_get_length{};

  std::atomic< Routine > g_array_length_routine{};

  std::atomic< std::int64_t > g_array_storage_offset{ -1 };

  std::atomic< Routine > g_script_execute{};

  // MinHook dispatcher state is mutated only while g_mutex is held.
  CodeExecute g_code_execute_original{};

  void *g_code_execute_target{};

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

  /// Recover YYRunnerInterface member assignments from the executable section.
  ///
  /// The extension initializer gets a runner function via LEA, stores that register into an RBP/RSP-relative interface slot.
  /// We retain only those LEA -> MOV pairs here; coherent initializer frames are selected & validated later by discover_reflection().
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

      if ( !ZYAN_SUCCESS( ZydisDisassembleIntel( ZYDIS_MACHINE_MODE_LONG_64, runtime, reinterpret_cast< const void* >( runtime ), end - runtime, &instruction ) ) )
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
            instruction.operands[1].mem.base == ZYDIS_REGISTER_RIP
          )
      {
        ZyanU64 absolute{};

        if ( ZYAN_SUCCESS( ZydisCalcAbsoluteAddress( &instruction.info, &instruction.operands[1], runtime, &absolute ) ) )
        {
          last_register = ZydisRegisterGetLargestEnclosing( ZYDIS_MACHINE_MODE_LONG_64, instruction.operands[0].reg.value );
          
          if ( last_register == ZYDIS_REGISTER_NONE )
          {
            last_register = instruction.operands[0].reg.value;
          }

          last_target = static_cast< std::uintptr_t >( absolute );
          last_lea = runtime;
        }

      }

      // associate the remembered address with its interface slot.
      // both frame-pointer & stack-pointer initializers exist in the wild.
      else if (
                instruction.info.mnemonic == ZYDIS_MNEMONIC_MOV &&
                instruction.info.operand_count_visible >= 2 &&
                instruction.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                ( instruction.operands[0].mem.base == ZYDIS_REGISTER_RBP || instruction.operands[0].mem.base == ZYDIS_REGISTER_RSP ) &&
                instruction.operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                runtime - last_lea <= 24
              )
      {
        auto source = ZydisRegisterGetLargestEnclosing( ZYDIS_MACHINE_MODE_LONG_64, instruction.operands[1].reg.value );

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
  std::vector< ZydisDisassembledInstruction > disassemble(void *start, std::size_t maximum)
  {
    std::vector< ZydisDisassembledInstruction > result;

    auto runtime = reinterpret_cast< std::uintptr_t >( start );

    const auto end = runtime + maximum;

    while ( runtime < end )
    {
      ZydisDisassembledInstruction instruction{};

      if ( !ZYAN_SUCCESS( ZydisDisassembleIntel( ZYDIS_MACHINE_MODE_LONG_64, runtime, reinterpret_cast< const void* >( runtime ), end - runtime, &instruction ) ) )
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
  void *follow_direct_jumps(void *function)
  {
    auto *current = function;

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

  /// Infer DynamicArrayOfRValue::m_Array from the body of an array routine.
  ///
  /// The implementation looks for two nearby loads using the same base and displacement.
  /// Requiring repetition rejects most incidental object loads;
  /// the resulting offset is still validated against an array before use.
  std::int64_t array_offset_from_body(void *function)
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
  std::int64_t discover_array_storage_offset(void *array_equals)
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

#if !defined(_WIN64)
    set_error("Runner-interface auto-discovery is implemented for x64 only");
    return false;
#else

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

    g_script_find_id.store( nullptr, std::memory_order_release );

    g_script_perform.store( nullptr, std::memory_order_release );

    g_array_get_length.store( nullptr, std::memory_order_release );


    // reduce .text section to candidate interface writes.
    const auto assignments = collect_stack_assignments( text );

    const auto text_start = reinterpret_cast< std::uintptr_t >( text.start );

    const auto text_end = text_start + text.size;

    // test bounded windows as possible initializer frames.
    // Looking at 1 coherent window avoids combining unrelated stack writes from nearby functions.
    for (std::size_t start = 0; start < assignments.size(); ++start)
    {
      std::size_t finish = start;

      while ( finish < assignments.size() && assignments[ finish ].instruction - assignments[ start ].instruction <= profile.maximum_instruction_span )
      {
        ++finish;
      }

      // RBP & RSP observations must not be mixed: their displacements have different origins even when they occur in the same instruction span
      std::vector< const Assignment* > frame_assignments;

      for (std::size_t index = start; index < finish; ++index)
      {

        if ( assignments[ index ].stack_base == assignments[ start ].stack_base )
        {
          frame_assignments.push_back( &assignments[ index ] );
        }

      }

      if ( frame_assignments.size() < profile.minimum_assignments || frame_assignments.size() > profile.maximum_assignments )
      {
        continue;
      }

      const auto displacement_less = [](const auto *left, const auto *right)
      {
        return left->displacement < right->displacement;
      };

      const auto first = *std::min_element( frame_assignments.begin(), frame_assignments.end(), displacement_less );

      const auto last = *std::max_element( frame_assignments.begin(), frame_assignments.end(), displacement_less );

      if ( last->displacement - first->displacement > profile.maximum_stack_span )
      {
        continue;
      }

      // each StructGetMember-looking assignment proposes interface base zero,
      // other required slots must exist at exact profile-relative offsets.
      for (const auto *member_assignment : frame_assignments)
      {
        const auto base = member_assignment->displacement - profile.struct_get_member_offset;

        const auto base_slack = first->displacement - base;

        if ( base > first->displacement || base_slack < 0 || base_slack > profile.maximum_base_slack || (base & 7) != 0 )
        {
          continue;
        }

        const auto target_at = [&]( std::ptrdiff_t offset ) -> std::uintptr_t
        {
          const auto displacement = base + offset;

          for (const auto *assignment : frame_assignments)
          {
            if ( assignment->displacement == displacement && assignment->target >= text_start && assignment->target < text_end )
            {
              return assignment->target;
            }
          }
          return 0;
        };

        // StructGetMember & StructGetKeys are mandatory.
        // Script and array entries are optional, but at least 1 must prove that this is a runner interface rather than an arbitrary function table.
        const auto member = target_at( profile.struct_get_member_offset );

        const auto keys = target_at( profile.struct_get_keys_offset );

        if ( !member || !keys )
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

        // publish only after the complete candidate passes validation
        // clearing the atomics above makes failed rediscovery fail closed.
        g_struct_get_member.store( reinterpret_cast< StructGetMember >( member ), std::memory_order_release );

        g_struct_get_keys.store( reinterpret_cast< StructGetKeys >( keys ), std::memory_order_release );

        if ( script_find )
        {
          g_script_find_id.store( reinterpret_cast< ScriptFindId >( script_find ), std::memory_order_release );
        }

        if ( script_perform )
        {
          g_script_perform.store( reinterpret_cast< ScriptPerform >( script_perform ), std::memory_order_release );
        }

        if ( array_length )
        {
          g_array_get_length.store( reinterpret_cast< ArrayGetLength >( array_length ), std::memory_order_release );
        }
        
        return true;
      }

    }
    
    set_error("YYRunnerInterface initializer wasnt recognized; configure StructGetKeys/StructGetMember manually");

    return false;
#endif // _WIN64 define end
  } // func end

  // ----------------------- Guarded runner API calls ----------------------------

  // Every recovered pointer is structurally validated before publication,
  // but the pointed-to object may disappear between queueing & execution.
  // SEH is therefore the final containment boundary around runner-owned memory/code.

  /// Query the number of keys using StructGetKeys' count-only convention.
  bool call_keys_count(StructGetKeys function, RValue *object, int &count)
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
  bool call_keys(StructGetKeys function, RValue *object, const char **keys, int &count)
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
  bool call_member(StructGetMember function, RValue *object, const char *key, RValue *&result)
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
  bool call_script_find(ScriptFindId function, const char *name, int &result)
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
  bool call_script_perform( ScriptPerform function, int id, void *self, void *other, int count, RValue *result, RValue *arguments )
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
  bool call_routine(Routine function, RValue &result, void *self, void *other, int count, RValue *arguments)
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

  /// Query array length through YYRunnerInterface when that entry is available.
  bool call_array_get_length(ArrayGetLength function, RValue *array, int &length)
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
  bool call_array_length_routine(Routine function, RValue *array, int &length)
  {
    RValue result{};

    result.kind = 5;

    RValue argument = *array;

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
  bool validate_array_storage(void *array_object, std::int64_t offset, int length, RValue *&elements)
  {
    __try
    {
      elements = *reinterpret_cast< RValue** >( static_cast< std::byte* >( array_object ) + offset );

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

      const auto sample_end = reinterpret_cast< std::uintptr_t >( elements ) + static_cast< std::uintptr_t >( sample_count ) * sizeof( RValue );
      
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
  bool discover_live_array_storage(void *array_object, int length, std::int64_t &offset, RValue *&elements)
  {
    if ( !array_object || length <= 0 )
    {
      return false;
    }

    std::int64_t selected_offset = -1;

    RValue *selected_elements{};

    for (std::int64_t candidate = sizeof( void* ); candidate <= 0x80; candidate += sizeof( void* ) )
    {
      RValue *candidate_elements{};

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
  bool copy_name(const char *source, char (&destination)[256])
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
  std::int32_t read_kind(RValue *value)
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
  bool safe_copy(void *destination, const void *source, std::size_t size)
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

  // ------------------------- Game-thread operations ----------------------------

  /// Reflect all requested members of an object
  ///
  /// returned names are copied, addresses remain pointers to runner-owned RValues.
  // CE later accepts a name only when this ptr matches a slot already found by memory-structure enumeration
  void execute_members(Request &request)
  {
    const auto keys_function = g_struct_get_keys.load( std::memory_order_acquire );

    const auto member_function = g_struct_get_member.load( std::memory_order_acquire );

    if ( !keys_function || !member_function )
    {
      request.error = "Reflection functions arent configured";
      
      request.status.store( GmdRequestStatus::Failed, std::memory_order_release );

      return;
    }

    // StructGetKeys expects RValue whose payload is the YYObjectBase pointer, not the raw object pointer passed to the bridge ABI.
    RValue object{};

    object.value.pointer = request.object;
    object.kind = 6;

    // First ask for the count, then allocate exactly that many key pointers.
    // request.maximum is a caller policy limit
    int count{};

    if ( !call_keys_count( keys_function, &object, count ) || count < 0 || static_cast< std::uint32_t >( count ) > MaximumMemberLimit )
    {
      request.error = "StructGetKeys count query failed";

      request.status.store( GmdRequestStatus::Failed, std::memory_order_release );

      return;
    }

    count = static_cast< int >( std::min< std::uint32_t >( static_cast< std::uint32_t >( count ), request.maximum ) );

    std::vector< const char* > names( static_cast< std::size_t >( count ) );

    int filled = count;

    if ( count && (!call_keys( keys_function, &object, names.data(), filled ) || filled < 0 || filled > count ) )
    {
      request.error = "StructGetKeys enumeration failed";

      request.status.store( GmdRequestStatus::Failed, std::memory_order_release );

      return;
    }

    // StructGetMember is called for every copied key so the record contains the authoritative RValue address AND name.
    request.members.reserve( static_cast< std::size_t >( filled ) );

    for (int index = 0; index < filled; ++index)
    {
      const char *name = names[ static_cast< std::size_t >( index ) ];

      if (!name)
      {
        continue;
      }

      GmdMemberRecord record{};

      if ( !copy_name( name, record.name ) )
      {
        continue;
      }

      RValue *value{};

      if ( !call_member( member_function, &object, name, value ) || !value )
      {
        continue;
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

    auto *array = static_cast< RValue* >( request.object );
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

      RValue *elements{};

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
        auto *request = g_queue.front();

        g_queue.pop_front();

        g_pending_requests.fetch_sub( 1, std::memory_order_release );

        auto expected = GmdRequestStatus::Queued;

        if ( request->status.compare_exchange_strong( expected, GmdRequestStatus::Running, std::memory_order_acq_rel ) )
        {
          ready.push_back(request);
        }

      }
    }

    for (auto *request : ready)
    {
      execute_request( *request );
    }

  }

  /// Code_Execute detour
  ///
  /// The first thread reaching the detour becomes the scheduler.
  /// Worker / rendering threads may also call Code_Execute in some runners;
  /// they always forward to the original function but never drain reflection requests.
  bool __fastcall dispatch_code_execute(void *self, void *other, void *code, RValue *arguments, int flags)
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
  Request *enqueue_request(std::unique_ptr<Request> request)
  {
    std::scoped_lock lock( g_mutex );

    if ( !g_hook_created )
    {
      set_error( "Code_Execute dispatcher is not configured" );
      return nullptr;
    }

    auto *handle = request.release();

    g_requests.insert( handle );

    g_queue.push_back( handle );

    g_pending_requests.fetch_add( 1, std::memory_order_release );

    return handle;
  }

  /// Validate an opaque C handle against bridge-owned request storage.
  Request *checked_request(void *handle)
  {
    if (!handle)
    {
      return nullptr;
    }

    std::scoped_lock lock( g_mutex );

    auto *request = static_cast< Request* >( handle );
    
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

/// Configure version-specific YYRunnerInterface slots and validation bounds.
///
/// The profile doesnt publish any runner pointers, only constrains the subsequent scanner pass;
/// all candidate functions still require structural validation.
std::uint32_t gmd_configure_discovery_profile(
                                                std::uint32_t script_find_id_offset,
                                                std::uint32_t script_perform_offset,
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
    return value <= 0x2000 && ( value & 7u ) == 0;
  };

  if (
       !aligned( script_find_id_offset ) ||
       !aligned( script_perform_offset ) ||
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
    static_cast< std::ptrdiff_t >( script_find_id_offset ),
    static_cast< std::ptrdiff_t >( script_perform_offset ),
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
std::uint32_t gmd_configure_dispatcher(void *code_execute)
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
std::uint32_t gmd_discover_reflection_at(void *module)
{
  clear_error();
  return discover_reflection( static_cast< HMODULE >( module ) ) ? 1u : 0u;
}

/// Supply already validated StructGetKeys and StructGetMember addresses.
std::uint32_t gmd_configure_reflection(void *keys, void *member)
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

/// Configure array helpers & infer the internal element-storage offset.
std::uint32_t gmd_configure_array_access(void *array_equals, void *array_length)
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
std::uint32_t gmd_configure_script_execute(void *script_execute)
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
void *gmd_queue_members(void *object, std::uint32_t maximum)
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
void *gmd_queue_array(GmdRValue *array, std::uint32_t maximum)
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
void *gmd_queue_script( const char *name, void *self, void *other, const GmdRValue *arguments, std::uint32_t argument_count )
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

  if ( argument_count && !safe_copy( request->arguments.data(), arguments, argument_count * sizeof( RValue ) ) )
  {
    set_error( "Script arguments unreadable" );
    return nullptr;
  }

  return enqueue_request( std::move(request) );
}

/// @brief Queue one resolved built-in routine for the GameMaker thread.
void *gmd_queue_routine( void *routine, void *self, void *other, const GmdRValue *arguments, std::uint32_t argument_count )
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

  if ( argument_count && !safe_copy( request->arguments.data(), arguments, argument_count * sizeof( RValue ) ) )
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
std::uint32_t gmd_get_request_status(void *handle)
{
  auto *request = checked_request( handle );
  
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
std::uint32_t gmd_get_member_count(void *handle)
{
  auto *request = checked_request( handle );

  if ( !request || request->status.load( std::memory_order_acquire ) != GmdRequestStatus::Completed )
  {
    set_error( "Request is not complete" );
    return 0;
  }

  return static_cast< std::uint32_t >( request->members.size() );
}

/// Copy completed member/array records into CE-allocated target memory.
std::uint32_t gmd_copy_members(void *handle, GmdMemberRecord *destination, std::uint32_t capacity)
{
  auto *request = checked_request( handle );

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
std::uint32_t gmd_copy_call_result(void *handle, GmdRValue *destination)
{
  auto *request = checked_request( handle );

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
std::uint32_t gmd_cancel_request(void *handle)
{
  std::scoped_lock lock( g_mutex );

  auto *request = static_cast< Request* >( handle );

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
std::uint32_t gmd_release_request(void *handle)
{
  std::scoped_lock lock( g_mutex );

  auto *request = static_cast< Request* >( handle );

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
std::uint32_t gmd_get_last_error(char *buffer, std::uint32_t capacity)
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