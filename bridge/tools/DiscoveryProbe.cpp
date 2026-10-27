/*
  Offline diagnostic for YYRunnerInterface discovery.

  This maps a same-architecture runner image without resolving its imports and
  runs the bridge's structural scanner against that image. It never executes
  runner code, so it is suitable for validating a new discovery profile before
  attempting injection. Live reflection still requires an attached game.
*/

#include "GMDumperBridge.h"

#include <Windows.h>

#include <array>
#include <cstring>
#include <cstdint>
#include <cstdio>
#include <vector>

namespace
{
  void print_last_error()
  {
    const auto required = gmd_get_last_error( nullptr, 0 );

    std::vector< char > buffer( required ? required : 1 );

    gmd_get_last_error( buffer.data(), static_cast< std::uint32_t >( buffer.size() ) );

    std::fprintf( stderr, "%s\n", buffer.data() );
  }

  void* registered_routine(HMODULE module, const char* wanted_name)
  {
#if defined(_WIN64)

    (void)module;
    (void)wanted_name;
    return nullptr;

#else
    const auto* base = reinterpret_cast< const std::uint8_t* >( module );

    const auto* dos = reinterpret_cast< const IMAGE_DOS_HEADER* >( base );

    const auto* nt = reinterpret_cast< const IMAGE_NT_HEADERS32* >( base + dos->e_lfanew );

    const auto image_size = nt->OptionalHeader.SizeOfImage;

    const auto preferred_base = static_cast< std::uintptr_t >( nt->OptionalHeader.ImageBase );

    const auto mapped_base = reinterpret_cast< std::uintptr_t >( module );

    const auto name_size = std::strlen(wanted_name) + 1;

    const std::uint8_t* name{};

    for (std::size_t offset = 0; offset + name_size <= image_size; ++offset)
    {
      if ( std::memcmp( base + offset, wanted_name, name_size ) == 0 )
      {
        name = base + offset;
        break;
      }
    }

    if (!name)
    {
      return nullptr;
    }

    const auto name_rva = reinterpret_cast< std::uintptr_t >( name ) - mapped_base;

    const auto preferred_name = preferred_base + name_rva;

    const auto section = IMAGE_FIRST_SECTION(nt);

    for (std::uint16_t index = 0; index < nt->FileHeader.NumberOfSections; ++index)
    {
      if ( std::memcmp( section[index].Name, ".text", 5 ) != 0 )
      {
        continue;
      }

      const auto* text = base + section[index].VirtualAddress;

      const auto text_size = static_cast< std::size_t >( section[index].Misc.VirtualSize );

      for (std::size_t offset = 0; offset + 19 <= text_size; ++offset)
      {
        if (
             text[offset + 0] != 0x6A ||
             text[offset + 2] != 0x6A ||
             text[offset + 4] != 0x68 ||
             text[offset + 9] != 0x68 ||
             text[offset + 14] != 0xE8
           )
        {
          continue;
        }

        std::uint32_t routine_address{};
        std::uint32_t name_address{};

        std::memcpy( &routine_address, text + offset + 5, sizeof( routine_address ) );
        std::memcpy( &name_address, text + offset + 10, sizeof( name_address ) );

        if ( name_address != preferred_name && name_address != reinterpret_cast<std::uintptr_t>(name) )
        {
          continue;
        }
        if ( routine_address < preferred_base || routine_address >= preferred_base + image_size )
        {
          continue;
        }

        return reinterpret_cast< void* >( mapped_base + routine_address - preferred_base );
      }
    }

    return nullptr;
#endif
  }
}

int wmain(int argument_count, wchar_t **arguments)
{
  if ( argument_count != 2 )
  {
    std::fprintf( stderr, "usage: GMDumperDiscoveryProbe <runner.exe>\n" );
    return 2;
  }

  const auto module = LoadLibraryExW( arguments[1], nullptr, DONT_RESOLVE_DLL_REFERENCES );

  if ( !module )
  {
    std::fprintf( stderr, "LoadLibraryExW failed: %lu\n", GetLastError() );
    return 3;
  }

  constexpr auto pointer_size = static_cast< std::uint32_t >( sizeof(void*) );

  const auto configured = gmd_configure_discovery_profile(
                                                            16 * pointer_size,
                                                            27 * pointer_size,
                                                            30 * pointer_size,
                                                            31 * pointer_size,
                                                            79 * pointer_size,
                                                            91 * pointer_size,
                                                            92 * pointer_size,
                                                            98 * pointer_size,
                                                            pointer_size == 4 ? 60 : 88,
                                                            160,
                                                            0x380,
                                                            0x1400,
                                                            0x800,
                                                            0
                                                          );

  if (!configured)
  {
    print_last_error();
    FreeLibrary( module );
    return 4;
  }

  const auto direct = gmd_discover_reflection_at(module) != 0;
  auto fallback = false;

  if ( !direct && pointer_size == 4 )
  {
    auto get_names = registered_routine( module, "variable_instance_get_names" );
    auto names_count = registered_routine( module, "variable_instance_names_count" );

    if (!get_names)
    {
      get_names = registered_routine( module, "variable_struct_get_names" );
    }

    if (!names_count)
    {
      names_count = registered_routine( module, "variable_struct_names_count" );
    }

    fallback = get_names && gmd_configure_member_fallback( get_names, names_count ) != 0;
  }

  if (!direct && !fallback)
  {
    print_last_error();
    FreeLibrary( module );
    return 4;
  }

  const auto base = reinterpret_cast< std::uintptr_t >( module );

  const auto keys = static_cast< std::uintptr_t >( gmd_get_struct_get_keys() );

  const auto member = static_cast< std::uintptr_t >( gmd_get_struct_get_member() );

  std::printf(
               "pointerSize=%u module=%llX StructGetKeys=%llX (rva=%llX) StructGetMember=%llX (rva=%llX) mode=%s\n",
               pointer_size,
               static_cast< unsigned long long >( base ),
               static_cast< unsigned long long >( keys ),
               static_cast< unsigned long long >( keys ? keys - base : 0 ),
               static_cast< unsigned long long >( member ),
               static_cast< unsigned long long >( member ? member - base : 0 ),
               direct ? "direct" : "builtin-dictionary-fallback"
             );

  FreeLibrary(module);
  return 0;
}