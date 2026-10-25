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

  if (!configured || !gmd_discover_reflection_at( module ))
  {
    print_last_error();
    FreeLibrary( module );
    return 4;
  }

  const auto base = reinterpret_cast< std::uintptr_t >( module );

  const auto keys = static_cast< std::uintptr_t >( gmd_get_struct_get_keys() );

  const auto member = static_cast< std::uintptr_t >( gmd_get_struct_get_member() );

  std::printf(
               "pointerSize=%u module=%llX StructGetKeys=%llX (rva=%llX) StructGetMember=%llX (rva=%llX) fallbackHelpers=%s\n",
               pointer_size,
               static_cast< unsigned long long >( base ),
               static_cast< unsigned long long >( keys ),
               static_cast< unsigned long long >( keys ? keys - base : 0 ),
               static_cast< unsigned long long >( member ),
               static_cast< unsigned long long >( member ? member - base : 0 ),
               gmd_configure_member_fallback( reinterpret_cast<void*>(1), reinterpret_cast<void*>(1) ) ? "yes" : "no"
             );

  FreeLibrary(module);
  return 0;
}