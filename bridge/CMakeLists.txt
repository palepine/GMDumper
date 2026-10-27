cmake_minimum_required(VERSION 3.23)

project( GMDumperBridge LANGUAGES C CXX )

include(FetchContent)

option( GMDUMPER_BUILD_DISCOVERY_PROBE "Build the offline runner-interface discovery probe" OFF )

if(MSVC)
  
  # Every static dependency must use the same CRT as the injected DLL
  # A mixed /MD & /MT x86 link pulls incompatible exception-handler support.
  set( CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>" )

endif()

if(NOT WIN32)
  message( FATAL_ERROR "GMDumperBridge supports Windows targets only" )
endif()

set( BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE )
set( ZYDIS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE )
set( ZYDIS_BUILD_TOOLS OFF CACHE BOOL "" FORCE )
set( ZYDIS_BUILD_DOXYGEN OFF CACHE BOOL "" FORCE )

FetchContent_Declare(minhook
  GIT_REPOSITORY https://github.com/TsudaKageyu/minhook.git
  GIT_TAG 8af6b4acae5a9388fd742b56fa79ece89d96f823
  UPDATE_DISCONNECTED TRUE
)

FetchContent_MakeAvailable(minhook)

FetchContent_Declare(zydis
  GIT_REPOSITORY https://github.com/zyantific/zydis.git
  GIT_TAG v4.1.1
  GIT_SHALLOW TRUE
  UPDATE_DISCONNECTED TRUE
)

FetchContent_MakeAvailable(zydis)

add_library(GMDumperZydis ALIAS Zydis)

add_library( GMDumperBridge SHARED src/Bridge.cpp )

target_compile_features( GMDumperBridge PRIVATE cxx_std_20 )

target_include_directories( GMDumperBridge PUBLIC include )

target_link_libraries( GMDumperBridge PRIVATE minhook GMDumperZydis )

target_compile_definitions( GMDumperBridge PRIVATE
                                                  WIN32_LEAN_AND_MEAN
                                                  NOMINMAX
                                                  GMDUMPER_BRIDGE_EXPORTS
                          )

if(MSVC)
  target_compile_options( GMDumperBridge PRIVATE
                                                  /W4
                                                  /permissive-
                                                  /EHsc
                        )

  endif()

if( CMAKE_SIZEOF_VOID_P EQUAL 8 )
  set( GMDUMPER_BRIDGE_ARCH "x64" )

elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)

  set( GMDUMPER_BRIDGE_ARCH "x86" )

else()

  message( FATAL_ERROR "Unsupported pointer size: ${CMAKE_SIZEOF_VOID_P}" )

endif()

set_target_properties(
  GMDumperBridge
  PROPERTIES
    OUTPUT_NAME "GMDumperBridge.${GMDUMPER_BRIDGE_ARCH}"
    PREFIX ""
)

if( GMDUMPER_BUILD_DISCOVERY_PROBE )

  add_executable( GMDumperDiscoveryProbe tools/DiscoveryProbe.cpp)

  target_compile_features( GMDumperDiscoveryProbe PRIVATE cxx_std_20 )

  target_include_directories( GMDumperDiscoveryProbe PRIVATE include )

  target_link_libraries( GMDumperDiscoveryProbe PRIVATE GMDumperBridge )

endif()
