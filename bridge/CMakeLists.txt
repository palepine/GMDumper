cmake_minimum_required(VERSION 3.23)

project( GMDumperBridge LANGUAGES C CXX )

include(FetchContent)

if(NOT WIN32)
  message( FATAL_ERROR "GMDumperBridge supports Windows targets only" )
endif()

set( BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE )
set( ZYDIS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE )
set( ZYDIS_BUILD_TOOLS OFF CACHE BOOL "" FORCE )
set( ZYDIS_BUILD_DOXYGEN OFF CACHE BOOL "" FORCE )

set( LOCAL_MINHOOK "${CMAKE_CURRENT_SOURCE_DIR}/../../PRIVATE_ceUEDumper/bridge/build/_deps/minhook-src" )
set( LOCAL_YYTK_INCLUDE "${CMAKE_CURRENT_SOURCE_DIR}/../../YYToolkit-stable/YYToolkit/include" )

if( EXISTS "${LOCAL_MINHOOK}/CMakeLists.txt" )

  add_subdirectory(
                    "${LOCAL_MINHOOK}"
                    "${CMAKE_CURRENT_BINARY_DIR}/local-minhook"
                  )

else()

  FetchContent_Declare(minhook
    GIT_REPOSITORY https://github.com/TsudaKageyu/minhook.git
    GIT_TAG 8af6b4acae5a9388fd742b56fa79ece89d96f823
    GIT_SHALLOW TRUE
  )

  FetchContent_MakeAvailable(minhook)
endif()

if( EXISTS "${LOCAL_YYTK_INCLUDE}/Zydis/Zydis.c" )
  
  add_library( GMDumperZydis STATIC "${LOCAL_YYTK_INCLUDE}/Zydis/Zydis.c" )
  
  target_include_directories( GMDumperZydis PUBLIC "${LOCAL_YYTK_INCLUDE}" )
else()

  FetchContent_Declare(zydis
    GIT_REPOSITORY https://github.com/zyantific/zydis.git
    GIT_TAG v4.1.1
    GIT_SHALLOW TRUE
  )

  FetchContent_MakeAvailable(zydis)

  add_library(GMDumperZydis ALIAS Zydis)

endif()

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

  set_property( TARGET GMDumperBridge PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>" )

  endif()

set_target_properties( GMDumperBridge PROPERTIES OUTPUT_NAME "GMDumperBridge" PREFIX "" )
