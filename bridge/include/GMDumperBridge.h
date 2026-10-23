/*
  GMDumperBridge - GameMaker game-thread reflection bridge
  Copyright (C) 2026 palepine

  GPL-3.0-or-later. See LICENSE in the project root.
*/
#pragma once

#include <cstdint>

#if defined(GMDUMPER_BRIDGE_EXPORTS)
#define GMD_API extern "C" __declspec(dllexport)
#else
#define GMD_API extern "C" __declspec(dllimport)
#endif

enum class GmdRequestStatus : std::uint32_t
{
  Queued = 1,    ///< Owned by the bridge and waiting for the runner thread.
  Running = 2,   ///< Removed from the queue and currently executing.
  Completed = 3, ///< Result records are stable and may be copied.
  Failed = 4,    ///< Terminal failure; gmd_get_last_error returns the reason.
  Cancelled = 5, ///< Removed before execution by gmd_cancel_request.
};

/// Fixed ABI record copied into a target-side buffer allocated by CE.
///
/// address remains runner-owned. The name itself is copied so Lua never has to dereference a temporary key string after the request is released.
struct GmdMemberRecord
{
  std::uint64_t address;
  std::int32_t kind;
  std::uint32_t reserved;
  char name[256];
};

struct GmdRValue
{
  std::uint64_t value;
  std::uint32_t flags;
  std::int32_t kind;
};

/// Return the bridge implementation version used to reject a stale injected DLL.
GMD_API std::uint32_t gmd_bridge_version();

/// Return the public ABI generation.
GMD_API std::uint32_t gmd_bridge_abi();

/// Install the Code_Execute detour that schedules queued work on the runner thread.
GMD_API std::uint32_t gmd_configure_dispatcher(void *code_execute);

/// Configure YYRunnerInterface slot offsets and discovery validation limits.
///
/// These values reorder/constrain discovery; they do not bypass validation.
GMD_API std::uint32_t gmd_configure_discovery_profile(
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
                                                      );

/// Discover runner-interface functions in the process main module.
GMD_API std::uint32_t gmd_discover_reflection();

/// Discover runner-interface functions in an explicitly supplied module.
GMD_API std::uint32_t gmd_discover_reflection_at(void *module);

/// Use caller-validated reflection functions instead of automatic discovery.
GMD_API std::uint32_t gmd_configure_reflection(void *struct_get_keys, void *struct_get_member);

/// Configure array helpers and infer DynamicArrayOfRValue element storage.
GMD_API std::uint32_t gmd_configure_array_access(void *array_equals, void *array_length);

/// Configure the optional script_execute built-in used for GML calls.
GMD_API std::uint32_t gmd_configure_script_execute(void *script_execute);

/// Return the discovered StructGetKeys address, or zero.
GMD_API std::uint64_t gmd_get_struct_get_keys();

/// Return the discovered StructGetMember address, or zero.
GMD_API std::uint64_t gmd_get_struct_get_member();

/// Return the discovered Script_Find_Id address, or zero.
GMD_API std::uint64_t gmd_get_script_find_id();

/// Return the discovered Script_Perform address, or zero.
GMD_API std::uint64_t gmd_get_script_perform();

/// Return the discovered YYArrayGetLength address, or zero.
GMD_API std::uint64_t gmd_get_array_length();

/// Return the validated array element-storage offset, or -1.
GMD_API std::int64_t gmd_get_array_storage_offset();

/// Return the runner thread selected by the Code_Execute detour.
GMD_API std::uint32_t gmd_get_scheduler_thread_id();

/// Queue reflected-member enumeration for one YYObjectBase pointer.
GMD_API void *gmd_queue_members(void *object, std::uint32_t maximum);

/// Queue element enumeration for one live array RValue.
GMD_API void *gmd_queue_array(GmdRValue *array, std::uint32_t maximum);

/// Queue one user-defined GML function call.
GMD_API void *gmd_queue_script(const char *name, void *self, void *other, const GmdRValue *arguments, std::uint32_t argument_count);

/// Queue one already-resolved runner routine.
GMD_API void *gmd_queue_routine(void *routine, void *self, void *other, const GmdRValue *arguments, std::uint32_t argument_count);

/// Read an opaque request's GmdRequestStatus value.
GMD_API std::uint32_t gmd_get_request_status(void *handle);

/// Return the number of completed member/array records.
GMD_API std::uint32_t gmd_get_member_count(void *handle);

/// Copy completed member/array records to a caller-owned buffer.
GMD_API std::uint32_t gmd_copy_members(void *handle, GmdMemberRecord *destination, std::uint32_t capacity);

/// Copy a completed script-call result to a caller-owned buffer.
GMD_API std::uint32_t gmd_copy_call_result(void *handle, GmdRValue *destination);

/// Cancel a request that has not started running.
GMD_API std::uint32_t gmd_cancel_request(void *handle);

/// Destroy a terminal request and invalidate its handle.
GMD_API std::uint32_t gmd_release_request(void *handle);

/// Remove the dispatcher after all requests and callbacks become idle.
GMD_API std::uint32_t gmd_remove_dispatcher();

/// Copy the last diagnostic and return the required NUL-terminated buffer size.
GMD_API std::uint32_t gmd_get_last_error(char *buffer, std::uint32_t capacity);