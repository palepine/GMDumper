--[[
  GMDumper native game-thread bridge client
  Copyright (C) 2026 palepine

  GPL-3.0-or-later. See LICENSE in the project root.


  - load the DLL into the process
  - configure version-profile discovery and the Code_Execute dispatcher
  - queue work
  - wait for copied results and release every terminal native request
]]

-- ///---///--///---///--///---///--///--///---///--///---///--///---///--///--///--///--///--///--///--///--///--///--///--/// BRIDGE STATE

local Bridge =
{
  ABI = 1,
  VERSION = 0x00010000,
  BINARIES =
  {
    [4] =
    {
      attachment = 'GMDumper.GMDumperBridge.x86.dll',
      file = 'GMDumperBridge.x86.dll',
      architecture = 'x86'
    },
    [8] =
    {
      attachment = 'GMDumper.GMDumperBridge.x64.dll',
      file = 'GMDumperBridge.x64.dll',
      architecture = 'x64'
    }
  },
  MEMBER_SIZE = 272,
  Status =
  {
    queued = 1,
    running = 2,
    completed = 3,
    failed = 4,
    cancelled = 5
  },
  State =
  {
    processId = 0,
    exports = nil,
    path = nil,
    configured = false,
    profileId = nil,
    extractedPath = nil,
    extractionSerial = 0
  }
}

local CE_DIRECTORY = getCheatEngineDir() or ''
local MODULE_DIRECTORY = CE_DIRECTORY .. [[autorun\GMDumperModules\]]

local EXPORTS =
{
  'gmd_bridge_version',
  'gmd_bridge_abi',
  'gmd_bridge_pointer_size',
  'gmd_configure_dispatcher',
  'gmd_configure_discovery_profile',
  'gmd_discover_reflection',
  'gmd_configure_reflection',
  'gmd_configure_cached_interface',
  'gmd_configure_member_fallback',
  'gmd_configure_array_access',
  'gmd_configure_script_execute',
  'gmd_get_struct_get_keys',
  'gmd_get_struct_get_member',
  'gmd_get_yy_get_string',
  'gmd_get_free_rvalue',
  'gmd_get_struct_add_rvalue',
  'gmd_get_script_find_id',
  'gmd_get_script_perform',
  'gmd_get_array_length',
  'gmd_get_array_storage_offset',
  'gmd_get_scheduler_thread_id',
  'gmd_queue_members',
  'gmd_queue_array',
  'gmd_queue_script',
  'gmd_queue_routine',
  'gmd_get_request_status',
  'gmd_get_member_count',
  'gmd_copy_members',
  'gmd_copy_call_result',
  'gmd_cancel_request',
  'gmd_release_request',
  'gmd_remove_dispatcher',
  'gmd_get_last_error'
}

--- Interpret uint32 as int32
-- @param value number|nil
-- @return number|nil
local function signedInteger(value) -- TODO: replace with CE APIs

  if value == nil then return nil end

  value = value & 0xFFFFFFFF

  if value >= 0x80000000 then return value - 0x100000000 end

  return value
end

-- ///---///--///---///--///---///--///--///---///--///---///--///---///--///--///--///--///--///--///--///--///--///--///--/// LOADING & CONFIGURATION

--- Invoke bridge export via executeCodeEx
-- queue exports only copy/queue data
-- @param address number
-- @param ... any
local function call(address, ...)
  local arguments = { ... }

  for index, value in ipairs(arguments) do
    arguments[index] =
    {
      type = 0,
      value = value or 0
    }
  end

  -- Bridge exports use the C ABI: cdecl on x86, the unified Windows ABI on x64.
  local callMethod = Bridge.State.callMethod or 0

  local ok, result = pcall( executeCodeEx, callMethod, 10000, address, table.unpack(arguments) )

  if not ok then return nil, tostring(result) end

  return result
end

--- Read bridge PE export
-- @param module table @ enumModules() entry
-- @return table|nil @ export name -> target address
-- @return string|nil
local function readModuleExports(module)
  
  local base = module and module.Address

  if not base then return nil, 'Bridge module has no base address' end
  if readSmallInteger(base) ~= 0x5A4D then return nil, 'Bridge module has no DOS header' end

  local peOffset = readInteger( base + 0x3C )
  if not peOffset or peOffset < 0x40 or peOffset > 0x100000 then return nil, 'Bridge module has invalid PE offset' end

  local nt = base + peOffset
  if readInteger(nt) ~= 0x00004550 then return nil, 'Bridge module has no PE header' end

  local optional = nt + 0x18
  local magic = readSmallInteger( optional )
  local dataDirectoryOffset

  if magic == 0x10B then
    dataDirectoryOffset = 0x60
  elseif magic == 0x20B then
    dataDirectoryOffset = 0x70
  else
    return nil, ('Bridge module has unsupported optional-header magic: 0x%X'):format( magic or 0 )
  end

  local exportRva = readInteger( optional + dataDirectoryOffset )
  local exportSize = readInteger( optional + dataDirectoryOffset + 4 )

  if not exportRva or exportRva == 0 or not exportSize or exportSize == 0 then return nil, 'Bridge module has no export directory' end

  local directory = base + exportRva
  local functionCount = readInteger( directory + 0x14 )
  local nameCount = readInteger( directory + 0x18 )
  local functionsRva = readInteger( directory + 0x1C )
  local namesRva = readInteger( directory + 0x20 )
  local ordinalsRva = readInteger( directory + 0x24 )

  if not functionCount or functionCount <= 0
     or not nameCount or nameCount <= 0
     or not functionsRva or functionsRva == 0
     or not namesRva or namesRva == 0
     or not ordinalsRva or ordinalsRva == 0 then
    return nil, 'Bridge export directory is incomplete'
  end

  -- The bridge has only a few dozen exports.  A defensive bound prevents a
  -- malformed directory from turning initialization into a long memory walk.
  if nameCount > 4096 or functionCount > 4096 then return nil, 'Bridge export directory is implausibly large' end

  local result = {}

  for index = 0, nameCount - 1 do
    local nameRva = readInteger( base + namesRva + index * 4 )
    local ordinal = readSmallInteger( base + ordinalsRva + index * 2 )

    if nameRva and nameRva ~= 0 and ordinal and ordinal < functionCount then
      local name = readString( base + nameRva, 256, false )
      local functionRva = readInteger( base + functionsRva + ordinal * 4 )

      if name and name ~= '' and functionRva and functionRva ~= 0 then
        
        -- forwarded exports point back into the export directory.
        if functionRva < exportRva or functionRva >= exportRva + exportSize then
          result[name] = base + functionRva
        end

      end

    end

  end

  return result
end

--- Resolve every required bridge export from one exact module image
-- @param module table
local function resolveExports(module)
  local available, exportError = readModuleExports(module)
  if not available then return nil, exportError end

  local result = {}

  for _, name in ipairs(EXPORTS) do
    result[name] = available[name]

    if not result[name] then return nil, 'Bridge export wasnt resolved: ' .. name end
  end

  return result
end

--- Find loaded bridge module for the target arch
-- @param pointerSize number
local function loadedBridgeModule(pointerSize)
  
  local binary = Bridge.BINARIES[ pointerSize ]

  local architecturePrefix = ('GMDumperBridge_%s_'):format(binary.architecture):lower()

  local installedName = binary.file:lower()

  for _, module in ipairs(enumModules() or {}) do

    -- PathToFile may be unavailable under restricted module enumeration even though CE still supplies the module's Name
    -- Either field is sufficient
    local reportedName = type(module.PathToFile) == 'string' and module.PathToFile ~= '' and module.PathToFile or module.Name
    local fileName = extractFileName( reportedName or '' )
    local lowered = tostring(fileName or ''):lower()

    if lowered == installedName or lowered:sub(1, #architecturePrefix) == architecturePrefix then
      return module
    end

  end

end

--- Locate loaded bridge directly through committed image mappings
-- @param pointerSize number
-- @return table|nil @ synthetic module descriptor
-- @return table|nil @ resolved bridge exports
local function mappedBridgeModule(pointerSize)
  local candidates = {}
  local seen = {}

  for _, region in ipairs(enumMemoryRegions() or {}) do
    local base = tonumber(region.AllocationBase) or tonumber(region.BaseAddress)
    local committed = region.State == nil or region.State == 0x1000
    
    -- standard LoadLibrary images are MEM_IMAGE.
    -- CE can also be configured to use a manual/stealth mapper, whose allocations are MEM_PRIVATE and are intentionally absent from the PEB module list.
    local image = region.Type == nil or region.Type == 0x1000000 or region.Type == 0x20000

    if base and base ~= 0 and committed and image and not seen[base] then
      seen[base] = true
      candidates[ #candidates + 1 ] =
      {
        Address = base,
        PathToFile = type(region.Extra) == 'string' and region.Extra or '',
      }
    end

  end

  for _, module in ipairs(candidates) do

    if readSmallInteger(module.Address) == 0x5A4D then

      local peOffset = readInteger( module.Address + 0x3C )

      local magic = peOffset and readSmallInteger( module.Address + peOffset + 0x18 ) or nil

      local architectureMatches = pointerSize == 8 and magic == 0x20B or pointerSize == 4 and magic == 0x10B

      if architectureMatches then
        local exports = resolveExports(module)
        if exports then
          return module, exports
        end

      end

    end

  end

end

--- Ask CE to observe modules loaded since its last symbol snapshot
-- loadNewSymbols is the narrow operation intended for this case.  Waiting for
-- exports makes the subsequent lookup deterministic on CE builds which update
-- symbols asynchronously.  Calls are synchronized because these APIs own CE's
-- process-wide symbol handler.
local function refreshLoadedModules()

  local function refresh()
    loadNewSymbols() -- CE 7.7+: update only newly loaded modules
    --reinitializeSymbolhandler( true )
    waitForExports()
  end

  if inMainThread() then
    refresh()
  else
    synchronize(refresh) -- probably threadsafe but still
  end

end

--- Load the bridge via target's LoadLibraryW, get HMODULE / result
-- @param path string
-- @param pointerSize number
-- @return table|nil @ synthetic module descriptor
-- @return table|nil @ resolved bridge exports
-- @return string|nil
-- @return boolean @ true when LoadLibraryW returned an HMODULE
local function loadBridgeDirectly(path, pointerSize)

  local loadLibrary = getAddressSafe( 'kernel32.LoadLibraryW' )

  if not loadLibrary then
    refreshLoadedModules()
    loadLibrary = getAddressSafe( 'kernel32.LoadLibraryW' )
  end

  if not loadLibrary then return nil, nil, 'kernel32.LoadLibraryW wasnt resolved', false end

  -- VirtualAllocEx-backed CE allocations are zero initialized.
  -- so no need to null-terminate?
  local pathBuffer = allocateMemory( (#path + 1) * 2 )
  if not pathBuffer then return nil, nil, 'Couldnt allocate the remote bridge path', false end

  local wrote = writeString( pathBuffer, path, true )
  local called, moduleBase

  if wrote then
    called, moduleBase = pcall( executeCodeEx, 0, 10000, loadLibrary, { type = 0, value = pathBuffer } )
  end

  deAlloc( pathBuffer )

  if not wrote then return nil, nil, 'Couldnt write the remote bridge path', false end

  if not called then return nil, nil, 'LoadLibraryW execution failed: ' .. tostring(moduleBase), false end

  if type(moduleBase) ~= 'number' or moduleBase == 0 then return nil, nil, 'Target LoadLibraryW rejected the bridge DLL', false end

  local module =
  {
    Address = moduleBase,
    PathToFile = path,
  }

  local exports, exportError = resolveExports(module)
  
  if not exports then
    return module, nil, exportError, true
  end

  return module, exports, nil, true
end

--- Resolve injected bridge after CE has refreshed its module snapshot
-- @param pointerSize number
-- @return table|nil @ module descriptor
-- @return table|nil @ resolved bridge exports
-- @return string|nil
local function resolveInjectedBridge(pointerSize)

  local module = loadedBridgeModule( pointerSize )
  local exports, exportError

  if module then
    exports, exportError = resolveExports( module )
    
    if exports then
      return module, exports
    end

  end

  refreshLoadedModules()

  for _ = 1, 4 do -- TODO: remove
    module = loadedBridgeModule(pointerSize)

    if module then
      exports, exportError = resolveExports(module)

      if exports then
        return module, exports
      end
    end

    sleep(25)
  end

  module, exports = mappedBridgeModule(pointerSize)

  if exports then
    return module, exports
  end

  return nil, nil, exportError or 'Injected bridge wasnt visible through CE module or memory-map enumeration'
end

--- local bridge path readable?
-- @param path string
local function readable(path)
  local file = io.open(path, 'rb')
  if not file then return false end

  file:close()
  return true
end

--- Remove extracted bridge after injection / target replacement
-- @param path string|nil
-- @return boolean @ true when no temporary file remains
local function discardTemporaryBridge(path)
  if not path then return true end

  local removed = os.remove(path)

  if removed or not readable(path) then
    if Bridge.State.extractedPath == path then Bridge.State.extractedPath = nil end
    return true
  end

  return false
end

--- Extract table-attached DLL to a temp path
-- @param processId number
-- @return string|nil @ extracted path; nil when no attachment exists
-- @return string|nil @ validation or filesystem error
local function extractAttachedBridge(processId, pointerSize)
  
  local function extract()

    local binary = Bridge.BINARIES[pointerSize]
    if not binary then return nil, 'Unsupported target pointer size: ' .. tostring(pointerSize) end

    local tableFile = findTableFile( binary.attachment )
    if not tableFile then return nil end

    local stream = tableFile.getData()
    if not stream then return nil, 'Attached bridge couldnt be read' end

    stream.Position = 0

    local firstByte = stream.readByte()
    local secondByte = stream.readByte()

    if firstByte ~= 0x4D or secondByte ~= 0x5A then
      stream.destroy()
      return nil, 'Attached bridge isnt a PE image'
    end

    local temporaryDirectory = os.getenv('TEMP') or os.getenv('TMP')

    if not temporaryDirectory or temporaryDirectory == '' then
      stream.destroy()
      return nil, 'Win TEMP dir is unavailable'
    end

    Bridge.State.extractionSerial = (Bridge.State.extractionSerial or 0) + 1

    local separator = temporaryDirectory:sub(-1) == '\\' and '' or '\\'
    local temporaryPath = temporaryDirectory
                          .. separator
                          .. ('GMDumperBridge_%s_abi%d_%d_%d_%d.dll'):format( binary.architecture, Bridge.ABI, processId, os.time(), Bridge.State.extractionSerial )

    stream.Position = 0

    local saved, saveError = stream.saveToFileNoError( temporaryPath )

    stream.destroy()

    if not saved then return nil, 'Couldnt extract temporary bridge DLL: ' .. tostring(saveError) end

    return temporaryPath
  end

  if inMainThread() then return extract() end
  return synchronize(extract)
end

--- Load/reconnect the bridge into the process
-- @param path string
-- @param pointerSize number
function Bridge.load(path, pointerSize)
  local processId = getOpenedProcessID()
  if not processId or processId == 0 then return nil, 'No target is attached' end

  pointerSize = tonumber(pointerSize)
  if pointerSize ~= 4 and pointerSize ~= 8 then return nil, 'Target pointer size must be 4 or 8' end

  local binary = Bridge.BINARIES[pointerSize]

  -- discard after process changes
  if Bridge.State.processId ~= processId then
    discardTemporaryBridge( Bridge.State.extractedPath )

    local extractionSerial = Bridge.State.extractionSerial or 0

    Bridge.State =
    {
      processId = processId,
      exports = nil,
      path = nil,
      configured = false,
      profileId = nil,
      pointerSize = pointerSize,
      callMethod = pointerSize == 4 and 1 or 0,
      extractedPath = nil,
      extractionSerial = extractionSerial
    }
  end

  if Bridge.State.exports then
    if Bridge.State.pointerSize ~= pointerSize then return nil, 'Loaded bridge architecture doesnt match the target' end
    return true
  end


  Bridge.State.callMethod = pointerSize == 4 and 1 or 0

  -- reconnect first
  local loadedModule = loadedBridgeModule( pointerSize )
  local exports, exportError

  if loadedModule then
    exports, exportError = resolveExports( loadedModule )
  end

  local temporaryPath

  if not path and not exports then
    local attachmentError

    path, attachmentError = extractAttachedBridge(processId, pointerSize)
    if attachmentError then return nil, attachmentError end

    if path then
      temporaryPath = path
      Bridge.State.extractedPath = path
    end
  end

  path = path or (MODULE_DIRECTORY .. binary.file)

  if not exports then

    if not readable(path) then
      discardTemporaryBridge(temporaryPath)
      return nil, 'Bridge DLL unavailable: no attached DLL and no readable file at ' .. tostring(path)
    end

    local loadedDirectly

    loadedModule, exports, exportError, loadedDirectly = loadBridgeDirectly( path, pointerSize )

    if loadedDirectly and not exports then

      discardTemporaryBridge( temporaryPath )

      return nil, 'Bridge loaded at ' .. ('0x%X'):format( loadedModule.Address ) .. ', but exports werent resolved: ' .. tostring(exportError or 'unknown error')
    end

    if not loadedDirectly then
      local directError = exportError
      local injected = injectDLL(path)

      if injected ~= true then
        discardTemporaryBridge( temporaryPath )

        return nil, 'Couldnt load the bridge: ' .. tostring(directError) .. '; injectDLL: ' .. tostring(injected)
      end

      loadedModule, exports, exportError = resolveInjectedBridge( pointerSize )

      if not exports and directError then
        exportError = tostring(exportError) .. '; direct LoadLibraryW: ' .. tostring(directError)
      end

    end

  end

  if not exports then
    discardTemporaryBridge( temporaryPath )
    return nil, 'Bridge injected, but exports werent resolved: ' .. tostring(exportError or 'unknown error')
  end
  
  -- check abi version
  local abi = call( exports.gmd_bridge_abi )

  if abi ~= Bridge.ABI then
    discardTemporaryBridge( temporaryPath )
    return nil, ('Bridge ABI mismatch: Lua expects %d, DLL provides %s'):format( Bridge.ABI, tostring(abi) )
  end

  local bridgePointerSize = call( exports.gmd_bridge_pointer_size )

  if bridgePointerSize ~= pointerSize then
    discardTemporaryBridge(temporaryPath)
    return nil, ('Bridge architecture mismatch: target uses %d-byte pointers, DLL uses %s'):format( pointerSize, tostring(bridgePointerSize) )
  end

  local version = call( exports.gmd_bridge_version )
  
  if not version or version < Bridge.VERSION then
    discardTemporaryBridge(temporaryPath)
    return nil, ('Bridge is stale (need 0x%08X, loaded 0x%08X); restart to unload'):format( Bridge.VERSION, tonumber(version) or 0 )
  end

  Bridge.State.exports, Bridge.State.path, Bridge.State.pointerSize = exports, path, pointerSize

  -- the loaded module no longer needs its source file
  discardTemporaryBridge(temporaryPath)
  return true
end

--- Invoke export by name
-- @param name string
-- @param ... any
function Bridge.call(name, ...)
  local exports = Bridge.State.exports
  if not exports or not exports[name] then return nil, 'Bridge not loaded' end

  return call( exports[name], ... )
end

--- Get last error
function Bridge.lastError()
  if not Bridge.State.exports then return 'Bridge not loaded' end

  local buffer = allocateMemory(1024)
  if not buffer or buffer == 0 then return 'Bridge op failed: couldnt allocate error buffer' end

  Bridge.call( 'gmd_get_last_error', buffer, 1024 )

  local result = readString( buffer, 1024, false )

  deAlloc(buffer)

  return result and result ~= '' and result or 'Bridge op failed'
end

--- Configure reflection and dispatcher
-- @param codeExecute any
-- @param reflection table
-- @param arrayEquals any
-- @param arrayLength any
-- @param scriptExecute any
-- @param profile table
-- @param pointerSize number
-- @param memberGetNames any
-- @param memberNamesCount any
function Bridge.configure(codeExecute, reflection, arrayEquals, arrayLength, scriptExecute, profile, pointerSize, memberGetNames, memberNamesCount)
  
  local loaded, loadError = Bridge.load( nil, pointerSize )
  if not loaded then return nil, loadError end

  profile = profile or
  {
    id = 'yy-runner-interface-v1',
    automatic = true,
    slotUnit = 'pointer',
    slots =
    {
      yyGetString = 16,
      freeRValue = 27,
      scriptFindId = 30,
      scriptPerform = 31,
      structAddRValue = 79,
      structGetMember = 91,
      structGetKeys = 92,
      arrayGetLength = 98
    },

    discovery =
    {
      minimumAssignments = 88,
      maximumAssignments = 160,
      maximumSpan = 0x380,
      maximumInstructionSpan = 0x1400,
      maximumFunctionDistance = 0x800,
      maximumBaseSlack = 0
    },
  }
  local slots, discovery = profile.slots or {}, profile.discovery or {}

  --- Convert a profile slot to arch-specific byte offset
  -- @param value number
  local function slotOffset(value)
    if type(value) ~= 'number' then return nil end
    return profile.slotUnit == 'pointer' and value * pointerSize or value
  end

  -- send slot offsets & bounds before interpreting
  if Bridge.call(
                  'gmd_configure_discovery_profile',
                   slotOffset( slots.yyGetString ),
                   slotOffset( slots.freeRValue ),
                   slotOffset( slots.scriptFindId ),
                   slotOffset( slots.scriptPerform ),
                   slotOffset( slots.structAddRValue ),
                   slotOffset( slots.structGetMember ),
                   slotOffset( slots.structGetKeys ),
                   slotOffset( slots.arrayGetLength ),
                   discovery.minimumAssignments,
                   discovery.maximumAssignments,
                   discovery.maximumSpan,
                   discovery.maximumInstructionSpan,
                   discovery.maximumFunctionDistance,
                   discovery.maximumBaseSlack
                ) ~= 1
  then
    return nil, Bridge.lastError()
  end

  -- explicit addresses win. Otherwise the profile decides if structural scan is supported for this runner
  if reflection
     and reflection.yyGetString
     and reflection.freeRValue
     and reflection.scriptFindId
     and reflection.scriptPerform
     and reflection.structAddRValue
     and reflection.structGetMember
     and reflection.structGetKeys
     and reflection.arrayLength
  then

    if Bridge.call(
                    'gmd_configure_cached_interface',
                    reflection.yyGetString,
                    reflection.freeRValue,
                    reflection.scriptFindId,
                    reflection.scriptPerform,
                    reflection.structAddRValue,
                    reflection.structGetMember,
                    reflection.structGetKeys,
                    reflection.arrayLength
                  ) ~= 1
    then
      return nil, Bridge.lastError()
    end

  elseif reflection and reflection.structGetKeys and reflection.structGetMember then

    if Bridge.call( 'gmd_configure_reflection', reflection.structGetKeys, reflection.structGetMember ) ~= 1 then return nil, Bridge.lastError() end

  elseif profile.automatic == false then
    return nil, ('Bridge profile %s doesnt support autoscan for this arch; configure StructGetKeys/StructGetMember manually'):format( tostring(profile.id or 'unknown') )
  
  elseif Bridge.call( 'gmd_discover_reflection' ) ~= 1 then
    return nil, Bridge.lastError()
  end

  local directKeys = Bridge.call( 'gmd_get_struct_get_keys' )
  local directMember = Bridge.call( 'gmd_get_struct_get_member' )
  local directAvailable = directKeys and directKeys ~= 0 and directMember and directMember ~= 0

  Bridge.State.memberFallbackConfigured = false
  Bridge.State.memberFallbackError = nil

  -- configure the built-in path even when direct interface entries were discovered.
  -- old runner interfaces can have executable functions at the newer StructGetMember/StructGetKeys slot numbers
  -- runtime invocation reveals that they are not reflection functions.
  -- The bridge falls back on the game thread when that probe returns zero / fails validation.
  if memberGetNames and memberNamesCount then

    if Bridge.call( 'gmd_configure_member_fallback', memberGetNames, memberNamesCount ) == 1 then
      Bridge.State.memberFallbackConfigured = true
    else
      Bridge.State.memberFallbackError = Bridge.lastError()
    end

  end

  if not directAvailable and not Bridge.State.memberFallbackConfigured then
    return nil, Bridge.State.memberFallbackError or 'Runner lacks direct reflection & member-name built-ins'
  end

  -- install dispatcher after reflection is available
  if Bridge.call( 'gmd_configure_dispatcher', codeExecute ) ~= 1 then return nil, Bridge.lastError() end

  Bridge.State.configured = true
  Bridge.State.profileId = profile.id
  Bridge.State.structGetKeys = Bridge.call( 'gmd_get_struct_get_keys' )
  Bridge.State.structGetMember = Bridge.call( 'gmd_get_struct_get_member' )

  -- array/script helpers are optional
  if arrayEquals and Bridge.call( 'gmd_configure_array_access', arrayEquals, arrayLength ) ~= 1 then
    Bridge.State.arrayError = Bridge.lastError()
  end

  Bridge.State.arrayLengthRoutine = arrayLength

  if scriptExecute and Bridge.call( 'gmd_configure_script_execute', scriptExecute ) ~= 1 then
    Bridge.State.scriptError = Bridge.lastError()
  end

  return Bridge.status()
end

--- Get recovered bridge capabilities and runner addresses
function Bridge.status()
  local arrayStorageOffset = Bridge.State.exports and Bridge.call( 'gmd_get_array_storage_offset' ) or nil
  local structGetKeys = Bridge.State.exports and Bridge.call( 'gmd_get_struct_get_keys' ) or nil
  local structGetMember = Bridge.State.exports and Bridge.call( 'gmd_get_struct_get_member' ) or nil

  return
  {
    loaded = Bridge.State.exports ~= nil,
    configured = Bridge.State.configured,
    pointerSize = Bridge.State.pointerSize,
    profileId = Bridge.State.profileId,
    path = Bridge.State.path,
    reflectionMode = Bridge.State.configured
                     and structGetKeys
                     and structGetKeys ~= 0
                     and structGetMember
                     and structGetMember ~= 0
                     and (Bridge.State.memberFallbackConfigured and 'direct+builtin-fallback' or 'direct')
                     or Bridge.State.configured
                     and Bridge.State.memberFallbackConfigured
                     and 'builtin-slot'
                     or nil,
    memberFallbackConfigured = Bridge.State.memberFallbackConfigured == true,
    memberFallbackError = Bridge.State.memberFallbackError,
    structGetKeys = structGetKeys,
    structGetMember = structGetMember,
    yyGetString = Bridge.State.exports and Bridge.call( 'gmd_get_yy_get_string' ) or nil,
    freeRValue = Bridge.State.exports and Bridge.call( 'gmd_get_free_rvalue' ) or nil,
    structAddRValue = Bridge.State.exports and Bridge.call( 'gmd_get_struct_add_rvalue' ) or nil,
    scriptFindId = Bridge.State.exports and Bridge.call( 'gmd_get_script_find_id' ) or nil,
    scriptPerform = Bridge.State.exports and Bridge.call( 'gmd_get_script_perform' ) or nil,
    arrayLength = Bridge.State.exports and Bridge.call( 'gmd_get_array_length' ) or nil,
    arrayLengthRoutine = Bridge.State.arrayLengthRoutine,
    arrayStorageOffset = arrayStorageOffset,
    arrayError = type(arrayStorageOffset) == 'number' and arrayStorageOffset >= 0 and arrayStorageOffset <= 0x100 and nil or Bridge.State.arrayError,
    scriptError = Bridge.State.scriptError,
    schedulerThreadId = Bridge.State.exports and Bridge.call( 'gmd_get_scheduler_thread_id' ) or nil
  }
end

-- ///---///--///---///--///---///--///--///---///--///---///--///---///--///--///--///--///--///--///--///--///--///--///--/// GAME-THREAD REQUESTS

--- Wait for an opaque native request to become terminal
-- running request cannot be released safely on timeout (thread may still write its result)
-- Queued requests are cancelled and all other terminal requests are released before returning an error
-- @param handle number
-- @param timeout number|nil
-- @param timeoutMessage string
local function waitForRequest(handle, timeout, timeoutMessage)
  local deadline = getTickCount() + (timeout or 5000)
  local status

  repeat

    status = Bridge.call( 'gmd_get_request_status', handle )
    if status == Bridge.Status.completed or status == Bridge.Status.failed or status == Bridge.Status.cancelled then break end

    sleep(5)
  until ( getTickCount() >= deadline )

  if status == Bridge.Status.completed then return true end

  if status == Bridge.Status.queued then
    Bridge.call( 'gmd_cancel_request', handle )
    status = Bridge.Status.cancelled
  end

  local message = status == Bridge.Status.failed and Bridge.lastError() or timeoutMessage

  if status ~= Bridge.Status.running then
    Bridge.call('gmd_release_request', handle)
  end

  return nil, message
end

--- Copy fixed-size member records out of a completed request
-- @param handle number
-- @param includeIndex boolean
local function copyMemberRecords(handle, includeIndex)
  
  local count = Bridge.call( 'gmd_get_member_count', handle ) or 0
  
  local buffer = count > 0 and allocateMemory( count * Bridge.MEMBER_SIZE ) or nil

  if count > 0 and (not buffer or buffer == 0) then return nil, 'couldnt allocate bridge output buffer' end

  local copied = count == 0 and 0 or Bridge.call( 'gmd_copy_members', handle, buffer, count )

  if copied ~= count then
    
    if buffer then
      deAlloc(buffer)
    end

    return nil, Bridge.lastError()
  end

  local records = {}

  for index = 0, count - 1 do

    local entry = buffer + index * Bridge.MEMBER_SIZE

    local record =
    {
      address = readQword( entry ),
      kind = signedInteger( readInteger(entry + 8) ),
      slot = signedInteger( readInteger(entry + 12) ),
    }

    if includeIndex then
      record.index = index
    else
      record.name = readString( entry + 16, 256, false )
    end

    records[ #records + 1 ] = record
  end

  if buffer then
    deAlloc(buffer)
  end

  return records
end

--- Enumerate array
-- @param arrayAddress number
-- @param maximum number
-- @param timeout number
function Bridge.enumerateArray(arrayAddress, maximum, timeout)
  if not Bridge.State.configured then return nil, 'Bridge not configured' end

  local handle = Bridge.call( 'gmd_queue_array', arrayAddress, maximum or 0x4000 )
  if not handle or handle == 0 then return nil, Bridge.lastError() end

  local completed, requestError = waitForRequest( handle, timeout, 'Waiting timeout for thread array reflection' )
  if not completed then return nil, requestError end

  local elements, copyError = copyMemberRecords( handle, true )

  Bridge.call( 'gmd_release_request', handle )
  if not elements then return nil, copyError end

  Bridge.State.arrayError = nil

  return elements
end

--- Encode Lua value as RValue
-- @param address number
-- @param argument any
local function encodeRValue(address, argument)
  local descriptor = type(argument) == 'table' and argument or { kind = type(argument) == 'boolean' and 'bool' or 'real' , value = argument }

  local kind, value = descriptor.kind or 'real', descriptor.value

  writeQword( address, 0 )
  writeInteger( address + 8, tonumber(descriptor.flags) or 0 )
  writeInteger( address + 12, 5 )

  if kind == 'real' then
    if type(value) ~= 'number' then return nil, 'real requires a number' end
    writeDouble( address, value )
    writeInteger( address + 12, 0 )

  elseif kind == 'int32' then
    if type(value) ~= 'number' then return nil, 'int32 requires a number' end
    writeInteger( address, value )
    writeInteger( address + 12, 7 )

  elseif kind == 'int64' then
    if type(value) ~= 'number' then return nil, 'int64 requires a number' end
    writeQword( address, value )
    writeInteger( address + 12, 10 )

  elseif kind == 'bool' then
    writeInteger( address, value and 1 or 0 )
    writeInteger( address + 12, 13 )

  elseif kind == 'pointer' or kind == 'object' or kind == 'array' then
    if type(value) ~= 'number' then return nil, kind .. ' requires a borrowed runtime pointer' end
    writePointer( address, value )
    writeInteger( address + 12, kind == 'pointer' and 3 or kind == 'object' and 6 or 2 )

  elseif kind == 'null' then
    writeInteger( address + 12, 12 )

  elseif kind == 'undefined' then
    writeInteger( address + 12, 5 )

  else
    return nil, 'unsupported argument kind: ' .. tostring(kind)
  end

  return true
end

--- Copy & decode call result
-- @param handle number
-- @param resultAddress number
-- @return table|nil
-- @return string|nil
local function copyCallResult(handle, resultAddress)
  if Bridge.call( 'gmd_copy_call_result', handle, resultAddress ) ~= 1 then return nil, Bridge.lastError() end

  local kind = readInteger( resultAddress + 12 )
  local result =
  {
    kind = kind,
    flags = readInteger( resultAddress + 8 )
  }

  if kind == 0 then
    result.value = readDouble( resultAddress )
  elseif kind == 7 or kind == 13 then
    result.value = readInteger( resultAddress )
  elseif kind == 10 then
    result.value = readQword( resultAddress )
  else
    result.pointer = readPointer( resultAddress )
  end

  return result
end

--- Call script
-- @param name string
-- @param arguments table
-- @param options table
function Bridge.callScript(name, arguments, options)
  
  if not Bridge.State.configured then return nil, 'Bridge not configured' end

  if type(name) ~= 'string' or name == '' then return nil, 'script name must be non-empty string' end

  if #name > 510 then return nil, 'script name is too long' end

  arguments, options = arguments or {}, options or {}

  if type(arguments) ~= 'table' then return nil, 'arguments must be a table array' end

  local allocations = {}

  --- Allocate and bookeep 1 request buffer
  -- @param size number
  local function allocate(size)
    local address = allocateMemory(size)
    if not address or address == 0 then return nil end

    allocations[ #allocations + 1 ] = address
    return address
  end

  --- Release every request buffer
  local function cleanup()
    for index = #allocations, 1, -1 do
      deAlloc( allocations[index] )
    end
  end

  -- native request copies into a fixed-size owned buffer before it is queued
  -- back that read with the full buffer so it never crosses CE's allocation when the supplied name is short.
  local nameAddress = allocate(512)
  local argumentAddress = #arguments > 0 and allocate( #arguments * 16 ) or 0
  local resultAddress = allocate(16)

  if not nameAddress or (#arguments > 0 and not argumentAddress) or not resultAddress then
    cleanup()
    return nil, 'Couldnt allocate script-call buffers'
  end

  writeString( nameAddress, name, false )

  for index, argument in ipairs(arguments) do
    
    local encoded, encodeError = encodeRValue( argumentAddress + (index - 1) * 16, argument )
    
    if not encoded then
      cleanup()
      return nil, ('argument %d: %s'):format(index, encodeError)
    end

  end

  local handle = Bridge.call( 'gmd_queue_script', nameAddress, options.self or 0, options.other or options.self or 0, argumentAddress, #arguments )
  if not handle or handle == 0 then
    cleanup()
    return nil, Bridge.lastError()
  end

  local completed, requestError = waitForRequest( handle, options.timeout, 'Waiting timeout for a script call' )
  if not completed then
    cleanup()
    return nil, requestError
  end

  local result, resultError = copyCallResult( handle, resultAddress )

  if not result then
    Bridge.call( 'gmd_release_request', handle )
    cleanup()
    return nil, resultError
  end

  Bridge.call( 'gmd_release_request', handle )

  cleanup()
  return result
end

--- Call one resolved no-argument runner routine
-- @param routine number
-- @param options table|nil
-- @return table|nil @ decoded RValue result
-- @return string|nil
function Bridge.callRoutine(routine, options)

  if not Bridge.State.configured then return nil, 'Bridge not configured' end

  if type(routine) ~= 'number' or routine == 0 then return nil, 'runner routine unavailable' end

  options = options or {}

  local resultAddress = allocateMemory(16)
  if not resultAddress or resultAddress == 0 then return nil, 'Couldnt allocate result buffer' end

  local handle = Bridge.call( 'gmd_queue_routine', routine, options.self or 0, options.other or options.self or 0, 0, 0 )

  if not handle or handle == 0 then

    local message = Bridge.lastError()

    deAlloc(resultAddress)

    return nil, message
  end

  local completed, requestError = waitForRequest( handle, options.timeout, 'Waiting timeout for a runner call' )

  if not completed then

    deAlloc(resultAddress)

    return nil, requestError
  end

  local result, resultError = copyCallResult( handle, resultAddress )

  Bridge.call( 'gmd_release_request', handle )

  deAlloc(resultAddress)

  return result, resultError
end

--- Enumerate members
-- @param object any
-- @param maximum number
-- @param timeout number
function Bridge.enumerateMembers(object, maximum, timeout)
  
  if not Bridge.State.configured then return nil, 'Bridge not configured' end

  local handle = Bridge.call( 'gmd_queue_members', object, maximum or 0x4000 )
  if not handle or handle == 0 then return nil, Bridge.lastError() end

  local completed, requestError = waitForRequest( handle, timeout, 'Waiting timeout for a reflection point' )
  if not completed then return nil, requestError end

  local members, copyError = copyMemberRecords( handle, false )

  Bridge.call( 'gmd_release_request', handle )
  if not members then return nil, copyError end

  return members
end

--- Annotate storage
-- @param storage table
-- @param maximum number
-- @param timeout number
function Bridge.annotateStorage(storage, maximum, timeout)

  -- reflection returns all visible runtime members; the raw map walker returns only populated storage
  -- address intersection is the safety invariant that proves a reflected name belongs to the exact RValue we intend to expose
  local members, memberError = Bridge.enumerateMembers( storage.instance.address, maximum, timeout )
  if not members then return nil, memberError end

  local byAddress = {}
  local bySlot = {}
  local byName = {}

  for _, member in ipairs(members) do

    if type(member.name) ~= 'string' or member.name == '' then return nil, 'bridge returned an empty member name' end
    
    if (not member.address or member.address == 0) and (not member.slot or member.slot < 0) then
      return nil, 'bridge returned neither an address nor a runtime slot for ' .. member.name
    end

    local hasAddress = member.address and member.address ~= 0

    if hasAddress then

      local previousAddress = byAddress[ member.address ]

      if previousAddress and previousAddress.name ~= member.name then return nil, 'bridge returned conflicting names for one RValue address' end

      byAddress[ member.address ] = member
    end

    if not hasAddress and member.slot and member.slot >= 0 then

      local previousSlot = bySlot[ member.slot ]

      if previousSlot and previousSlot.name ~= member.name then return nil, 'bridge returned conflicting names for one runtime slot' end

      bySlot[ member.slot ] = member
    end

    local previousName = byName[ member.name ]

    if previousName and previousName.address ~= member.address and previousName.slot ~= member.slot then
      return nil, 'bridge returned duplicate member name at different locations: ' .. member.name
    end

    byName[ member.name ] = member

  end

  local resolved = 0
  local assignments = {}

  for _, variable in ipairs( storage.variables ) do

    local member = byAddress[ variable.address ] or bySlot[ variable.slot ]
    
    if member then
      
      if variable.kind ~= nil and member.kind ~= nil and member.kind >= 0 and variable.kind ~= member.kind then
        return nil, ('bridge/raw RValue kind mismatch for %s at %X'):format( member.name, variable.address )
      end

      assignments[variable] = member.name
      resolved = resolved + 1
    end

  end

  if resolved ~= #storage.variables then
    return nil, ('bridge resolved %d/%d enumerated RValue addresses (%d reflected members)'):format( resolved, #storage.variables, #members )
  end

  for variable, name in pairs(assignments) do variable.name = name end
  
  storage.namesAvailable = true
  storage.bridgeMemberCount = #members
  storage.resolvedNameCount = resolved
  return storage
end

return Bridge