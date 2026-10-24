--[[
  GMDumper — Cheat Engine runtime dumper for GameMaker
  Copyright (C) 2026 palepine

  This program is free software: you can redistribute it and/or modify it under
  the terms of the GNU General Public License as published by the Free Software
  Foundation, either version 3 of the License, or (at your option) any later version.

  The script is heavely influenced and derives from Aurie Framework's YYToolkit

  YYToolkit
  Copyright (C) Aurie Framework 

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU Affero General Public License as published
  by the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU Affero General Public License for more details.

  You should have received a copy of the GNU Affero General Public License
  along with this program.  If not, see <https://www.gnu.org/licenses/>.

  UndertaleModTool
  Copyright (C) UnderminersTeam

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

]]

-- TODO: add namespaces for gm_watchObjectFields?

-- ///---///--///---///--///---///--///--///---///--///---///--///---///--///--///--///--///--///--///--///--///--///--///--/// GLOBALS & STATE

local GM =
{
  API = {},
  State = {},
  GUI = {},
  Resources = {},
  Portable = {}
}

local CE_VERSION_SUPPORTED = 7.7
local SETTINGS_KEY = [[GMDumper\Configuration]]
local CE_DIRECTORY = getCheatEngineDir() or ''
local SCRIPT_DIRECTORY = CE_DIRECTORY .. [[autorun\]]
local MODULE_DIRECTORY = SCRIPT_DIRECTORY .. [[GMDumperModules\]]

local PORTABLE_FILES =
{
  { name = 'GMDumper',                     path = [[autorun\GMDumper.lua]] },
  { name = 'GMDumper.GMRuntime',           path = [[autorun\GMDumperModules\GMRuntime.lua]] },
  { name = 'GMDumper.GMVersioning',        path = [[autorun\GMDumperModules\GMVersioning.lua]] },
  { name = 'GMDumper.GMBridge',            path = [[autorun\GMDumperModules\GMBridge.lua]] },
  { name = 'GMDumper.GMDumperBridge.x86.dll',  path = [[autorun\GMDumperModules\GMDumperBridge.x86.dll]],
    binary = true,
  },
  { name = 'GMDumper.GMDumperBridge.x64.dll',  path = [[autorun\GMDumperModules\GMDumperBridge.x64.dll]],
    binary = true,
  },
}

-- init/restore state
local shared = package.loaded['GMDumper.resources']
if type(shared) ~= 'table' then
  shared = {}
  package.loaded['GMDumper.resources'] = shared
end

shared.symbols = shared.symbols or {}
shared.listener = shared.listener or {}
shared.fieldSymbolCache = shared.fieldSymbolCache or {}
shared.boundFieldSymbols = shared.boundFieldSymbols or {}
shared.objectFieldWatches = shared.objectFieldWatches or {}
shared.fieldRefreshLock = shared.fieldRefreshLock or createCriticalSection()

-- retire worker before replacing any shared tables
if shared.fieldResolverThread then
  
  pcall(function() shared.fieldResolverThread.terminate() end)

  if shared.fieldResolverWake then pcall(function() shared.fieldResolverWake.setEvent() end) end

  local waited, finished = pcall(function() return shared.fieldResolverThread.waitfor(6000) end)

  if waited and finished then pcall(function() shared.fieldResolverThread.destroy() end) end

  shared.fieldResolverThread = nil
end

-- event
if shared.fieldResolverWake then
  pcall(function() shared.fieldResolverWake.destroy() end)
  shared.fieldResolverWake = nil
end

local resetFieldBindings, restoreObjectFieldWatches, startFieldResolver, stopFieldResolver

-- ///---///--///---///--///---///--///--///---///--///---///--///---///--///--///--///--///--///--///--///--///--///--///--/// LOCAL HELPERS

function printTable(value, indent, visited)
  indent = indent or 0
  visited = visited or {}

  if type(value) ~= 'table' then
    print(string.rep('  ', indent) .. tostring(value))
    return
  end

  if visited[value] then
    print( string.rep('  ', indent) .. '<cycle>' )
    return
  end

  visited[value] = true

  for key, item in pairs(value) do
    local prefix = string.rep( '  ', indent ) .. tostring(key) .. ' = '

    if type(item) == 'table' then
      print(prefix .. '{')
      printTable(item, indent + 1, visited)
      print( string.rep('  ', indent) .. '}' )
    else
      print( prefix .. tostring(item) )
    end
  end
end

--- On main thread
-- @param callback function|nil
-- @param ... any
local function onMainThread(callback, ...)
  if inMainThread() then return callback(...) end
  return synchronize(callback, ...)
end

--- Read attached table-file source
-- @param attachmentName string
-- @return string|nil @ complete source text
function GM.Portable.getAttachedSource(attachmentName)

  return onMainThread(
    function()
      local tableFile = findTableFile( attachmentName )
      if not tableFile then return nil end

      local stream = createStringStream()

      stream.Position = 0
      stream.copyFrom( tableFile.Stream, tableFile.Stream.Size )

      local source = stream.DataString

      stream.destroy()
      return source
    end
  )
end

--- Resolve a module from the current table / installed files
-- @param moduleName string
-- @param fileName string
-- @param attachmentName string
function GM.Portable.registerModuleResolver(moduleName, fileName, attachmentName)
  package.loaded[moduleName] = nil

  package.preload[ moduleName ] = function()
    local source = GM.Portable.getAttachedSource( attachmentName )

    if source then
      local chunk, parseError = load( source, '@' .. attachmentName )
      if not chunk then error(parseError, 2) end

      return chunk()
    end

    local installedPath = MODULE_DIRECTORY .. fileName
    local chunk, loadError = loadfile( installedPath, 't' )

    if not chunk then error( ('Unable to load %s. Installed file: %s'):format( moduleName, tostring(loadError) ), 2 ) end

    return chunk()
  end
end

--- Read all portable files
-- @return table[]|nil @ binary-safe file descriptors
-- @return string|nil @ read or validation error
function GM.Portable.readFiles()
  local files = {}

  for _, descriptor in ipairs( PORTABLE_FILES ) do
    
    local sourcePath = CE_DIRECTORY .. descriptor.path
    
    local sourceFile, openError = io.open( sourcePath, 'rb' )

    if not sourceFile then
      if descriptor.optional then goto continue end

      return nil, 'Couldnt read portable dependency ' .. sourcePath .. ': ' .. tostring(openError)
    end

    local fileData = sourceFile:read('*a')

    sourceFile:close()

    if not fileData or fileData == '' then return nil, 'Portable dependency is empty: ' .. sourcePath end
    if descriptor.binary and fileData:sub(1, 2) ~= 'MZ' then return nil, 'Portable DLL isnt a PE image: ' .. sourcePath end

    files[#files + 1] =
    {
      name = descriptor.name,
      data = fileData,
      binary = descriptor.binary == true,
      sourcePath = sourcePath,
    }

    ::continue::
  end

  return files
end

--- Replace one attached table file
-- @param attachmentName string
-- @param fileData string
-- @param binaryPath string|nil
function GM.Portable.replaceTableFile(attachmentName, fileData, binaryPath)
  local existing = findTableFile(attachmentName)
  if existing then existing.delete() end

  if binaryPath then
    assert( createTableFile( attachmentName, binaryPath ), 'Could not attach binary file ' .. attachmentName )
    return
  end

  local tableFile = assert( createTableFile(attachmentName), 'Could not create table file ' .. attachmentName )
  local sourceStream = createStringStream(fileData)

  tableFile.Stream.Position = 0
  tableFile.Stream.CopyFrom(sourceStream, 0)

  sourceStream.destroy()
end

--- Attach / update the complete portable GMDumper runtime
-- @return boolean|nil @ true when every available runtime file was attached
-- @return string|nil @ attachment error
function GM.API.gm_attachToTable()
  if not inMainThread() then return onMainThread( GM.API.gm_attachToTable ) end

  local files, readError = GM.Portable.readFiles()
  if not files then return nil, readError end

  local attached, attachError = pcall(
    function()
      for _, file in ipairs(files) do
        GM.Portable.replaceTableFile( file.name, file.data, file.binary and file.sourcePath or nil )
      end
    end
  )

  if not attached then return nil, 'Could not attach GMDumper: ' .. tostring(attachError) end

  return true
end

GM.Portable.registerModuleResolver( 'GMDumperModules.GMRuntime',    'GMRuntime.lua',    'GMDumper.GMRuntime' )
GM.Portable.registerModuleResolver( 'GMDumperModules.GMVersioning', 'GMVersioning.lua', 'GMDumper.GMVersioning' )
GM.Portable.registerModuleResolver( 'GMDumperModules.GMBridge',     'GMBridge.lua',     'GMDumper.GMBridge' )

--- Load runtime
local function loadRuntime()
  local ok, module = pcall(require, 'GMDumperModules.GMRuntime')
  if ok then return module end

  local chunk, loadError = loadfile( MODULE_DIRECTORY .. 'GMRuntime.lua', 't' )
  if chunk then return chunk() end
  module = loadError
  
  error('Unable to load GMDumperModules.GMRuntime: ' .. tostring(module))
end

local Runtime = loadRuntime()

--- Load bridge
local function loadBridge()
  local ok, module = pcall(require, 'GMDumperModules.GMBridge')
  if ok then return module end

  local chunk, loadError = loadfile( MODULE_DIRECTORY .. 'GMBridge.lua', 't' )
  if chunk then return chunk() end

  return nil, tostring(loadError or module)
end

local Bridge, bridgeLoadError = loadBridge()

--- Install bridge-backed reflection on an initialized state
-- @param state table
-- @param configured table
local function installBridgeResolvers(state, configured)
  
  state.resolveInstanceVariableNames = function(storage)
    return Bridge.annotateStorage( storage, configured.maximumRawVariables or 0x4000, configured.bridgeTimeout or 5000 )
  end

  local globalScope = Runtime.Reflection.findFunction( state, '@@GlobalScope@@' )

  state.globals = state.globals or {}

  if not globalScope then
    state.globals.error = '@@GlobalScope@@ is unavailable'
    return
  end

  state.globals.error = nil

  state.resolveGlobalObject = function()

    local result, callError = Bridge.callRoutine( globalScope.routine, { timeout = configured.bridgeTimeout or 5000 } )
    if not result then return nil, callError end

    if result.kind ~= 6 or not result.pointer or result.pointer == 0 then
      return nil, ('@@GlobalScope@@ returned %s instead of obj'):format( Runtime.Reflection.rvalueKindName(result.kind) )
    end

    return result.pointer
  end
  
end

--- Append log msg
-- @param message string
local function log(message)
  if GM.State.log == nil then GM.State.log = '' end

  GM.State.log = GM.State.log .. tostring(message) .. '\n\r'

  if type(GM.State.logRuntime) == 'table' then
    GM.State.logRuntime.log = GM.State.log
  end
end

--- Load persistent settings
local function options()
  local settings = onMainThread( getSettings, SETTINGS_KEY, true )
  
  local minimum = tonumber( settings.minimumFunctionCount ) or 32
  
  local maximumScripts = tonumber( settings.maximumScripts ) or 4096

  local maximumInstances = tonumber( settings.maximumInstances ) or 100000

  local scanScripts = tostring( settings.scanScripts or 'true' ) ~= 'false'

  local fieldRefreshInterval = math.max(100, tonumber(settings.fieldRefreshInterval) or 250)
  
  return
  {
    minimumFunctionCount = minimum,
    maximumScripts = maximumScripts,
    maximumInstances = maximumInstances,
    scanScripts = scanScripts,
    fieldRefreshInterval = fieldRefreshInterval,
  }
end

local function ensureReady()
  if not GM.State.runtime or not GM.State.runtime.ready then error('GMDumper not initialized', 2) end
  return GM.State.runtime
end

--- remove owned symbols (non-field which are reset separately)
local function clearSymbols()
  for name in pairs( shared.symbols ) do
    unregisterSymbol(name)
  end

  shared.symbols = {}
end

--- (Re-)Register a symbol and bookeep
-- @param name string
-- @param address number
local function registerOne(name, address)
  if shared.boundFieldSymbols[name] then return nil, 'symbol is owned by object-field watch: ' .. name end

  if getAddressSafe(name) ~= nil and shared.symbols[name] == nil then return nil, 'symbol is already owned: ' .. name end

  if shared.symbols[name] ~= nil then unregisterSymbol(name) end

  registerSymbol( name, address, true )

  shared.symbols[ name ] = address

  return true
end

-- ///---///--///---///--///---///--///--///---///--///---///--///---///--///--///--///--///--///--///--///--///--///--///--/// INITIALIZATION & STATUS

--- Init GameMaker runtime
-- @param overrides table|nil @ optional scanner and resolver overrides
-- @return table|nil @ initialized runtime state
-- @return string|nil @ scanner error
function GM.API.gm_initDumper(overrides) -- TODO: export to functions
  if getOpenedProcessID() == 0 then error('not attached') end

  GM.State.log = '' -- restart logging
  GM.State.logRuntime = nil

  -- stop background reads before replacing the state object they reference
  if stopFieldResolver then stopFieldResolver() end
  
  local configured = options() -- settings
  for key, value in pairs(overrides or {}) do configured[key] = value end

  -- target-side scanner, validation. Exit if fails
  local state, scannerError = Runtime.initialize(configured)
  if not state then
    GM.State.lastError = scannerError
    log('initialization failed: ' .. tostring(scannerError))
    return nil, scannerError
  end

  -- reset bound symbols and cache
  if resetFieldBindings then onMainThread(resetFieldBindings) end
  clearSymbols()
  shared.fieldSymbolCache = {}
  
  GM.State.runtime = state
  GM.State.logRuntime = state
  state.log = GM.State.log
  GM.State.lastError = nil

  local bridgeProfileError = state.profile.bridge.automatic == false and ('Bridge auto-discovery isnt available for profile ' .. state.profile.id) or nil
  state.bridge = { available = false , error = bridgeLoadError or bridgeProfileError }

  local manualReflection = configured.structGetKeys and configured.structGetMember

  if configured.bridge ~= false and (state.profile.bridge.automatic ~= false or manualReflection) and state.codeExecute and Bridge then
    
    -- Nil normally, bridge discovers the ABI, otherwise manually
    local reflection = configured.structGetKeys
                       and configured.structGetMember
                       and {  structGetKeys = configured.structGetKeys , structGetMember = configured.structGetMember  }
                       or nil
    
    local arrayEquals = Runtime.Reflection.findFunction( state, 'array_equals' )
    local arrayLength = Runtime.Reflection.findFunction( state, 'array_length' )
    local scriptExecute = Runtime.Reflection.findFunction( state, 'script_execute' )
    local memberGetNames = Runtime.Reflection.findFunction( state, 'variable_instance_get_names' ) or Runtime.Reflection.findFunction( state, 'variable_struct_get_names' )
    local memberNamesCount = Runtime.Reflection.findFunction( state, 'variable_instance_names_count' ) or Runtime.Reflection.findFunction( state, 'variable_struct_names_count' )

    local bridgeState, bridgeError = Bridge.configure(
                                                        state.codeExecute,
                                                        reflection,
                                                        arrayEquals and arrayEquals.routine,
                                                        arrayLength and arrayLength.routine,
                                                        scriptExecute and scriptExecute.routine,
                                                        state.profile.bridge,
                                                        state.pointerSize,
                                                        memberGetNames and memberGetNames.routine,
                                                        memberNamesCount and memberNamesCount.routine
                                                      )
    
    if bridgeState then
      state.bridge = bridgeState
      state.bridge.available = true

      -- Game-thread reflection annotates raw storage & resolves the global scope
      installBridgeResolvers( state, configured )

    else
      state.bridge =
      {
        available = false ,
        error = bridgeError
      }

      state.globals = state.globals or { available = false }

      state.globals.error = 'game-thread global scope unavailable: ' .. tostring(bridgeError)

      log('game-thread reflection unavailable: ' .. tostring(bridgeError))
    end

  end
  
  -- reg the engine functions
  if state.functionTable.start then
    registerOne( 'GM_RFunctionTable', state.functionTable.start )
  elseif state.functionTable.registrar then
    registerOne( 'GM_FunctionRegistrar', state.functionTable.registrar )
  end

  if state.codeExecute then
    registerOne( 'GM_CodeExecute', state.codeExecute )
  end

  if state.instances and state.instances.runRoomAddress then
    registerOne( 'GM_RunRoom', state.instances.runRoomAddress )
  end

  -- Restore every 'watch' before the worker is allowed to observe the binding table
  shared.restoringFieldBindings = true

  local ok, restoreError = pcall(restoreObjectFieldWatches, state)
  if not ok then log('object-field watches not restored: ' .. tostring(restoreError)) end

  shared.restoringFieldBindings = false

  if next(shared.boundFieldSymbols) then startFieldResolver(state) end
  
  log(
      ('ready: %s, version %s, profile %s, %d built-ins, %d compiled scripts, instances %s, %s')
      :format( state.runnerKind, state.version.text, state.profile.id, #state.functionTable.functions, #state.scripts,
               state.instances and (state.instances.available and 'available' or state.instances.error) or 'disabled', state.identity.name)
    )

  return state
end

--- Get complete state
-- @return table|nil @ runtime state
function GM.API.gm_getState()
  return GM.State.runtime
end

--- Get init status/info
-- @return table @ status snapshot
function GM.API.gm_getStatus()
  local state = GM.State.runtime
  local instances = state and state.instances
  local namedReflection = state
                          and ( state.bridge
                                and state.bridge.available == true
                                or instances
                                and instances.variableReflection
                                and instances.variableReflection.available == true
                              )
                          or false

  local reflectionError

  if not namedReflection then

    reflectionError = instances
                      and instances.variableReflectionError
                      or state
                      and state.bridge
                      and state.bridge.error
                      or nil
  end

  return
  {
    ready = state and state.ready == true or false,
    scanning = GM.State.scanning == true,
    -- dumping = GM.State.dumping == true,
    lastError = GM.State.lastError,
    log = GM.State.log or state and state.log or '',
    executable = state and state.identity or nil,
    runnerKind = state and state.runnerKind or nil,
    version = state and state.version or nil,
    profile = state and state.profile or nil,
    functionCount = state and state.functionTable and #state.functionTable.functions or 0,
    scriptCount = state and #(state.scripts or {}) or 0,
    instancesAvailable = instances and instances.available == true or false,
    globalsAvailable = state and state.globals and state.globals.available == true or false,
    globalsError = state and state.globals and state.globals.error or instances and instances.globalStorageError or nil,
    instanceCount = instances and instances.list and instances.list.count or 0,
    instanceError = instances and instances.error or nil,
    namedReflection = namedReflection,
    reflectionError = reflectionError,

    bridgeError = state and state.bridge and state.bridge.error or nil,
  }
end

--- Get validated layouts (runner/room/instance)
-- @return table @ layout snapshot
function GM.API.gm_getLayout()
  local state = ensureReady()

  return
  {
    functionTable = state.functionTable.start,
    functionRegistrar = state.functionTable.registrar,
    functionSource = state.functionTable.source,
    functionEntryKind = state.functionTable.layout.kind,
    functionEntrySize = state.functionTable.layout.stride,
    codeExecute = state.codeExecute,
    runnerKind = state.runnerKind,
    version = state.version,
    profile = state.profile,
    runRoom = state.instances and state.instances.runRoomAddress or nil,
    roomLayout = state.instances and state.instances.roomLayout or nil,
    instanceLayout = state.instances and state.instances.instanceLayout or nil,
    variableReflection = state.instances and state.instances.variableReflection or nil,
    variableReflectionError = state.instances and state.instances.variableReflectionError or nil,
  }
end

--- Get selected GameMaker version info
-- @return table @ version descriptor
function GM.API.gm_getVersion()
  return ensureReady().version
end

--- Get selected profile
-- @return table @ profile
function GM.API.gm_getProfile()
  return ensureReady().profile
end

--- Get injected lib status
-- @return table @ bridge capability snapshot
function GM.API.gm_getBridgeStatus()
  local state = ensureReady()

  if Bridge and Bridge.State.exports then
    local status = Bridge.status()
    status.available = state.bridge and state.bridge.available == true
    status.error = state.bridge and state.bridge.error or nil
    return status
  end

  return state.bridge
end

-- ///---///--///---///--///---///--///--///---///--///---///--///---///--///--///--///--///--///--///--///--///--///--///--/// REFLECTION QUERIES

--- Configure/reconnect the bridge
-- @param reflection table|nil @ optional manual reflection routine addresses
-- @return table|nil @ bridge status
-- @return string|nil @ bridge error
function GM.API.gm_configureBridge(reflection)
  local state = ensureReady()

  if not Bridge then return nil, bridgeLoadError or 'Bridge client is unavailable' end

  local arrayEquals = Runtime.Reflection.findFunction( state, 'array_equals' )
  local arrayLength = Runtime.Reflection.findFunction( state, 'array_length' )
  local scriptExecute = Runtime.Reflection.findFunction( state, 'script_execute' )
  local memberGetNames = Runtime.Reflection.findFunction( state, 'variable_instance_get_names' ) or Runtime.Reflection.findFunction( state, 'variable_struct_get_names' )
  local memberNamesCount = Runtime.Reflection.findFunction( state, 'variable_instance_names_count' ) or Runtime.Reflection.findFunction( state, 'variable_struct_names_count' )

  local status, bridgeError = Bridge.configure(
                                                state.codeExecute,
                                                reflection,
                                                arrayEquals and arrayEquals.routine,
                                                arrayLength and arrayLength.routine,
                                                scriptExecute and scriptExecute.routine,
                                                state.profile.bridge,
                                                state.pointerSize,
                                                memberGetNames and memberGetNames.routine,
                                                memberNamesCount and memberNamesCount.routine
                                              )

  if not status then
    state.bridge = { available = false , error = bridgeError }
    return nil, bridgeError
  end

  status.available = true
  state.bridge = status

  installBridgeResolvers( state, state.options )
  
  return status
end

--- Find a native function by name
-- @param name string @ built-in function name
-- @return table|nil @ function descriptor
function GM.API.gm_findFunction(name)
  return Runtime.Reflection.findFunction( ensureReady(), name )
end

--- List built-in runtime functions matching a name fragment
-- @param pattern string|nil @ case-insensitive name fragment
-- @return table[] @ function descriptors
function GM.API.gm_listFunctions(pattern)
  return Runtime.Reflection.listFunctions( ensureReady(), pattern )
end

--- Get the function table
-- @return table @ function-table descriptor
function GM.API.gm_getFunctionTable()
  return ensureReady().functionTable
end

--- List native YYC script descriptors matching a name fragment
-- @param pattern string|nil @ case-insensitive name fragment
-- @return table[] @ script descriptors
function GM.API.gm_listScripts(pattern)
  local state = ensureReady()
  local result = {}
  pattern = pattern and pattern:lower() or nil

  for _, entry in ipairs(state.scripts or {}) do

    if not pattern or entry.name:lower():find( pattern, 1, true ) then
      result[#result + 1] = entry
    end
  end

  return result
end

--- List active room instances matching an object name/ID
-- @param pattern string|number|nil @ object-name fragment or instance ID
-- @return table[]|nil @ active instance descriptors
-- @return string|nil @ instance-enumeration error
function GM.API.gm_listInstances(pattern)
  local instances, instanceError = Runtime.Instances.list( ensureReady() )
  if not instances then return nil, instanceError end

  if not pattern then return instances end

  local result, lower = {}, tostring(pattern):lower()

  for _, instance in ipairs(instances) do
  
    if instance.objectName:lower():find( lower, 1, true ) or tostring(instance.id) == tostring(pattern) then
      result[#result + 1] = instance
    end
  end
  
  return result
end

--- Enumerate raw variable storage (gameplay) for 1 instance
-- @param instanceOrId table|number @ instance descriptor, address or ID
-- @param maximum number|nil @ max variables to return
-- @return table|nil @ variable-storage descriptor
-- @return string|nil @ enumeration error
function GM.API.gm_listInstanceVariables(instanceOrId, maximum)
  return Runtime.Instances.listVariablesRaw( ensureReady(), instanceOrId, maximum )
end

--- Find 1 reflected instance variable by name/numeric slot
-- @param instanceOrId table|number @ instance descriptor, address or ID
-- @param nameOrSlot string|number @ reflected name or runtime slot
-- @return table|nil @ variable descriptor
-- @return string|nil @ lookup error
function GM.API.gm_findInstanceVariable(instanceOrId, nameOrSlot)
  return Runtime.Instances.findVariable( ensureReady(), instanceOrId, nameOrSlot )
end

--- Resolve RValue address of one instance variable
-- @param instanceOrId table|number @ instance descriptor, address or ID
-- @param nameOrSlot string|number @ reflected name or runtime slot
-- @return number|nil @ RValue address
-- @return string|nil @ lookup error
function GM.API.gm_getInstanceVariableAddress(instanceOrId, nameOrSlot)
  local variable, variableError = Runtime.Instances.findVariable( ensureReady(), instanceOrId, nameOrSlot )
  
  return variable and variable.address or nil, variableError
end

--- Enumerate user-defined global variables
-- @param maximum number|nil @ max variables to return
-- @return table|nil @ variable-storage descriptor
-- @return string|nil @ enumeration error
function GM.API.gm_listGlobalVariables(maximum)
  return Runtime.Globals.listVariablesRaw( ensureReady(), maximum, true )
end

--- Find a user-defined global variable
-- @param nameOrSlot string|number @ reflected name or runtime slot
-- @return table|nil @ variable descriptor
-- @return string|nil @ lookup error
function GM.API.gm_findGlobalVariable(nameOrSlot)
  return Runtime.Globals.findVariable( ensureReady(), nameOrSlot )
end

-- ///---///--///---///--///---///--///--///---///--///---///--///---///--///--///--///--///--///--///--///--///--///--///--/// WATCHED FIELD SYMBOLS

--- Capture storage invariants needed by fast resolver path
-- @param storage table
-- @param variable table
local function fieldStorageCacheRecord(storage, variable)
  local instance, map = storage.instance, storage.map

  return
  {
    processId = getOpenedProcessID(),
    instanceId = instance.id,
    instanceAddress = instance.address,
    objectAddress = instance.object,
    slot = variable.slot,
    address = variable.address,
    storageKind = storage.storageKind,
    yyVars = storage.yyVars,
    variableMap = storage.variableMap,
    mapElements = map and map.elements or nil,
    mapMask = map and map.currentMask or nil,
    bucket = variable.bucket,
    hash = variable.hash,
    node = variable.node,
    rvalueAddress = variable.rvalueAddress,
    valueOffset = variable.valueOffset,
  }
end

--- Register RValue address as a symbol
-- @param symbol string
-- @param binding table
-- @param address number
local function registerFieldAddress(symbol, binding, address)
  if not address then return nil, false end

  if binding.registered and binding.address == address then return address, false end  -- getAddressSafe(symbol) == address

  if binding.registered or getAddressSafe(symbol) then
    unregisterSymbol(symbol) -- explicitly
  end
  registerSymbol(symbol, address, true)

  binding.address, binding.registered = address, true
  binding.invalidReason, binding.invalidatedAt = nil, nil
  return address, true
end

--- Withdraw a symbol whose target can no longer be proven alive.
-- We do not preserve the last address.  A frozen MemoryRecord must become
-- unresolved rather than continue writing into released GameMaker storage.
-- @param symbol string
-- @param binding table
-- @param reason string
local function invalidateFieldBinding(symbol, binding, reason)

  local wasRegistered = binding.registered or getAddressSafe(symbol) ~= nil
  if wasRegistered then
    unregisterSymbol(symbol)
  end

  binding.address = nil
  binding.registered = false
  binding.invalidReason = reason
  -- binding.invalidatedAt = os.date('!%Y-%m-%dT%H:%M:%SZ')
  return wasRegistered
end

-- batch-poke to reinterpret address-list per resolver pass
-- @param symbols any
local function reinterpretFieldSymbolRecords(symbols)
  if not symbols or not next(symbols) then return 0 end

  return onMainThread(
    function()
      local addressList = getAddressList()
      if not addressList then return 0 end

      local reinterpreted = 0

      for index = 0, addressList.getCount() - 1 do

        local record = addressList.getMemoryRecord(index)

        if record and record.Type ~= vtAutoAssembler then
          local expression = tostring(record.getAddress() or '')
          local referencesChangedSymbol = false
          
          for token in expression:gmatch('[%a_][%w_%.]*') do
            if symbols[token] then
              referencesChangedSymbol = true
              break
            end
          end

          if referencesChangedSymbol then
            local ok = pcall(function() record.reinterpret() end)
            if ok then reinterpreted = reinterpreted + 1 end
          end
        end
      end
      return reinterpreted
    end
  )
end

--- Attach symbol to object watch
-- @param state table
-- @param symbol string
-- @param objectName string
-- @param fieldName string
-- @param watchId string
local function ensureWatchedFieldBinding(state, symbol, objectName, fieldName, watchId)
  local binding = shared.boundFieldSymbols[symbol]

  if not binding then
    binding =
    {
      objectName = objectName,
      fieldName = fieldName,
      watchIds = {}
    }
    shared.boundFieldSymbols[symbol] = binding
  end

  binding.watchIds[watchId] = true

  if not shared.restoringFieldBindings and startFieldResolver then
    startFieldResolver(state)
  end

  return binding
end

--- Build the public symbol for a reflected object field
-- @param objectName string
-- @param fieldName string
-- @return string
local function objectFieldSymbol(objectName, fieldName)
  return objectName .. '.' .. fieldName
end

--- reset field bindings
resetFieldBindings = function()
  if stopFieldResolver then stopFieldResolver() end

  -- Unregister first, then reinterpret
  local changedSymbols = {} 

  for symbol, binding in pairs( shared.boundFieldSymbols ) do
    
    if binding.registered then
      unregisterSymbol(symbol)
      changedSymbols[symbol] = true
    end

  end

  reinterpretFieldSymbolRecords(changedSymbols)

  shared.boundFieldSymbols = {}
end

--- Check if cached field in a group still names the same RValue
-- Uses direct reads only. Bridge is used on cache misses/structural changes
-- @param state table
-- @param group table
-- @param selected any
local function cachedStorageStillMatches(state, group, selected)
  
  for _, item in ipairs( group.bindings ) do

    local cached = shared.fieldSymbolCache[ item.symbol ]
    local binding = item.binding

    if not binding.registered
       or not cached
       or cached.processId ~= getOpenedProcessID()
       or cached.instanceId ~= selected.id
       or cached.instanceAddress ~= selected.address
       or cached.objectAddress ~= selected.object
    then
      return false
    end

    if cached.storageKind == 'dense-array' then
      -- dense slots are a 16-byte RValue array;
      if not selected.yyVars
         or selected.yyVars == 0
         or selected.yyVars ~= cached.yyVars
         or selected.yyVars + cached.slot * 16 ~= cached.address
      then
        return false
      end

    elseif cached.storageKind == 'sparse-map' then
      
      -- a rehash can retain same instance & slot but move the bucket, validate the header/bucket
      if not selected.variableMap
         or selected.variableMap == 0
         or selected.variableMap ~= cached.variableMap
         or readInteger(selected.variableMap + 8) ~= cached.mapMask
         or readPointer(selected.variableMap + 0x10) ~= cached.mapElements
         or cached.bucket == nil
      then
        return false
      end

      local stride = state.pointerSize == 8 and 16 or 12

      local element = cached.mapElements + cached.bucket * stride
      
      if readInteger( element + state.pointerSize ) ~= cached.slot
         or ( ( readInteger( element + state.pointerSize + 4 ) or 0 ) & 0xFFFFFFFF ) ~= cached.hash
         or readPointer( element ) ~= cached.address
      then
        return false
      end

    elseif cached.storageKind == 'gms1-bucket-map' then
      
      -- GMS1 stores variables in chained buckets
      -- re-walk only the cached bucket & require exact node/ID/value relationship to survive
      local layout = state.instances and state.instances.instanceLayout

      local storage = selected.legacyVariableMap or layout and readPointer( selected.address + layout.variableStorageOffset ) or nil

      if not layout or not layout.direct or not storage or storage == 0 or storage ~= cached.variableMap or cached.bucket == nil or not cached.node then
        return false
      end

      local node = readPointer( storage + layout.variableBucketOffset + cached.bucket * state.pointerSize )
      local found = false

      for _ = 1, 100000 do
        if not node or node == 0 then break end
        
        if node == cached.node then

          found = readInteger( node + layout.variableNodeIdOffset ) == cached.slot
                  and node + layout.variableNodeValueOffset == cached.rvalueAddress
                  and cached.rvalueAddress + cached.valueOffset == cached.address
          break
        end

        node = readPointer( node + layout.variableNodeNextOffset )
      end

      if not found then return false end
    else

      return false
    end

  end
  return true
end

--- Resolve all bindings
-- caller owns fieldRefreshLock
-- @param state table
-- @param cancelled boolean
local function refreshFieldBindingsUnlocked(state, cancelled) -- TODO: extract
  local statistics =
    {
      requested = 0,
      refreshed = 0,
      unchanged = 0,
      invalidated = 0,
      reinterpreted = 0,
      failures = {},
    }

  local changedSymbols = {}
  local groups = {}
  local objectNames = {}

  -- group fields by the object name (many fields, one inst lookup)
  for symbol, binding in pairs( shared.boundFieldSymbols ) do
    statistics.requested = statistics.requested + 1

    if binding.objectName and binding.fieldName then
      local group = groups[ binding.objectName ] or { objectName = binding.objectName , bindings = {} }

      group.bindings[#group.bindings + 1] = { symbol = symbol , binding = binding }

      groups[ binding.objectName ] = group

      if binding.objectName ~= 'global' then
        objectNames[ binding.objectName ] = true
      end

    else
      statistics.failures[symbol] = 'watch binding has no object/field metadata'
    end

  end

  -- Traverse active-room list & build every requested index
  local targets, targetError

  if next(objectNames) then
    targets, targetError = Runtime.Instances.findActiveTargets( state, {}, {}, objectNames )
  else
    targets =
    {
      instances = {},
      byObjectName = {}
    }
  end

  if not targets then
    statistics.error = targetError

    -- unregister
    for _, group in pairs(groups) do
      for _, item in ipairs( group.bindings ) do

        if invalidateFieldBinding( item.symbol, item.binding, 'active instance list is unavailable: ' .. tostring(targetError) ) then
          statistics.invalidated = statistics.invalidated + 1
          changedSymbols[ item.symbol ] = true
        end

      end

    end

    statistics.reinterpreted = reinterpretFieldSymbolRecords(changedSymbols)
    return statistics
  end

  local globalGroup = groups.global

  if globalGroup then
    local globalInstance, globalError = Runtime.Globals.instance(state)

    if globalInstance then

      targets.instances[ #targets.instances + 1 ] = globalInstance
      targets.byObjectName.global = { globalInstance }
    else
      globalGroup.targetError = globalError or 'global scope unavailable'
    end

  end

  for _, group in pairs(groups) do

    if cancelled and cancelled() then
      statistics.cancelled = true
      break
    end

    -- Watched symbols are valid only while exactly 1 matching instance exists
    local matches = targets.byObjectName[ group.objectName ] or {}

    local selected = #matches == 1 and matches[1] or nil

    local absenceReason = group.targetError
                          or #matches == 0 and ( group.objectName == 'global' and 'global scope unavailable' or 'obj w/o active instance' )
                          or #matches > 1 and 'obj w/ multiple active instances'

    if absenceReason then

      for _, item in ipairs( group.bindings ) do

        if invalidateFieldBinding( item.symbol, item.binding, absenceReason ) then
          statistics.invalidated = statistics.invalidated + 1
          changedSymbols[item.symbol] = true
        end

      end
      goto next_group
    end

    -- most ticks end here
    if cachedStorageStillMatches( state, group, selected ) then
      statistics.unchanged = statistics.unchanged + #group.bindings
      goto next_group
    end

    -- lingering CInstance with freed variables is invalidated here
    local rawStorage, rawStorageError = Runtime.Instances.listVariablesRaw( state, selected, nil, false, targets.instances )

    if not rawStorage then
      local reason = 'instance variable storage unavailable: ' .. tostring(rawStorageError)

      for _, item in ipairs(group.bindings) do

        if invalidateFieldBinding( item.symbol, item.binding, reason ) then
          statistics.invalidated = statistics.invalidated + 1
          changedSymbols[item.symbol] = true
        end

      end

      goto next_group
    end

    -- cheap proof failed, perform a reflected pass for the whole object and rebuild every field address from that snapshot
    local storage, storageError = Runtime.Instances.listVariablesRaw( state, selected, nil, true, targets.instances )

    if storage then
      local byName = {}

      for _, variable in ipairs( storage.variables or {} ) do
        if variable.name then byName[ variable.name ] = variable end
      end

      for _, item in ipairs( group.bindings ) do
        local variable = storage.namesAvailable and byName[ item.binding.fieldName ] or nil

        if variable and variable.address then

          local changed = item.binding.address ~= variable.address or not item.binding.registered

          shared.fieldSymbolCache[ item.symbol ] = fieldStorageCacheRecord( storage, variable )

          local _, symbolChanged = registerFieldAddress( item.symbol, item.binding, variable.address )

          item.binding.instanceId = storage.instance.id
          item.binding.objectAddress = storage.instance.object
          item.binding.slot = variable.slot

          if symbolChanged then
            changedSymbols[item.symbol] = true
          end

          if changed then
            statistics.refreshed = statistics.refreshed + 1
          else
            statistics.unchanged = statistics.unchanged + 1
          end

        elseif item.binding.fieldName and not storage.namesAvailable then

          local reason = tostring( storage.nameResolutionError or 'strict field names unavailable')
          statistics.failures[item.symbol] = reason

          if invalidateFieldBinding( item.symbol, item.binding, reason ) then
            statistics.invalidated = statistics.invalidated + 1
            changedSymbols[item.symbol] = true
          end

        else
          local reason = 'field is absent from reflected storage'

          if invalidateFieldBinding( item.symbol, item.binding, reason ) then
            statistics.invalidated = statistics.invalidated + 1
            changedSymbols[item.symbol] = true
          end

        end
      end

    else

      for _, item in ipairs(group.bindings) do
        local reason = tostring( storageError or 'reflection failed' )
        statistics.failures[ item.symbol ] = reason

        if invalidateFieldBinding( item.symbol, item.binding, reason ) then
          statistics.invalidated = statistics.invalidated + 1
          changedSymbols[ item.symbol ] = true
        end

      end

    end
    ::next_group::
  end
  -- reinterpret only records that mention a symbol changed by this pass
  statistics.reinterpreted = reinterpretFieldSymbolRecords(changedSymbols)
  return statistics
end

--- Serialize manual & worker refreshes
-- @param state table
-- @param cancelled boolean
local function refreshFieldBindings(state, cancelled)
  local lock = shared.fieldRefreshLock
  
  if not lock.tryEnter() then
    return
    {
      requested = 0,
      refreshed = 0,
      unchanged = 0,
      failures = {},
      busy = true
    }
  end

  local ok, result = pcall( refreshFieldBindingsUnlocked, state, cancelled )
  lock.leave()

  if not ok then error(result, 0) end
  return result
end

--- Stop field resolver
stopFieldResolver = function()
  local thread  = shared.fieldResolverThread
  local wake = shared.fieldResolverWake

  shared.fieldResolverThread = nil  
  shared.fieldResolverWake = nil

  if thread then
    pcall(function() thread.terminate() end)

    if wake then pcall( function() wake.setEvent() end ) end

    local waited, finished = pcall( function() return thread.waitfor(6000) end )

    if waited and finished then pcall( function() thread.destroy() end ) end
  end

  if wake then pcall( function() wake.destroy() end ) end
  return true
end

--- Start field resolver
-- @param state table
-- @param interval number
startFieldResolver = function(state, interval)

  if shared.fieldResolverThread then return true end

  interval = math.max( 100, tonumber(interval) or tonumber( state.options.fieldRefreshInterval ) or 250 )

  local wake, processId = createEvent( false, false ), getOpenedProcessID()

  shared.fieldResolverWake = wake

  shared.fieldResolverThread = createThread(

    function(thread)
      thread.Name = 'GMDumper field-symbol resolver'
      thread.freeOnTerminate(false)

      -- performs target reads and symbol operations
      while not thread.Terminated do

        wake.waitFor(interval)

        if thread.Terminated then break end

        if GM.State.runtime ~= state or not state.ready or getOpenedProcessID() ~= processId then break end

        if next(shared.boundFieldSymbols) then
          pcall( refreshFieldBindings, state, function() return thread.Terminated end )
        end

      end

    end

  )
  
  return true
end

--- Validate & copy reflected field names requested by a watch
-- @param fields table @ sequential array of reflected field names
-- @return table|nil @ copied field-name array
-- @return string|nil @ validation error
local function normalizeWatchedFields(fields)
  if type(fields) ~= 'table' then return nil, 'fields must be a sequential array of reflected field names' end

  local result = {}
  local seen = {}

  for index, fieldName in ipairs(fields) do

    if type(fieldName) ~= 'string' or not fieldName:match('^[%a_][%w_]*$') then
      return nil, ('invalid reflected field at index %d: %s'):format(index, tostring(fieldName))
    end

    if seen[fieldName] then return nil, 'duplicate reflected field: ' .. fieldName end

    seen[fieldName] = true
    result[index] = fieldName
  end

  -- index tables only
  for key in pairs(fields) do
    if type(key) ~= 'number' or key % 1 ~= 0 or key < 1 or key > #result then return nil, 'fields must be a sequential array of reflected field names' end
  end

  if #result == 0 then return nil, 'at least one reflected field is required' end

  return result
end

--- Remove 1 watched
-- @param watchId number
local function detachObjectFieldWatch(watchId)

  local watch = shared.objectFieldWatches[ watchId ]
  if not watch then return false end

  local changedSymbols = {}

  for _, fieldName in ipairs( watch.fields or {} ) do

    local symbol = objectFieldSymbol( watch.objectName, fieldName )

    local binding = shared.boundFieldSymbols[ symbol ]

    if binding and binding.watchIds then

      binding.watchIds[ watchId ] = nil

      if not next( binding.watchIds ) then

        if invalidateFieldBinding( symbol, binding, 'object-field watch removed' ) then
          changedSymbols[symbol] = true
        end

        shared.boundFieldSymbols[ symbol ] = nil
        shared.fieldSymbolCache[ symbol ] = nil

      end

    end

  end

  shared.objectFieldWatches[watchId] = nil

  reinterpretFieldSymbolRecords(changedSymbols)
  return true
end

--- Validate symbol ownership, then attach the watch to resolver bindings
-- @param state table
-- @param watch table
local function installObjectFieldWatch(state, watch)

  -- complete validation first
  for _, fieldName in ipairs( watch.fields ) do

    local symbol = objectFieldSymbol( watch.objectName, fieldName )

    local existing = shared.boundFieldSymbols[ symbol ]

    if existing and ( ( existing.objectName and existing.objectName ~= watch.objectName ) or ( existing.fieldName and existing.fieldName ~= fieldName ) ) then
      return nil, ( 'symbol %s already bound to %s.%s'):format( symbol, tostring(existing.objectName), tostring(existing.fieldName) )
    end

    if not existing and getAddressSafe( symbol ) ~= nil then return nil, 'symbol already owned: ' .. symbol end

  end

  for _, fieldName in ipairs( watch.fields ) do
    local symbol = objectFieldSymbol( watch.objectName, fieldName )
    ensureWatchedFieldBinding( state, symbol, watch.objectName, fieldName, watch.id )
  end

  return watch
end

--- Restore object field watches
-- @param state table
restoreObjectFieldWatches = function(state)
  local rejected = {}

  for id, watch in pairs(shared.objectFieldWatches) do
    local installed, installError = installObjectFieldWatch( state, watch )

    if not installed then
      rejected[ #rejected + 1 ] = id
      log( ('watch %s was removed during restore: %s'):format( tostring(watch.id), tostring(installError) ) )
    end
  end

  for _, id in ipairs(rejected) do
    detachObjectFieldWatch(id)
  end

end

--- Keep reflected fields of 1 unique GM object registered as symbols
-- @param objectName string @ exact GM object name
-- @param fields table @ sequential array of reflected field names
-- @param watchOptions table|nil @ watch ID and immediate-refresh options
-- @return table|nil @ stored watch descriptor
-- @return table|string|nil @ refresh status or validation error
function GM.API.gm_watchObjectFields(objectName, fields, watchOptions)
  local state = ensureReady()

  watchOptions = watchOptions or {}

  if type(objectName) ~= 'string' or not objectName:match('^[%a_][%w_]*$') then
    return nil, 'objectName must match GM object identifier'
  end

  local normalized, fieldError = normalizeWatchedFields( fields )
  if not normalized then return nil, fieldError end

  local watchId = tostring( watchOptions.id or objectName )
  if watchId == '' then return nil, 'watch id cannot be empty' end

  -- Pause the worker while mutating its binding set, then wake a fresh pass
  if shared.fieldResolverThread then stopFieldResolver() end

  shared.restoringFieldBindings = true

  local previous = shared.objectFieldWatches[ watchId ]
  if previous then detachObjectFieldWatch(watchId) end

  -- watches remain saved between initializations
  local watch =
  {
    id = watchId,
    objectName = objectName,
    fields = normalized,
  }

  shared.objectFieldWatches[watchId] = watch

  local installed, installError = onMainThread( installObjectFieldWatch, state, watch )

  if not installed then
    shared.objectFieldWatches[watchId] = previous
    
    if previous then
      onMainThread(installObjectFieldWatch, state, previous)
    end

    shared.restoringFieldBindings = false

    if next(shared.boundFieldSymbols) then
      startFieldResolver(state)
    end

    return nil, installError
  end

  shared.restoringFieldBindings = false

  local refresh
  if watchOptions.immediate == true then
    refresh = refreshFieldBindings(state)
  end
  
  if next( shared.boundFieldSymbols ) then
    startFieldResolver(state)
    if shared.fieldResolverWake then
      shared.fieldResolverWake.setEvent()
    end
  end

  return watch, refresh or { queued = true }
end

--- Remove object-field watch and its unowned symbols
-- @param watchId string|number @ watch identifier
-- @return boolean @ true when a watch was removed
function GM.API.gm_unwatchObjectFields(watchId)
  local state = ensureReady()

  if shared.fieldResolverThread then
    stopFieldResolver()
  end

  shared.restoringFieldBindings = true

  local removed = onMainThread( detachObjectFieldWatch, tostring(watchId) )

  shared.restoringFieldBindings = false

  if next( shared.boundFieldSymbols ) then
    startFieldResolver(state)

    if shared.fieldResolverWake then
      shared.fieldResolverWake.setEvent()
    end
  end
  
  return removed
end

--- Get object-field watches & binding status
-- @return table @ watch descriptors keyed by watch ID
function GM.API.gm_getObjectFieldWatches()
  local result = {}

  for id, watch in pairs( shared.objectFieldWatches ) do

    local copy =
    {
      id = id,
      objectName = watch.objectName,
      fields = {},
      ready = true
    }

    for index, fieldName in ipairs(watch.fields or {}) do

      local symbol = objectFieldSymbol( watch.objectName, fieldName )
      local binding = shared.boundFieldSymbols[ symbol ]

      local status =
      {
        field = fieldName,
        symbol = symbol,
        registered = binding and binding.registered == true or false,
        address = binding and binding.address or nil,
        instanceId = binding and binding.instanceId or nil,
        error = binding and binding.invalidReason or nil,
      }

      if not status.registered then
        copy.ready = false
      end

      copy.fields[index] = status
    end

    result[id] = copy
  end

  return result
end

--- Rediscover current-room & instance layouts
-- @param overrides table|nil @ instance-scanner overrides
-- @return table|nil @ validated instance runtime
-- @return string|nil @ scanner error
function GM.API.gm_rescanInstances(overrides)
  local state = ensureReady()
  
  for key, value in pairs(overrides or {}) do
    state.options[key] = value
  end
  
  -- structure snapshots contain target allocations and describe the previous layout
  -- release them before replacing the instance runtime
  Runtime.Instances.releaseSnapshot(state)

  local result = Runtime.Discovery.findInstanceRuntime(state)

  if result.runRoomAddress then registerOne( 'GM_RunRoom', result.runRoomAddress ) end

  if result.available and next( shared.boundFieldSymbols ) then
    refreshFieldBindings(state)
  end

  return result.available and result or nil, result.available and nil or result.error
end

-- ///---///--///---///--///---///--///--///---///--///---///--///---///--///--///--///--///--///--///--///--///--///--///--/// RVALUE REFLECTION & INVOCATION

--- Decode RValue as a descriptor
-- @param address number @ live RValue address
-- @return table|nil @ decoded value descriptor
-- @return string|nil @ decoding error
function GM.API.gm_decodeRValue(address)
  return Runtime.Reflection.decodeRValue(address)
end

--- Get object ptr from value
-- @param value any
-- @param valueOptions table
local function objectPointerFromValue(value, valueOptions)
  valueOptions = valueOptions or {}

  if type(value) == 'table' then
    if value.kindName == 'object' or value.kind == 6 then
      return value.pointer or value.value
    end

    if value.address then
      value = value.address
    else
      return nil, 'value isnt object RValue'
    end
  end

  if type(value) ~= 'number' then return nil, 'expected RValue addr/descriptor/raw obj ptr' end

  if valueOptions.rawObject == true then
    return value
  end

  local decoded, decodeError = Runtime.Reflection.decodeRValue(value)
  if not decoded then return nil, decodeError end

  if decoded.kind ~= 6 or not decoded.pointer or decoded.pointer == 0 then return nil, 'RValue isnt object/struct' end
  
  return decoded.pointer, nil, decoded
end

--- Enumerate VALUE_OBJECT/struct
-- @param value table|number @ object RValue descriptor, address or raw pointer
-- @param memberOptions table|nil @ maximum, timeout and rawObject options
-- @return table|nil @ named member collection
-- @return string|nil @ reflection error
function GM.API.gm_listRValueMembers(value, memberOptions)
  ensureReady()

  if not Bridge then return nil, bridgeLoadError or 'Bridge client unavailable' end

  local object, objectError, decoded = objectPointerFromValue( value, memberOptions )
  if not object then return nil, objectError end

  local members, memberError = Bridge.enumerateMembers(
                                                        object,
                                                        memberOptions and memberOptions.maximum,
                                                        memberOptions and memberOptions.timeout
                                                      )
  if not members then return nil, memberError end

  local result =
  {
    object = object,
    value = decoded,
    members = {},
    byName = {}
  }

  for _, member in ipairs(members) do

    local item, decodeError = Runtime.Reflection.decodeRValue( member.address )

    item = item or { address = member.address , kind = member.kind , error = decodeError }

    item.name = member.name
    result.members[ #result.members + 1 ] = item
    result.byName[ item.name ] = item
  end

  table.sort( result.members, function(left, right) return left.name < right.name end )
  return result
end

--- Find named member in an object-valued RValue
-- @param value table|number @ object RValue descriptor, address or raw pointer
-- @param name string @ exact reflected member name
-- @param memberOptions table|nil @ reflection options
-- @return table|nil @ decoded member descriptor
-- @return string|nil @ reflection or lookup error
function GM.API.gm_findRValueMember(value, name, memberOptions)
  if type(name) ~= 'string' then return nil, 'member name must be a string' end

  local result, memberError = GM.API.gm_listRValueMembers( value, memberOptions )
  if not result then return nil, memberError end

  return result.byName[name], result.byName[name] and nil or ('member not found: ' .. name)
end

--- Enumerate elements of an array-valued RValue
-- @param value table|number @ array RValue descriptor or address
-- @param arrayOptions table|nil @ maximum and timeout options
-- @return table|nil @ decoded array descriptor
-- @return string|nil @ enumeration error
function GM.API.gm_listRValueArray(value, arrayOptions)
  ensureReady()

  if not Bridge then return nil, bridgeLoadError or 'Bridge client is unavailable' end

  local address = type(value) == 'table' and value.address or value
  if type(address) ~= 'number' then return nil, 'expected a live array RValue address or descriptor' end

  local decoded, decodeError = Runtime.Reflection.decodeRValue(address)
  if not decoded then return nil, decodeError end

  if decoded.kind ~= 2 then return nil, 'RValue isnt array' end

  local elements, arrayError = Bridge.enumerateArray( address, arrayOptions and arrayOptions.maximum, arrayOptions and arrayOptions.timeout )
  if not elements then return nil, arrayError end

  local result =
  {
    address = address,
    value = decoded,
    elements = {}
  }

  for _, element in ipairs(elements) do
    local item, elementError = Runtime.Reflection.decodeRValue( element.address )

    item = item or { address = element.address, kind = element.kind, error = elementError }

    item.index = element.index
    result.elements[#result.elements + 1] = item
  end

  result.count = #result.elements
  return result
end

--- Get array element by index
-- @param value table|number @ array RValue descriptor or address
-- @param index number @ zero-based element index
-- @param arrayOptions table|nil @ maximum and timeout options
-- @return table|nil @ decoded element descriptor
-- @return string|nil @ lookup error
function GM.API.gm_getRValueArrayElement(value, index, arrayOptions)
  index = tonumber(index)
  if not index or index < 0 or index ~= math.floor(index) then return nil, 'array index must be a non-negative integer' end

  arrayOptions = arrayOptions or {}
  arrayOptions.maximum = math.max( index + 1, tonumber(arrayOptions.maximum) or 0 )

  local result, arrayError = GM.API.gm_listRValueArray( value, arrayOptions )

  if not result then return nil, arrayError end
  return result.elements[index + 1], result.elements[index + 1] and nil or 'array index is out of bounds'
end

--- Call user-defined GML func via Script_Find_Id/Script_Perform (game-thread)
-- Arguments: scalar, references (pointer/object/array RValues)
-- @param name string @ user-defined function name
-- @param arguments table|nil @ scalar or borrowed-reference arguments
-- @param callOptions table|nil @ self, other and timeout options
-- @return table|nil @ copied result RValue
-- @return string|nil @ invocation error
function GM.API.gm_callUserFunction(name, arguments, callOptions)
  ensureReady()

  if not Bridge then return nil, bridgeLoadError or 'Bridge client unavailable' end

  callOptions = callOptions or {}

  local function addressOf(value)
    if type(value) == 'table' then return value.address end
    return value
  end

  callOptions.self = addressOf( callOptions.self ) or 0
  callOptions.other = addressOf( callOptions.other ) or callOptions.self

  local result, callError = Bridge.callScript( name, arguments, callOptions )
  if not result then return nil, callError end
  
  result.kindName = Runtime.Reflection.rvalueKindName( result.kind )
  return result
end

-- ///---///--///---///--///---///--///--///---///--///---///--///---///--///--///--///--///--///--///--///--///--///--///--/// SYMBOLS, STRUCTURES & DUMPS

--- Register built-in and YYC routine addresses as symbols
-- @param prefix string|nil @ symbol namespace prefix
-- @return table @ registered symbol set
function GM.API.gm_registerFunctionSymbols(prefix)
  local state = ensureReady()

  prefix = prefix or ''

  local used = {}
  local pending = {}

  for _, entry in ipairs( state.functionTable.functions ) do
    local clean = entry.name:gsub('[^%w_.$]', '_')
    local name = prefix .. clean
    
    if used[name] then name = name .. '_' .. entry.index end
    used[name] = true
    pending[#pending + 1] = { name = name, address = entry.routine }
  end

  for _, entry in ipairs(state.scripts or {}) do
    local name = prefix .. entry.name:gsub('[^%w_.$]', '_')
    if not used[name] then
      used[name] = true
      pending[#pending + 1] = { name = name, address = entry.routine }
    end
  end

  for _, item in ipairs(pending) do -- TODO: remove once completely redundant
    if shared.boundFieldSymbols[item.name] then return nil, 'function symbol collides with watched field: ' .. item.name end

    if getAddressSafe(item.name) ~= nil and shared.symbols[ item.name ] == nil then return nil, 'function symbol is already owned: ' .. item.name end
  end

  for _, item in ipairs(pending) do
    local registered, registrationError = registerOne( item.name, item.address )
    if not registered then return nil, registrationError end
  end

  return used
end

--- Create instance snapshot
-- @return userdata @ instance-index structure
-- @return table @ target-side snapshot descriptor
function GM.API.gm_createInstanceOverview()
  local state = ensureReady()

  return onMainThread(
    function()
      local structure, snapshot, structureError = Runtime.Structures.createInstanceOverview(state)
      if not structure then return nil, structureError end

      registerOne( 'InstanceIndex', snapshot.address )
      return structure, snapshot
    end
  )
end

--- Open instance snapshot in Struct Dissect
-- @return userdata @ Structure Dissect form
-- @return userdata @ instance-index structure
-- @return table @ target-side snapshot descriptor
function GM.API.gm_openInstanceOverview()
  local state = ensureReady()

  return onMainThread(
    function()
      local structure, snapshot, structureError = Runtime.Structures.createInstanceOverview(state)
      if not structure then error( structureError, 2 ) end

      registerOne( 'InstanceIndex', snapshot.address )
      local form = createStructureForm()
      form.Column[0].AddressText = 'InstanceIndex'
      form.MainStruct = structure
      
      return form, structure, snapshot
    end
  )
end

--- Dump current instances/objects with fields
-- @param path string|nil @ output path
-- @param dumpOptions table|nil @ filtering and maximum-count options
-- @return string|nil @ written path
-- @return table|string @ dump statistics or error
function GM.API.gm_dumpObjects(path, dumpOptions)
  return Runtime.Dump.objects( ensureReady(), path, dumpOptions )
end

--- Release symbols, snapshots, hooks and runtime state
-- @return boolean @ true after cleanup
function GM.API.gm_cleanup()
  
  -- stop resolver first for teardown
  if resetFieldBindings then onMainThread(resetFieldBindings) end
  
  if GM.State.runtime then Runtime.Instances.releaseSnapshot( GM.State.runtime ) end

  if Bridge and Bridge.State.exports and Bridge.State.configured then
    Bridge.call( 'gmd_remove_dispatcher' )
    Bridge.State.configured = false
  end

  clearSymbols()

  shared.fieldSymbolCache = {}
  GM.State.runtime = nil
  GM.State.logRuntime = nil
  GM.State.scanning = false

  collectgarbage()
  return true
end

--- Heuristic to guess GameMaker
-- @return boolean @ true when GM evidence passes the threshold
-- @return table @ detection evidence
function GM.API.gm_isGameMakerProcess()
  local processId = getOpenedProcessID()

  if type(processId) ~= 'number' or processId == 0 then
    return false, {}
  end

  return Runtime.Discovery.couldBeGameMaker(processId)
end

--- Get process evidence
-- @return table @ copied evidence records
function GM.API.gm_getDetectionEvidence()
  local copied = {}
  
  for index, item in ipairs( GM.State.detectionEvidence or {} ) do
    copied[index] = item
  end

  return copied
end

-- ///---///--///---///--///---///--///--///---///--///---///--///---///--///--///--///--///--///--///--///--///--///--///--/// PUBLIC API

local exports =
{
  'gm_attachToTable',
  'gm_initDumper',
  'gm_getState',
  'gm_getStatus',
  'gm_getLayout',
  'gm_getVersion',
  'gm_getProfile',
  'gm_getBridgeStatus',
  'gm_configureBridge',
  'gm_findFunction',
  'gm_listFunctions',
  'gm_getFunctionTable',
  'gm_listScripts',
  'gm_listInstances',
  'gm_listInstanceVariables',
  'gm_findInstanceVariable',
  'gm_getInstanceVariableAddress',
  'gm_listGlobalVariables',
  'gm_findGlobalVariable',
  'gm_watchObjectFields',
  'gm_unwatchObjectFields',
  'gm_getObjectFieldWatches',
  'gm_rescanInstances',
  'gm_decodeRValue',
  'gm_listRValueMembers',
  'gm_findRValueMember',
  'gm_listRValueArray',
  'gm_getRValueArrayElement',
  'gm_registerFunctionSymbols',
  'gm_createInstanceOverview',
  'gm_openInstanceOverview',
  'gm_callUserFunction',
  'gm_dumpObjects',
  'gm_cleanup',
  'gm_isGameMakerProcess',
  'gm_getDetectionEvidence'
}

-- register API
for _, name in ipairs(exports) do
  _G[name] = GM.API[name]
end

-- ///---///--///---///--///---///--///--///---///--///---///--///---///--///--///--///--///--///--///--///--///--///--///--/// GUI & PROCESS LIFECYCLE

--- Check proc id
-- @param processId number
local function isUsableProcessId(processId)
  return type(processId) == 'number' and processId > 0 and processId ~= 0xFFFFFFFF and processId ~= 0xFFFFFFFE
end

--- Destroy menu
function GM.GUI.destroyMenu()
  if not inMainThread() then return onMainThread( GM.GUI.destroyMenu ) end

  local ownedMenu = shared.menu

  if ownedMenu then pcall( function() ownedMenu.destroy() end ) end
  shared.menu = nil

  local root = MainForm and MainForm.Menu and MainForm.Menu.Items

  if root then

    for index = root.Count - 1, 0, -1 do
      local item = root[index]
      if item and item.Name == 'miGMDumper' then item.destroy() end
    end

  end
  GM.GUI.items = nil
end

--- Add menu item
-- @param parent table
-- @param name string
-- @param caption string
-- @param callback function|nil
local function addMenuItem(parent, name, caption, callback)
  local item = createMenuItem(parent)
  item.Name = name
  item.Caption = caption
  item.OnClick = callback
  parent.add(item)
  return item
end

--- initialization
-- @param hookState table
function GM.GUI.launchInitialization(hookState)
  if GM.State.scanning then return false end
  local processId = getOpenedProcessID()

  if not isUsableProcessId(processId) then return false end

  -- generation checking
  local generation = hookState and hookState.generation or 0

  GM.State.scanning = true

  GM.GUI.createMenu('scanning')

  -- Sig scanning and layout validation
  createThread(
    function(thread)
      thread.Name = 'GMDumper runtime scanner'
      local ok, state, scanError = pcall( GM.API.gm_initDumper )
      if not ok then
        scanError = state
        state = nil
      end

      if getOpenedProcessID() ~= processId or (hookState and hookState.generation ~= generation) then
        GM.State.scanning = false
        return
      end

      GM.State.scanning = false

      if state then
        onMainThread( GM.GUI.createMenu, 'ready' )
      else
        GM.State.lastError = scanError
        onMainThread(  function()  GM.GUI.createMenu('idle');  log( 'GM: init failed:\n' .. tostring(scanError) )  end  )
      end
    end
  )
  return true
end

--- Launch object dump
function GM.GUI.launchObjectDump()
  if GM.State.dumping then return false end
  local processId = getOpenedProcessID()
  local state = ensureReady()
  GM.State.dumping = true

  if GM.GUI.items and GM.GUI.items.dump then
    GM.GUI.items.dump.Enabled = false
    GM.GUI.items.dump.Caption = 'Dumping live objects and fields...'
  end

  createThread(
    function(thread)
      thread.Name = 'GMDumper object dumper'
      local ok, path, stats = pcall( GM.API.gm_dumpObjects )
      if not ok then
        stats = path
        path = nil
      end

      GM.State.dumping = false
      if getOpenedProcessID() ~= processId or GM.State.runtime ~= state then return end

      onMainThread(
        function()
          GM.GUI.createMenu('ready')
          if path then
            log( ('Wrote %s\n\n%d objects, %d instances, %d fields, %d read errors'):format( path, stats.objectCount, stats.instanceCount, stats.fieldCount, stats.errorCount ) )
          else
            log( 'Object dump failed:\n' .. tostring(stats) )
          end
        end
      )
    end
  )
  return true
end

--- Attach portable files to the table
-- @param menuItem table|nil
function GM.GUI.attachToTable(menuItem)
  local attached, attachmentError = GM.API.gm_attachToTable()

  if not attached then
    messageDialog( attachmentError or 'Could not attach GMDumper', mtError, mbOK )
    return
  end

  if menuItem then menuItem.Caption = 'Attach script to table (upd)' end
end

--- Create menu
-- @param mode string
-- @param statusText string
function GM.GUI.createMenu(mode, statusText)
  if not inMainThread() then return onMainThread( GM.GUI.createMenu, mode, statusText ) end
  if not MainForm or not MainForm.Menu then return end
  GM.GUI.destroyMenu()

  local menu = createMenuItem( MainForm.Menu )
  menu.Name = 'miGMDumper'
  menu.Caption = 'GMDumper'
  shared.menu = menu
  GM.GUI.items = { root = menu }

  local hookState = package.loaded['GMDumper.processOpenedHook']
  local initializeCaption = mode == 'ready' and 'Rescan runtime' or 'Init runtime'

  if mode == 'scanning' then
    local working = addMenuItem( menu, 'miGMDumperWorking', 'Scanning runtime', nil )
    working.Enabled = false
    GM.GUI.items.status = working
  else
    GM.GUI.items.initialize = addMenuItem( menu, 'miGMDumperInitialize', initializeCaption,   function() GM.GUI.launchInitialization( hookState ) end   )
  end

  local debugMenu = addMenuItem( menu, 'miGMDumperDebug', 'Debug', nil )

  GM.GUI.items.debug = debugMenu
  GM.GUI.items.attach = addMenuItem( debugMenu, 'miGMDumperAttach', 'Append script to table', GM.GUI.attachToTable )

  if mode == 'ready' then
    local state = GM.State.runtime

    GM.GUI.items.dump = addMenuItem( menu, 'miGMDumperDumpObjects', 'Dump objects & fields',   function() GM.GUI.launchObjectDump() end   )

    GM.GUI.items.instances = addMenuItem(menu, 'miGMDumperDissectInstances', 'Dissect Instances',
      function()
        local ok, result = pcall( GM.API.gm_openInstanceOverview )
        if not ok then messageDialog(tostring(result), mtError, mbOK) end
      end
    )

    if not (state and state.instances and state.instances.available) then
      GM.GUI.items.dump.Enabled = false
      GM.GUI.items.dump.Caption = 'Object dump unavailable'
      log( 'Object dump unavailable: ' .. tostring(state and state.instances and state.instances.error or 'not scanned') )
      GM.GUI.items.instances.Enabled = false
      GM.GUI.items.instances.Caption = 'Live Instances unavailable'
      log( 'Live Instances unavailable: ' .. tostring(state and state.instances and state.instances.error or 'not scanned') )
    end

    addMenuItem(debugMenu, 'miGMDumperRescanInstances', 'Rescan room/instances',
      function()
        local ok, result, scanError = pcall( GM.API.gm_rescanInstances )

        if ok and result then
          GM.GUI.createMenu('ready')
        else
          messageDialog( tostring(scanError or result), mtError, mbOK )
        end

      end
    )

    addMenuItem(debugMenu, 'miGMDumperBridge', 'Reconnect bridge',
      function()
        local ok, result, bridgeError = pcall( GM.API.gm_configureBridge )
        if ok and result then GM.GUI.createMenu('ready') else messageDialog( tostring(bridgeError or result), mtError, mbOK ) end
      end
    )

    addMenuItem(debugMenu, 'miGMDumperCleanup', 'Clear runtime',   function() GM.API.gm_cleanup();  GM.GUI.createMenu('idle'); end   )

  end

  local helpIndex = MainForm.miHelp and MainForm.miHelp.MenuIndex or MainForm.Menu.Items.Count
  MainForm.Menu.Items.insert( helpIndex, menu )
end

--- Process checking
-- @param processId number
-- @param hookState table
-- @param generation any
function GM.GUI.detectProcess(processId, hookState, generation)
  
  createThread(
    function(thread)
      thread.Name = 'GMDumper process detector'
      waitForExports()

      local ok, detected, evidence = pcall( Runtime.Discovery.couldBeGameMaker, processId )
      
      if not ok then
        detected = false
        evidence = {}
      end

      if hookState.generation ~= generation or getOpenedProcessID() ~= processId then return end

      onMainThread(
        function()
          
          if hookState.generation ~= generation or getOpenedProcessID() ~= processId then return end

          GM.State.detectionEvidence = evidence or {}

          if detected then GM.GUI.createMenu('idle') else GM.GUI.destroyMenu() end

        end
      )

    end
  )

end

--- On process opened
-- @param processId number
-- @param processHandle any
-- @param caption string
-- @param hookState table
function GM.GUI.onProcessOpened(processId, processHandle, caption, hookState)
  
  -- Invalidate generation and clean
  hookState.generation = (hookState.generation or 0) + 1
  local generation = hookState.generation

  GM.State.detectionEvidence = {}
  GM.State.lastError = nil
  GM.State.scanning = false
  GM.GUI.destroyMenu()
  GM.API.gm_cleanup()
  GM.State.log = ''
  
  if isUsableProcessId(processId) then GM.GUI.detectProcess( processId, hookState, generation ) end
end

--- Install process event listener
function GM.GUI.installProcessListener()
  if not inMainThread() then return onMainThread( GM.GUI.installProcessListener ) end
  if not MainForm then return end

  -- Restore the handler
  if shared.listener and shared.listener.owner and MainForm.OnProcessOpened == shared.listener.callback then
    MainForm.OnProcessOpened = shared.listener.previous
  end

  shared.listener = {}

  local hookState = package.loaded['GMDumper.processOpenedHook']
  
  if type(hookState) ~= 'table' then
    hookState = { generation = 0 }
    package.loaded['GMDumper.processOpenedHook'] = hookState
  end

  hookState.callback = function(processId, processHandle, caption)
    GM.GUI.onProcessOpened( processId, processHandle, caption, hookState )
  end

  if not hookState.installed then

    local previousHandler = MainForm.OnProcessOpened

    MainForm.OnProcessOpened = function(processId, processHandle, caption)
      
      if previousHandler then
        previousHandler( processId, processHandle, caption )
      end

      if hookState.callback then
        hookState.callback( processId, processHandle, caption )
      end
    end

    hookState.installed = true
  end

  local processId = getOpenedProcessID()
  
  if isUsableProcessId(processId) then
    hookState.callback(processId, nil, nil)
  else
    GM.API.gm_cleanup()
    GM.GUI.destroyMenu()
  end

end

if getCEVersion() < CE_VERSION_SUPPORTED then
  log( ('Cheat Engine %.1f or newer required'):format( CE_VERSION_SUPPORTED ) )
end

GM.GUI.installProcessListener()

return GM.API