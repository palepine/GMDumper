--[[
  GMDumper runtime discovery and reflection backend
  Copyright (C) 2026 palepine

  GPL-3.0-or-later. See LICENSE in the project root.
]]

-- ///---///--///---///--///---///--///--///---///--///---///--///---///--///--///--///--///--///--///--///--///--///--///--/// RUNTIME STATE

local Runtime =
{
  Memory = {}, -- mapped-image helpers, scans
  Discovery = {}, -- inference, validated layout selection
  Reflection = {}, -- function queries, RValue decoding
  Instances = {}, -- active-room traversal, gameplay-variable storage
  Globals = {}, -- global storage vars
  Dump = {},
  Structures = {} -- struct dissect
}

local CE_DIRECTORY = getCheatEngineDir() or ''
local MODULE_DIRECTORY = CE_DIRECTORY .. [[autorun\GMDumperModules\]]

--- Load version-profile module
-- @return table
local function loadVersioning()
  local ok, module = pcall(require, 'GMDumperModules.GMVersioning')
  if ok then return module end

  local chunk, loadError = loadfile( MODULE_DIRECTORY .. 'GMVersioning.lua', 't' )
  if chunk then return chunk() end

  module = loadError
  error('Unable to load GMDumperModules.GMVersioning: ' .. tostring(module))
end

local Versioning = loadVersioning()

-- arbitrary limits
local MAX_FUNCTIONS = 0x4000
local MAX_STRING = 128

--- Safe call
-- @param fn function|nil
-- @param ... any
local function safeCall(fn, ...)
  local ok, a, b, c = pcall(fn, ...)
  if ok then return a, b, c end
  return nil
end

local readPtr = readPointer
local readI32 = readInteger

-- ///---///--///---///--///---///--///--///---///--///---///--///---///--///--///--///--///--///--///--///--///--///--///--/// MEMORY & FILE HELPERS

--- Read a bounded C string
-- @param address number
-- @param maximum number
local function readCString(address, maximum)
  return readString( address, maximum or MAX_STRING , false )
end

--- Trim whitespaces
-- @param value any
local function trim(value)
  return ( tostring( value or '' ):gsub( '^%s+', '' ):gsub( '%s+$', '' ) )
end

--- Range contains
-- @param range table
-- @param address number
local function rangeContains(range, address)
  return range and address and address >= range.start and address < range.finish
end

--- Is plausible name
-- @param name string
local function isPlausibleName(name)
  if type(name) ~= 'string' or #name < 2 or #name > 127 then return false end
  if name:find('[^%w_@$.:]') then return false end
  return name:find('[A-Za-z_]') ~= nil
end

--- Is plausible user-variable name
-- One-character identifiers are valid GML even though they are too weak for
-- discovery anchors such as built-in function names.
-- @param name string
local function isPlausibleVariableName(name)
  if type(name) ~= 'string' or #name < 1 or #name > 127 then return false end
  if name:find('[^%w_@$.:]') then return false end
  return name:find('[A-Za-z_]') ~= nil
end

--- Turn text into a byte pattern
-- @param text string
local function bytePattern(text)
  local result = {}
  for index = 1, #text do result[#result + 1] = ('%02X'):format( text:byte( index ) ) end
  return table.concat(result, ' ')
end

--- Pointer pattern
-- @param value any
-- @param pointerSize number
local function pointerPattern(value, pointerSize)
  local bytes = {}

  local current = value

  for _ = 1, pointerSize do
    bytes[ #bytes + 1 ] = ('%02X'):format( current & 0xFF )
    current = current >> 8
  end

  return table.concat(bytes, ' ')
end

--- Copy results
-- @param results table
local function copyResults(results)
  local copied = {}

  if results then

    for index = 1, #results do

      local address = type(results[index]) == 'number' and results[index] or getAddressSafe( results[index] )
      if address then copied[#copied + 1] = address end

    end
  end

  return copied
end

--- Run byte-pattern scan (aligned)
-- @param pattern string
-- @param startAddress number
-- @param stopAddress number
-- @param protection string
-- @param alignment number
-- @param cancellation function|nil
function Runtime.Memory.scan(pattern, startAddress, stopAddress, protection, alignment, cancellation)
  
  local scan = createMemScan()

  scan.VarType = vtByteArray
  scan.Hexadecimal = true
  scan.Scanvalue = pattern
  scan.Fastscanmethod = fsmAligned
  scan.Fastscanparameter = tostring(alignment or 1)

  if startAddress then scan.Startaddress = startAddress end
  if stopAddress then scan.Stopaddress = stopAddress end
  if protection then scan.Protectionflags = protection end

  scan.scan()

  while scan.waitTillDone(250) == false do
    if cancellation and cancellation() then
      scan.terminateScan()
      break
    end
  end

  local results = copyResults( scan.Results )
  local errorText = scan.ErrorString
  
  scan.destroy()

  if errorText and errorText ~= '' then return {}, errorText end

  return results
end

--- Get main module descriptor
function Runtime.Memory.mainModule()
  local modules = enumModules() or {}
  local processName = extractFileName( process or '' ):lower()

  for _, module in ipairs(modules) do
    
    if extractFileName( module.PathToFile ):lower() == processName then return module end

  end

  return modules[1]
end

--- Parse mapped PE section ranges from the main module
-- @param module table
function Runtime.Memory.sections(module)
  if not module or not module.Address then return nil, 'No main module' end
  local base = module.Address
  
  local peOffset = readI32( base + 0x3C )
  if not peOffset then return nil, 'Invalid DOS header' end
  
  local pe = base + peOffset
  if readI32( pe ) ~= 0x4550 then return nil, 'Invalid PE signature' end

  local sectionCount = readSmallInteger( pe + 6 )
  local optionalSize = readSmallInteger( pe + 20 )
  
  if not sectionCount or not optionalSize then return nil, 'Invalid PE file header' end

  local sections = {}
  local first = pe + 24 + optionalSize

  for index = 0, sectionCount - 1 do

    local header = first + index * 40

    local name = trim( ( readCString( header, 8 ) or '' ):gsub( '\0.*$', '' ) )
    local virtualSize = readI32( header + 8 ) or 0
    local virtualAddress = readI32( header + 12 ) or 0
    local rawSize = readI32( header + 16 ) or 0
    local size = math.max( virtualSize, rawSize )

    if name ~= '' and size > 0 then
      sections[name] =
      {
        name = name,
        start = base + virtualAddress,
        finish = base + virtualAddress + size,
        size = size
      }
    end

  end
  
  sections.image =
  {
    start = base,
    finish = base + module.Size,
    size = module.Size
  }

  return sections
end

--- Is executable memory
-- @param state table
-- @param address number
function Runtime.Memory.isExecutable(state, address)
  if not address or address == 0 then return false end

  if rangeContains( state.sections['.text'], address ) then return true end

  for _, module in ipairs( enumModules() or {} ) do
    if address >= module.Address and address < module.Address + module.Size then return true end
  end

  return false
end

--- Executable identity
-- @param module table
function Runtime.Memory.executableIdentity(module)
  local path = module and module.PathToFile or ''
  local version, metadata = '', nil

  if type(getFileVersion) == 'function' and path ~= '' then

    local versionValue, components = safeCall( getFileVersion, path )
    if versionValue then
      version = tostring(versionValue)
    end

    if type(components) == 'table' then
      metadata = components
    end
  end

  return
  {
    path = path,
    name = extractFileName(path),
    size = module and module.Size or 0,
    fileVersion = version,
    versionMetadata = metadata
  }
end

-- ///---///--///---///--///---///--///--///---///--///---///--///---///--///--///--///--///--///--///--///--///--///--///--/// GAME DATA & VERSIONING

--- Read unsigned 8-bit value
-- @param address number
local function readU8(address)
  return readBytes( address, 1, false )
end

local readF32 = readFloat

--- Convert unsigned 32-bit to signed representation
-- @param value any
local function signed32(value)
  if value and value >= 0x80000000 then return value - 0x100000000 end
  return value
end

--- Convert unsigned 8-bit to signed representation
-- @param value any
local function signed8(value)
  if value and value >= 0x80 then return value - 0x100 end
  return value
end

--- Monotonic milliseconds
local function monotonicMilliseconds()
  local tick = getTickCount() or nil
  return type(tick) == 'number' and tick or math.floor( os.clock() * 1000 )
end

--- File exists readable
-- @param path string
local function fileExistsReadable(path)
  
  local exists = safeCall(fileExists, path)
  if exists ~= nil then return exists == true end

  local file = io.open(path, 'rb')
  if not file then return false end

  file:close()
  return true
end

--- Read file prefix
-- @param path string
-- @param count number
local function readFilePrefix(path, count)
  local file = io.open(path, 'rb')
  if not file then return nil end

  local prefix = file:read(count)
  
  file:close()

  return prefix
end

--- Unpack little-endian unsigned 32-bit value
-- @param value any
-- @param offset number
local function unpackU32LE(value, offset)
  if type(value) ~= 'string' or #value < offset + 3 then return nil end

  local a, b, c, d = value:byte( offset, offset + 3 )

  return a | (b << 8) | (c << 16) | (d << 24)
end

--- Version text
-- @param version number
local function versionText(version)
  if not version then return 'unknown' end

  return ('%d.%d.%d.%d'):format( version.major or 0, version.minor or 0, version.release or 0, version.build or 0 )
end

-- not exact, but good to know the lower bound
-- the table isn't ultimate, might be imprecise
-- the inference is:
-- executable metadata > chunk-derived lower bound > stored GEN8 version > unknown 0.0.0.0
local GAME_DATA_LOWER_BOUNDS =
{
  { 'UILR', 2024, 13 },
  { 'PSEM', 2023, 2 },
  { 'FEAT', 2022, 8 },
  { 'FEDS', 2, 3, 6 },
  { 'SEQN', 2, 3, 0 },
  { 'TGIN', 2, 2, 1 }
}

--- Infer the min runtime version represented by a chunk directory
-- @param chunks table
-- @return table|nil
local function inferGameDataVersion(chunks)

  for _, item in ipairs(GAME_DATA_LOWER_BOUNDS) do

    if chunks[ item[1] ] then

      return
      {
        major = item[2],
        minor = item[3],
        release = item[4] or 0,
        build = 0,
        source = 'data.win/chunk:' .. item[1],
        confidence = 'lower-bound'
      }

    end

  end

end

--- Recover build-runtime version from compiler-owned STRG paths.
-- GameMaker's asset compiler may preserve paths beneath Cache/runtimes/runtime-X.Y.Z.B/bin in the string table.
-- not ultimate though
-- @param data table
-- @return table|nil
-- @return string|nil
local function readGameDataRuntimePathVersion(data)

  local chunk = data and data.chunks and data.chunks.STRG

  if not chunk or not chunk.size or chunk.size <= 0 or chunk.size > 0x10000000 then return nil end

  local bytes

  if data.embedded and not data.fileBase then return nil end

  local file = io.open( data.path, 'rb' )
  if not file then return nil end

  file:seek( 'set', (data.fileBase or 0) + chunk.offset )

  bytes = file:read( chunk.size )

  file:close()

  if type(bytes) ~= 'string' or #bytes ~= chunk.size then return nil end

  local versions = {}

  for text in bytes:lower():gmatch('runtimes[\\/]runtime%-(%d+%.%d+%.%d+%.%d+)[\\/]bin[\\/]') do
    versions[text] = true
  end

  local selected

  for text in pairs(versions) do
    
    if selected and selected ~= text then
      return nil, 'conflicting runtime build paths in data.win/STRG'
    end

    selected = text
  end

  if not selected then return nil end

  local major, minor, release, build = selected:match('^(%d+)%.(%d+)%.(%d+)%.(%d+)$')
  if not major then return nil end

  return
  {
    major = tonumber(major),
    minor = tonumber(minor),
    release = tonumber(release),
    build = tonumber(build),
    source = 'data.win/STRG-runtime-path',
    confidence = 'exact-build-runtime'
  }
end

--- Read FORM directory and the fixed portion of GEN8
--- the 4 stored runtime words are useful for GMS1
-- for modern games chunk features provide a more honest lower bound because GEN8 is commonly frozen
function Runtime.Discovery.readGameDataVersion(path)
  local file = io.open( path, 'rb' )
  if not file then return nil, 'unreadable game data' end

  local header = file:read(8)
  if not header or header:sub( 1, 4 ) ~= 'FORM' then
    file:close()
    return nil, 'not a FORM container'
  end

  local chunks = {}
  local gen8 = nil
  local formSize = unpackU32LE( header, 5 ) or 0
  local formEnd = 8 + formSize
  local position = 8
  
  while position + 8 <= formEnd do
    file:seek( 'set', position )

    local chunkHeader = file:read(8)
    if not chunkHeader or #chunkHeader < 8 then break end

    local name = chunkHeader:sub( 1, 4 )
    local size = unpackU32LE( chunkHeader, 5 )
    
    if not size or size > formEnd or position + 8 + size > formEnd + 8 then break end

    chunks[name] = { offset = position + 8, size = size }

    if name == 'GEN8' then
      file:seek( 'set', position + 8 )
      gen8 = file:read( math.min(size, 64) )
    end

    position = position + 8 + size
  end

  file:close()

  local stored
  
  if gen8 and #gen8 >= 60 then
    stored =
    {
      major = unpackU32LE( gen8, 45 ),
      minor = unpackU32LE( gen8, 49 ),
      release = unpackU32LE(gen8, 53),
      build = unpackU32LE( gen8, 57 ),
      source = 'data.win/GEN8',
      confidence = 'stored'
    }
  end

  return
  {
    path = path,
    stored = stored,
    inferred = inferGameDataVersion(chunks),
    chunks = chunks,
    bytecodeVersion = gen8 and gen8:byte(2) or nil
  }
end

--- Read embedded FORM container from the mapped image
-- @param state table
-- @return table|nil
function Runtime.Discovery.readMappedGameDataVersion(state)
  local range = state.sections['.data'] or state.sections.image
  local hits = Runtime.Memory.scan( '46 4F 52 4D * * * * 47 45 4E 38', range.start, range.finish - 1, nil, 1 )

  for _, base in ipairs(hits) do

    local formSize = readI32( base + 4 )
    local formEnd = formSize and (base + 8 + formSize) or nil

    if formSize and formSize > 0 and formEnd <= state.sections.image.finish then

      local chunks = {}
      local gen8Address = nil
      local gen8Size = nil
      local position = base + 8

      for _ = 1, 1024 do
        if position + 8 > formEnd then break end

        local name = readString( position, 4, false )
        local size = readI32( position + 4 )

        if type(name) ~= 'string' or #name ~= 4 or not size or size < 0 or position + 8 + size > formEnd then
          chunks = nil
          break
        end

        chunks[name] = { offset = position + 8 - base, address = position + 8, size = size }

        if name == 'GEN8' then
          gen8Address = position + 8
          gen8Size = size
        end

        position = position + 8 + size
      end

      if chunks and gen8Address and gen8Size >= 60 then
        local stored =
        {
          major = readI32( gen8Address + 44 ),
          minor = readI32( gen8Address + 48 ),
          release = readI32( gen8Address + 52 ),
          build = readI32( gen8Address + 56 ),
          source = 'embedded-FORM/GEN8',
          confidence = 'stored'
        }

        return
        {
          path = state.module.PathToFile,
          embedded = true,
          address = base,
          stored = stored,
          inferred = inferGameDataVersion(chunks),
          chunks = chunks,
          bytecodeVersion = readU8(gen8Address + 1)
        }
      end

    end

  end

end

--- Read embedded FORM container from the executable file
-- @param state table
-- @return table|nil
function Runtime.Discovery.readEmbeddedGameDataVersion(state)
  local file = io.open( state.module.PathToFile, 'rb' )
  if not file then return nil end

  local fileSize = file:seek('end')
  local position, overlap, formBase = 0, '', nil

  while position < fileSize and not formBase do

    file:seek( 'set', position )

    local block = file:read( math.min( 0x100000, fileSize - position ) ) or ''
    local searchable = overlap .. block
    local searchPosition = 1

    while true do

      local found = searchable:find( 'FORM', searchPosition, true )
      if not found then break end

      local absolute = position - #overlap + found - 1

      if searchable:sub( found + 8, found + 11 ) == 'GEN8' then
        file:seek( 'set', absolute + 4 )
        local formSize = unpackU32LE( file:read(4), 1 )
        if formSize and absolute + 8 + formSize <= fileSize then formBase = absolute break end
      end

      searchPosition = found + 1
    end

    overlap = searchable:sub( math.max(1, #searchable - 15) )
    position = position + #block
  end

  if not formBase then file:close() return nil end

  file:seek( 'set', 0x3C )
  local peOffset = unpackU32LE( file:read(4), 1 )

  file:seek( 'set', peOffset + 6 )
  local sectionCountBytes = file:read(2)
  local sectionCount = sectionCountBytes and (sectionCountBytes:byte(1) | (sectionCountBytes:byte(2) << 8)) or 0

  file:seek('set', peOffset + 20)
  local optionalSizeBytes = file:read(2)
  local optionalSize = optionalSizeBytes and (optionalSizeBytes:byte(1) | (optionalSizeBytes:byte(2) << 8)) or 0
  local sectionHeaders = peOffset + 24 + optionalSize
  local mappedAddress

  for index = 0, sectionCount - 1 do

    file:seek( 'set', sectionHeaders + index * 40 )
    local header = file:read(40)

    if header and #header == 40 then

      local virtualAddress = unpackU32LE( header, 13 )
      local rawSize = unpackU32LE( header, 17 )
      local rawAddress = unpackU32LE( header, 21 )

      if formBase >= rawAddress and formBase < rawAddress + rawSize then
        mappedAddress = state.module.Address + virtualAddress + (formBase - rawAddress)
        break
      end

    end

  end

  local formSize
  file:seek( 'set', formBase + 4 )
  formSize = unpackU32LE( file:read(4), 1 )
  local chunks = {}
  local gen8 = nil
  local relative = 8

  while relative + 8 <= 8 + formSize do

    file:seek( 'set', formBase + relative )

    local header = file:read(8)
    if not header or #header < 8 then break end

    local name = header:sub( 1, 4 )
    local size = unpackU32LE( header, 5 )
    if not size or relative + 8 + size > 8 + formSize then break end

    chunks[name] =
    {
      offset = relative + 8,
      fileOffset = formBase + relative + 8,
      address = mappedAddress and (mappedAddress + relative + 8) or nil,
      size = size
    }

    if name == 'GEN8' then
      file:seek( 'set', formBase + relative + 8 )
      gen8 = file:read( math.min( size, 64 ) )
    end

    relative = relative + 8 + size
  end

  file:close()
  if not gen8 or #gen8 < 60 then return nil end

  return
  {
    path = state.module.PathToFile,
    embedded = true,
    address = mappedAddress,
    fileBase = formBase,
    stored =
    {
      major = unpackU32LE( gen8, 45 ),
      minor = unpackU32LE( gen8, 49 ),
      release = unpackU32LE(gen8, 53),
      build = unpackU32LE( gen8, 57 ),
      source = 'embedded-FORM/GEN8',
      confidence = 'stored'
    },
    inferred = inferGameDataVersion(chunks),
    chunks = chunks,
    bytecodeVersion = gen8:byte(2)
  }
end

--- Read object asset names from the OBJT records in a FORM container
-- @param data table|nil
-- @return table
local function readGameDataObjectNames(data)
  local chunk = data and data.chunks and data.chunks.OBJT
  if not chunk then return {} end

  local file = (not data.embedded or data.fileBase) and io.open(data.path, 'rb') or nil

  --- Read FORM-relative unsigned 32-bit value
  -- @param offset number
  local function readU32(offset)
    
    if file then
      file:seek( 'set', (data.fileBase or 0) + offset )
      return unpackU32LE( file:read(4), 1 )
    end

    if data.embedded and data.address then return readI32( data.address + offset ) end
  end

  --- Read one FORM-relative byte string
  -- @param offset number
  -- @param count number
  local function readText(offset, count)

    if file then
      file:seek( 'set', (data.fileBase or 0) + offset )
      return file:read(count)
    end

    if data.embedded and data.address then
      return readString( data.address + offset, count, false )
    end

  end

  local count = readU32( chunk.offset )
  local names = {}

  if count and count >= 0 and count <= 1000000 then

    for index = 0, count - 1 do
      local recordOffset = readU32( chunk.offset + 4 + index * 4 )
      
      local nameOffset = recordOffset and readU32(recordOffset) or nil

      local length = nameOffset and nameOffset >= 4 and readU32(nameOffset - 4) or nil

      if length and length > 0 and length <= MAX_STRING then
        local name = readText( nameOffset, length )
        if isPlausibleName(name) then names[index] = name end
      end

    end

  end

  if file then file:close() end
  return names
end

--- Parse version string
-- @param value any
local function parseVersionString(value)
  local a, b, c, d = tostring(value or ''):match( '(%d+)%.(%d+)%.(%d+)%.(%d+)' )
  if not a then a, b, c = tostring(value or ''):match('(%d+)%.(%d+)%.(%d+)') end

  if not a then return nil end

  return 
  {
    major = tonumber(a),
    minor = tonumber(b) or 0,
    release = tonumber(c) or 0,
    build = tonumber(d) or 0,
    source = 'executable-version',
    confidence = 'metadata'
  }
end

--- Define version
-- @param state table
function Runtime.Discovery.defineVersion(state)

  -- inferring independently, it might be inconsistent
  -- - executable resource labels the runner build;
  -- - GEN8 stores project metadata and may remain frozen
  -- - chunk presence supplies only a minimum data-format generation
  local directory = extractFilePath( state.module.PathToFile )
  local data

  for _, filename in ipairs( { 'data.win', 'game.unx', 'game.ios' } ) do
    
    local candidate = directory .. filename

    if fileExistsReadable(candidate) then
      data = Runtime.Discovery.readGameDataVersion( candidate )
      break
    end

  end

  if not data then
    data = Runtime.Discovery.readMappedGameDataVersion(state)
  end
  
  if not data then
    data = Runtime.Discovery.readEmbeddedGameDataVersion(state)
  end

  state.gameData = data

  if data then

    data.exact, data.exactError = readGameDataRuntimePathVersion(data)

    if not data.exact and data.embedded and not data.fileBase then

      local fileData = Runtime.Discovery.readEmbeddedGameDataVersion(state)

      if fileData then
        data.exact, data.exactError = readGameDataRuntimePathVersion(fileData)
      end

    end

    data.objectNames = readGameDataObjectNames(data)
  end

  local metadata = state.identity.versionMetadata or {}

  local metadataT = 
  {
    tostring(metadata.CompanyName or ''),
    tostring( metadata.ProductName or '' ),
    tostring( metadata.FileDescription or '' ),
    tostring( metadata.OriginalFilename or '' )
  }
  local metadataText = table.concat( metadataT, ' ' ):lower()

  if metadataText:find('gamemaker studio 2', 1, true) then
    state.profileHint = 'gms2'
  elseif metadataText:find('gamemaker studio 1', 1, true) then
    state.profileHint = 'gms1'
  end

  local executable = parseVersionString( state.identity.fileVersion )

  if not executable and tonumber( metadata.major ) then

    executable =
    {
      major = tonumber( metadata.major ),
      minor = tonumber( metadata.minor ) or 0,
      release = tonumber( metadata.release ) or 0,
      build = tonumber( metadata.build ) or 0,
      source = 'executable-version-components',
      confidence = 'metadata'
    }

  end

  executable = executable or parseVersionString( metadata.ProductVersion )

  if executable and not ( metadataText:find('yoyo', 1, true ) or metadataText:find( 'gamemaker', 1, true ) or metadataText:find( 'runner', 1, true ) ) then
    executable.confidence = 'unverified-game-executable'
  end

  -- runner metadata is normally preferred
  local selected, reason

  local genericGms2Version = state.profileHint == 'gms2'
                             and executable
                             and executable.major == 1
                             and executable.minor == 0
                             and executable.release == 0
                             and executable.build == 0

  if executable
     and executable.confidence == 'metadata'
     and not genericGms2Version
     and (executable.major == 1 or executable.major == 2 or executable.major >= 2022)
  then
    selected, reason = executable, 'executable version resource'
  elseif data and data.exact then
    selected, reason = data.exact, 'data.win compiler runtime path'
  elseif data and data.inferred then
    selected, reason = data.inferred, 'data.win feature lower bound'
  elseif data and data.stored then
    selected, reason = data.stored, 'stored GEN8 version'
  elseif genericGms2Version then
    selected, reason = executable, 'generic GMS2 executable version resource'
  end

  state.version = selected or { major = 0, minor = 0, release = 0, build = 0, source = 'unknown', confidence = 'unknown' }

  state.version.text = versionText(state.version)
  state.version.reason = reason or 'no reliable version metadata'
  state.versionEvidence =
  {
    executable = executable,
    gameData = data
  }

  return state.version
end

-- ///---///--///---///--///---///--///--///---///--///---///--///---///--///--///--///--///--///--///--///--///--///--///--/// RUNNER DISCOVERY

--- Unique module scan (readonly)
-- @param module table
-- @param pattern string
local function uniqueModuleScan(module, pattern)
  
  local moduleName = extractFileName( module and module.PathToFile or '' )

  if moduleName == '' then return nil end

  local address = AOBScanModuleUnique( moduleName, pattern, '-W-X-C' )

  if address and type(address) ~= 'number' then
    address = getAddressSafe(address)
  end

  return address
end

--- Is the process GM runner?
-- @param processId number
function Runtime.Discovery.couldBeGameMaker(processId)
  if processId and getOpenedProcessID() ~= processId then return false, {} end
  
  local module = Runtime.Memory.mainModule()
  if not module or not module.PathToFile then return false, {} end

  -- sidecar FORM file is strong enough by itself
  -- generic strings require several independent hits
  local evidence, score = {}, 0

  --- Add weighted evidence record
  -- @param kind string
  -- @param detail string
  -- @param weight number
  local function add(kind, detail, weight)
    evidence[#evidence + 1] =
    {
      kind = kind,
      detail = detail,
      weight = weight
    }
    score = score + weight
  end

  local sections = Runtime.Memory.sections(module)
  local image = sections and sections.image

  local directory = extractFilePath( module.PathToFile )
  local packagedRunner = directory .. 'compile\\' .. extractFileName(module.PathToFile)
  local text = sections and sections['.text']

  -- ? some packaged games start through a launcher
  if text and text.size < 0x10000 and fileExistsReadable(packagedRunner) then
    return false,
    {
      {
        kind = 'launcher-container',
        detail = packagedRunner,
        weight = -10
      }
    }
  end

  for _, filename in ipairs( { 'data.win', 'game.unx', 'game.ios' } ) do

    local path = directory .. filename

    if fileExistsReadable(path) then
      local formHeader = readFilePrefix(path, 4) == 'FORM'
      add( formHeader and 'game-data-form' or 'game-data-sidecar', filename, formHeader and 5 or 2 )
      break
    end

  end

  if score >= 5 then return true, evidence end


  local versionText, components = getFileVersion( module.PathToFile )

  local versionEvidence = tostring(versionText or '')
  
  if type(components) == 'table' then
    versionEvidence = table.concat(
      {
        versionEvidence,
        tostring(components.CompanyName or ''),
        tostring(components.ProductName or ''),
        tostring(components.FileDescription or ''),
        tostring(components.OriginalFilename or '')
      }, ' '
    )
  end

  local lower = versionEvidence:lower()

  if lower:find('yoyo', 1, true) or lower:find('gamemaker', 1, true) then
    add('version-resource', versionEvidence, 5)
  end


  if score >= 5 then return true, evidence end

  local markers =
  {
    {
      text = 'YoYo Games',
      weight = 4
    },
    {
      text = 'GameMaker',
      weight = 3
    },
    {
      text = 'show_debug_message',
      weight = 2
    },
    {
      text = 'room_goto',
      weight = 2
    },
  }

  for _, marker in ipairs(markers) do

    if processId and getOpenedProcessID() ~= processId then return false, {} end

    local address = uniqueModuleScan( module, bytePattern(marker.text) )

    if not address and image then
      local hits = Runtime.Memory.scan( bytePattern( marker.text ), image.start, image.finish - 1, nil, 1 )
      address = hits[1]
    end

    if address then
      add( 'image-string', marker.text, marker.weight )
    end

  end

  return score >= 4, evidence
end

local ANCHORS =
{
  'show_debug_message',
  'room_goto',
  'instance_create_depth',
  'variable_global_get',
  'ds_map_create',
  'array_length',
  'script_execute',
  '@@CopyStatic@@'
}

--- Runner evidence
-- @param state table
-- @param cancellation function|nil
function Runtime.Discovery.runnerEvidence(state, cancellation)
  local evidence = {}
  local image = state.sections.image

  local markers =
  {
    {
      text = 'GameMaker',
      weight = 2
    },
    {
      text = 'YoYo Games',
      weight = 2
    },
    {
      text = 'YoYo Runner',
      weight = 3
    },
    {
      text = 'data.win',
      weight = 1
    },
    {
      text = 'audiogroup1.dat',
      weight = 1
    },
    {
      text = 'game.unx',
      weight = 1
    }
  }

  local score = 0

  for _, marker in ipairs(markers) do
    local hits = Runtime.Memory.scan( bytePattern( marker.text ), image.start, image.finish - 1, nil, 1, cancellation )
    
    if #hits > 0 then

      evidence[#evidence + 1] =
      {
        marker = marker.text,
        address = hits[1],
        weight = marker.weight
      }

      score = score + marker.weight
    end

  end
  state.runnerEvidence = evidence
  state.runnerScore = score
  return score > 0
end

--- Read function entry
-- @param state table
-- @param address number
-- @param layout table
local function readFunctionEntry(state, address, layout)
  local name, routine, arguments, usage

  if layout.kind == 'reference' then

    local nameAddress = readPtr( address + layout.nameOffset )

    name = readCString( nameAddress, MAX_STRING )
    routine = readPtr( address + layout.routineOffset )
    arguments = readI32( address + layout.argumentOffset )
    usage = readI32( address + layout.usageOffset )

  elseif layout.kind == 'inline' then

    name = readCString( address + layout.nameOffset, 64 )
    routine = readPtr( address + layout.routineOffset )
    arguments = readI32( address + layout.argumentOffset )
    usage = readI32( address + layout.usageOffset )

  else
    return nil
  end

  if not isPlausibleName(name) then return nil end

  if not Runtime.Memory.isExecutable(state, routine) then return nil end

  if arguments == nil or arguments < -1 or arguments > 64 then return nil end

  return
  {
    address = address,
    name = name,
    routine = routine,
    argumentCount = arguments,
    usageCount = usage or 0
  }

end

--- Collect table (func)
-- @param state table
-- @param anchorEntry table
-- @param layout table
local function collectTable(state, anchorEntry, layout)
  local start = anchorEntry
  local misses = 0

  for _ = 1, MAX_FUNCTIONS do

    local previous = start - layout.stride

    if readFunctionEntry( state, previous, layout ) then
      start = previous
      misses = 0
    else
      misses = misses + 1
      if misses >= 1 then break end
    end
  end

  local functions, duplicates = {}, 0

  local byName = {}

  for index = 0, MAX_FUNCTIONS - 1 do

    local address = start + index * layout.stride
    local entry = readFunctionEntry( state, address, layout )

    if not entry then break end
    entry.index = index
    functions[#functions + 1] = entry

    if byName[entry.name] then
      duplicates = duplicates + 1
    else
      byName[entry.name] = entry
    end

  end
  return
  {
    start = start,
    layout = layout,
    functions = functions,
    byName = byName,
    duplicates = duplicates
  }
end

--- Table score
-- @param candidate table
local function tableScore(candidate)
  if not candidate then return -1 end
  local count = #candidate.functions
  local anchors = 0

  for _, name in ipairs(ANCHORS) do

    if candidate.byName[name] then
      anchors = anchors + 1
    end

  end

  return count + anchors * 100 - candidate.duplicates * 4
end

--- Read one x86 Function_Add call site
-- @param state table
-- @param address number
-- @param layout table
-- @return table|nil
local function readFunctionRegistration(state, address, layout)
  if state.pointerSize ~= 4 or layout.kind ~= 'registration' then return nil end

  local nameAddress = readPtr( address + layout.nameOffset )
  local routine = readPtr( address + layout.routineOffset )
  local arguments = signed8( readU8( address + layout.argumentOffset ) )
  local usage = signed8( readU8( address + layout.usageOffset ) )
  local callAddress = address + layout.callOffset
  local displacement = signed32( readI32( callAddress + 1 ) )
  local registrar = displacement and ( callAddress + 5 + displacement ) or nil
  local name = readCString( nameAddress, MAX_STRING )

  if readU8(address) ~= 0x6A or readU8(address + 2) ~= 0x6A then return nil end
  if readU8(address + 4) ~= 0x68 or readU8(address + 9) ~= 0x68 then return nil end
  if readU8(callAddress) ~= 0xE8 then return nil end

  if not isPlausibleName(name) then return nil end

  if not Runtime.Memory.isExecutable(state, routine) then return nil end
  if not Runtime.Memory.isExecutable(state, registrar) then return nil end
  
  if arguments == nil or arguments < -1 or arguments > 64 then return nil end
  if usage == nil or usage < 0 or usage > 8 then return nil end

  return
  {
    address = address,
    nameAddress = nameAddress,
    name = name,
    routine = routine,
    argumentCount = arguments,
    usageCount = usage,
    registrar = registrar
  }
end

--- Recover built-in function table from Function_Add calls
-- @param state table
-- @param layout table
-- @param cancellation function|nil
-- @return table|nil
local function collectFunctionRegistrations(state, layout, cancellation)
  local text = state.sections['.text'] or state.sections.image
  local matches = Runtime.Memory.scan( layout.pattern, text.start, text.finish - 1, '+X-W-C', 1, cancellation )

  -- GameMaker Studio 1.0 emits no contiguous RFunction array in the image.

  local groups = {}

  for _, address in ipairs(matches) do
    local entry = readFunctionRegistration( state, address, layout )

    if entry then
      local group = groups[entry.registrar]

      if not group then
        group =
        {
          registrar = entry.registrar,
          layout = layout,
          functions = {},
          byName = {},
          duplicates = 0,
          source = 'registration-stream'
        }
        groups[entry.registrar] = group
      end

      entry.index = #group.functions
      group.functions[#group.functions + 1] = entry

      if group.byName[entry.name] then
        group.duplicates = group.duplicates + 1
      else
        group.byName[entry.name] = entry
      end

    end

  end

  local candidates = {}

  for _, candidate in pairs(groups) do
    candidates[#candidates + 1] = candidate
  end

  table.sort( candidates, function(left, right) return tableScore(left) > tableScore(right) end )

  return candidates[1]
end

--- Function layouts selected by the active profile
-- @param state table
-- @return table
function Runtime.Discovery.functionLayouts(state)
  return state.profile.layouts.functionEntries
end

--- Find function table
-- @param state table
-- @param cancellation function|nil
function Runtime.Discovery.findFunctionTable(state, cancellation)
  local image = state.sections.image
  local candidates = {}
  local seen = {}

  local layouts = Runtime.Discovery.functionLayouts(state)

  local minimumCount = state.options.minimumFunctionCount or 32

  local registrationCandidate
  local registrationAttempted = false

  --- Try profiled Function_Add streams in preference order
  -- @return table|nil
  local function registrations()

    if registrationAttempted then
      return registrationCandidate
    end

    registrationAttempted = true

    for _, layout in ipairs(layouts) do
      if layout.kind ~= 'registration' then goto continue end

      local candidate = collectFunctionRegistrations( state, layout, cancellation )

      if not candidate or #candidate.functions < minimumCount then goto continue end

      candidate.score = tableScore(candidate)

      do -- for the label
        registrationCandidate = candidate
        return registrationCandidate
      end

      ::continue::
    end
  end

  -- GMS1 has no contiguous RFunction table
  -- its startup Function_Add calls are the table
  if layouts[1] and layouts[1].kind == 'registration' then
    local candidate = registrations()
    if candidate then return candidate end
  end

  -- modern runners are found from multiple built-in name anchors
  for _, anchor in ipairs(ANCHORS) do
    local pattern = bytePattern(anchor .. '\0')

    local stringHits = Runtime.Memory.scan( pattern, image.start, image.finish - 1, nil, 1, cancellation )

    local allStringHits = Runtime.Memory.scan( pattern, nil, nil, nil, 1, cancellation )

    local knownStrings = {}

    for _, address in ipairs(stringHits) do
      knownStrings[address] = true
    end

    for _, address in ipairs(allStringHits) do

      if knownStrings[address] then goto nextStringHit end

      stringHits[#stringHits + 1] = address
      knownStrings[address] = true

      ::nextStringHit::
    end

    for _, stringAddress in ipairs(stringHits) do

      for _, layout in ipairs(layouts) do

        if layout.kind == 'registration' then goto nextLayout end

        local entryHits

        if layout.kind == 'reference' then
          entryHits = Runtime.Memory.scan( pointerPattern( stringAddress, state.pointerSize ), nil, nil, nil, state.pointerSize, cancellation )
        else
          entryHits = { stringAddress }
        end

        for _, entryAddress in ipairs(entryHits) do

          local key = ('%X:%s'):format( entryAddress, layout.kind )

          if seen[key] then goto nextEntry end
          if not readFunctionEntry( state, entryAddress, layout ) then goto nextEntry end

          seen[key] = true
          candidates[#candidates + 1] = collectTable( state, entryAddress, layout )

          ::nextEntry::
        end

        ::nextLayout::
      end
    end

    -- re-score after each anchor
    table.sort(candidates,   function(left, right)  return tableScore(left) > tableScore(right)  end  )

    local best = candidates[1]

    if best and #best.functions >= minimumCount then
      local registered = state.pointerSize == 4 and registrations() or nil

      if registered and tableScore(registered) > tableScore(best) then
        return registered
      end

      best.score = tableScore(best)
      return best
    end
  end

  table.sort(candidates,   function(left, right)   return tableScore(left) > tableScore(right)   end   )

  local best = candidates[1]

  if not best or #best.functions < minimumCount then

    local candidate = registrations()
    if candidate then return candidate end

    return nil, ( 'No validated GM RFunction table found (best candidate: %d entries)'):format(best and #best.functions or 0)
  end

  best.score = tableScore(best)

  local registered = state.pointerSize == 4 and registrations() or nil

  if registered and tableScore(registered) > tableScore(best) then
    return registered
  end

  return best
end

--- Find the VM Code_Execute dispatcher
-- @param state table
-- @param cancellation function|nil
function Runtime.Discovery.findCodeExecute(state, cancellation)
  local patterns = state.profile.layouts.codeExecutePatterns

  local text = state.sections['.text'] or state.sections.image

  for _, pattern in ipairs(patterns) do

    local hits = Runtime.Memory.scan( pattern, text.start, text.finish - 1, '+X-W-C', 1, cancellation )

    for _, callAddress in ipairs(hits) do

      local displacement = readI32( callAddress + 1 )
      if displacement and displacement >= 0x80000000 then displacement = displacement - 0x100000000 end

      local target = displacement and ( callAddress + 5 + displacement ) or nil

      if target and rangeContains( text, target ) then
        return target, callAddress, pattern
      end

    end

  end

  return nil
end

--- Classify runner
-- @param state table
local function classifyRunner(state)

  local codeChunk = state.gameData and state.gameData.chunks and state.gameData.chunks.CODE

  local hasVm = state.codeExecute ~= nil or (codeChunk and codeChunk.size and codeChunk.size > 4)

  local hasYycNames = false

  for _, entry in ipairs( state.functionTable.functions ) do
    if entry.name:match('^gml_') then hasYycNames = true break end
  end

  if hasVm and hasYycNames then return 'hybrid/unknown' end
  if hasVm then return 'VM' end
  if hasYycNames then return 'YYC' end

  return 'unknown (runtime API discovered)'
end

--- Find compiled scripts
-- @param state table
-- @param cancellation function|nil
function Runtime.Discovery.findCompiledScripts(state, cancellation)

  if state.functionTable.layout.kind == 'registration' then
    local scripts = {}

    for _, entry in ipairs(state.functionTable.functions) do
      if entry.name:match('^gml_') then scripts[#scripts + 1] = entry end
    end

    table.sort( scripts, function(left, right) return left.name < right.name end )
    return scripts
  end

  local image = state.sections.image

  local hits = Runtime.Memory.scan( bytePattern('gml_Script_'), image.start, image.finish - 1, nil, 1, cancellation )

  local scripts, seen = {}, {}

  local layout = Runtime.Discovery.functionLayouts(state)[1]

  for _, stringAddress in ipairs(hits) do

    local name = readCString( stringAddress, MAX_STRING )

    if isPlausibleName(name) and not seen[name] then

      local refs = Runtime.Memory.scan( pointerPattern( stringAddress, state.pointerSize ), nil, nil, nil, state.pointerSize, cancellation )
      
      for _, reference in ipairs(refs) do

        local entry = readFunctionEntry( state, reference, layout )
        
        if entry and entry.name == name then
          seen[name] = true
          scripts[#scripts + 1] = entry
          break
        end

      end

    end

    if #scripts >= (state.options.maximumScripts or 4096) then break end
  end

  table.sort( scripts, function(a, b) return a.name < b.name end )
  return scripts
end

--- Built-in variable table layout selected by the active profile
-- @param state table
-- @return table
local function variableLayout(state)
  return state.profile.layouts.builtInVariables
end

--- Read variable entry
-- @param state table
-- @param address number
-- @param layout table
local function readVariableEntry(state, address, layout)

  local nameAddress = readPtr( address + layout.nameOffset )
  local name = readCString( nameAddress, MAX_STRING )

  if not isPlausibleName(name) then return nil end

  local getter = readPtr( address + layout.getterOffset )
  local setter = readPtr( address + layout.setterOffset )

  if (not getter or getter == 0) and (not setter or setter == 0) then return nil end
  if getter and getter ~= 0 and not Runtime.Memory.isExecutable( state, getter ) then return nil end
  if setter and setter ~= 0 and not Runtime.Memory.isExecutable( state, setter ) then return nil end

  local canSet = readU8( address + layout.canSetOffset )
  if canSet ~= nil and canSet ~= 0 and canSet ~= 1 then return nil end
  
  return
  {
    address = address,
    name = name,
    nameAddress = nameAddress,
    getter = getter,
    setter = setter,
    canSet = canSet == 1
  }
end

--- Collect variable table
-- @param state table
-- @param anchor number
-- @param layout table
local function collectVariableTable(state, anchor, layout)
  local start = anchor

  for _ = 1, 600 do
    local previous = start - layout.stride
    if not readVariableEntry( state, previous, layout ) then break end
    start = previous
  end

  local entries, byName = {}, {}

  for index = 0, 599 do

    local entry = readVariableEntry( state, start + index * layout.stride, layout )
    if not entry then break end
    entry.index = index
    entries[ #entries + 1 ] = entry
    byName[ entry.name ] = entry

  end

  return
  {
    start = start,
    layout = layout,
    entries = entries,
    byName = byName
  }
end

--- Read one x86 Variable_BuiltIn_Add call site
-- @param state table
-- @param address number
-- @param hasSetterPointer boolean
-- @return table|nil
local function readVariableRegistration(state, address, hasSetterPointer)

  if state.pointerSize ~= 4 or readU8(address) ~= 0x6A then return nil end

  local setterOpcode = readU8(address + 2)
  local getterOffset = hasSetterPointer and 8 or 5
  local setterOffset = hasSetterPointer and 3 or nil
  local nameOffset = hasSetterPointer and 13 or 10
  local callOffset = hasSetterPointer and 17 or 14

  if hasSetterPointer then
    
    if setterOpcode ~= 0x68 or readU8(address + 7) ~= 0x68 or readU8(address + 12) ~= 0x68 then return nil end

  elseif setterOpcode ~= 0x6A or readU8(address + 3) ~= 0 or readU8(address + 4) ~= 0x68 or readU8(address + 9) ~= 0x68 then
    
    return nil
  end

  local callAddress = address + callOffset

  if readU8(callAddress) ~= 0xE8 then return nil end

  local nameAddress = readPtr( address + nameOffset )
  local name = readCString( nameAddress, MAX_STRING )
  local getter = readPtr( address + getterOffset )
  local setter = setterOffset and readPtr( address + setterOffset ) or 0
  local displacement = signed32( readI32( callAddress + 1 ) )
  local registrar = displacement and ( callAddress + 5 + displacement ) or nil

  if not isPlausibleName(name) then return nil end

  if not Runtime.Memory.isExecutable( state, getter ) then return nil end

  if setter ~= 0 and not Runtime.Memory.isExecutable( state, setter ) then return nil end

  if not Runtime.Memory.isExecutable( state, registrar ) then return nil end

  return
  {
    address = address,
    nameAddress = nameAddress,
    name = name,
    getter = getter,
    setter = setter,
    canSet = setter ~= 0,
    registrar = registrar
  }
end

--- Recover early GMS1 built-in variables from Variable_BuiltIn_Add calls
-- @param state table
-- @param cancellation function|nil
-- @return table|nil
local function collectVariableRegistrations(state, cancellation)
  if state.pointerSize ~= 4 then return nil end

  local text = state.sections['.text'] or state.sections.image
  local variants =
  {
    {
      pattern = '6A * 6A 00 68 * * * * 68 * * * * E8 * * * *',
      hasSetterPointer = false
    },
    {
      pattern = '6A * 68 * * * * 68 * * * * 68 * * * * E8 * * * *',
      hasSetterPointer = true
    }
  }

  local groups = {}

  for _, variant in ipairs(variants) do

    local matches = Runtime.Memory.scan( variant.pattern, text.start, text.finish - 1, '+X-W-C', 1, cancellation )

    for _, address in ipairs(matches) do

      local entry = readVariableRegistration( state, address, variant.hasSetterPointer )

      if entry then
        local group = groups[entry.registrar]

        if not group then
          group =
          {
            start = nil,
            registrar = entry.registrar,
            layout = { kind = 'registration', stride = 0 },
            entries = {},
            byName = {},
            source = 'Variable_BuiltIn_Add stream'
          }
          groups[entry.registrar] = group

        end

        entry.index = #group.entries
        group.entries[#group.entries + 1] = entry
        if not group.byName[entry.name] then group.byName[entry.name] = entry end
      end

    end

  end

  local best, bestScore

  for _, candidate in pairs(groups) do

    local anchors = 0

    for _, name in ipairs({ 'background_color', 'room_width', 'id' }) do
      if candidate.byName[name] then anchors = anchors + 1 end
    end

    local score = #candidate.entries + anchors * 100

    if anchors > 0 and (not bestScore or score > bestScore) then
      best, bestScore = candidate, score
    end

  end

  if best and #best.entries >= 16 then return best end
end

--- Discover RVariableRoutine by its names
-- VM runners duplicate the names to the heap while YYC runners often retain image strings, so both ranges are searched
function Runtime.Discovery.findVariableTable(state, cancellation)
  local layout = variableLayout(state)
  local deadline = monotonicMilliseconds() + (state.options.instanceScanTimeoutMs or 15000)
  local timedOut = false
  
  --- Check cancellation callback
  local function cancelled()
    if cancellation and cancellation() then return true end
    
    if monotonicMilliseconds() >= deadline then
      timedOut = true
      return true
    end

    return false
  end

  -- primary: resolve fixed built-in array from Variable_BuiltIn_Add
  local fromRegistration = Runtime.Discovery.findVariableTableFromRegistration

  if fromRegistration then

    local candidate = fromRegistration( state, cancelled )
    
    if candidate then
      candidate.source = 'Variable_BuiltIn_Add'
      return candidate
    end

  end

  local registrationStream = collectVariableRegistrations( state, cancelled )
  if registrationStream then return registrationStream end

  -- fallback for runners whose registration code changed
  -- long names may be on the heap, but RVariableRoutine itself is static in the main image,
  -- so pointer searches are restricted to .data/the image
  local candidates, seen = {}, {}
  local dataRange = state.sections['.data'] or state.sections.image

  for _, anchorName in ipairs( { 'background_color', 'room_width' } ) do

    if cancelled() then break end

    local strings = Runtime.Memory.scan( bytePattern(anchorName .. '\0'), nil, nil, nil, 1, cancelled )
    
    for stringIndex, stringAddress in ipairs(strings) do
      
      if stringIndex > (state.options.maximumVariableStringHits or 32) or cancelled() then break end

      local references = Runtime.Memory.scan( pointerPattern( stringAddress, state.pointerSize ), dataRange.start, dataRange.finish - 1, nil, state.pointerSize, cancelled )
      
      for _, reference in ipairs(references) do
        
        if not seen[reference] then
          seen[reference] = true
          local entry = readVariableEntry( state, reference, layout )

          if entry and entry.name == anchorName then
            candidates[#candidates + 1] = collectVariableTable( state, reference, layout )
          end
          
        end

      end

    end

  end

  table.sort(candidates,
    function(a, b)
      --- Score a variable-registration candidate address
      -- @param value any
      local function score(value)
        local anchors = 0
        
        for _, name in ipairs( { 'background_color', 'room_width', 'id' } ) do

          if value.byName[name] then anchors = anchors + 1 end
        end

        return #value.entries + anchors * 100
      end

      return score(a) > score(b)
    end
  )

  local best = candidates[1]

  if not best or #best.entries < 16 then
    return nil, timedOut and 'RVariableRoutine scan timeout' or 'No validated RVariableRoutine table found'
  end

  best.source = 'bounded-name-reference'
  return best
end

--- Decoded instruction
-- @param address number
local function decodedInstruction(address)

  local size = getInstructionSize(address)
  if type(size) ~= 'number' or size < 1 or size > 15 then return nil end
  
  local line = disassemble(address)
  if type(line) ~= 'string' then return nil end
  
  local values = { splitDisassembledString(line) }
  local text = line
  
  for _, value in ipairs(values) do

    if type(value) == 'string' then
      local candidate = value:match('^%s*([%a]+)')

      if candidate and ( { mov = true, movsxd = true, test = true, je = true, jz = true, cmp = true, lea = true } )[ candidate:lower() ] then
        text = value
      end

    end
  end

  local mnemonic = text:match('^%s*([%a]+)')

  if not mnemonic or not ( { mov = true, movsxd = true, test = true, je = true, jz = true, cmp = true, lea = true } )[ mnemonic:lower() ] then
    mnemonic = line:match('%-%s*([%a]+)%s')
  end

  return
  {
    address = address,
    size = size,
    text = text,
    line = line,
    mnemonic = mnemonic and mnemonic:lower()
  }
end

--- Instruction memory address
-- @param instruction table
-- @param pointerSize number
local function instructionMemoryAddress(instruction, pointerSize)
  local address = instruction.address

  if pointerSize == 8 then
    local index = 0
    local first = readU8(address)

    if first and first >= 0x40 and first <= 0x4F then index = 1 end

    local opcode = readU8( address + index )
    local modrm = readU8( address + index + 1 )

    if (opcode == 0x8B or opcode == 0x8D) and modrm and (modrm & 0xC7) == 0x05 then

      local displacement = signed32( readI32(address + index + 2) )
      if displacement then return address + index + 6 + displacement end

    end

  end
  
  local expression = instruction.text:match( '%[([^%]]+)%]' ) or instruction.line:match( '%[([^%]]+)%]' )
  if not expression then return nil end

  expression = expression:gsub( '^%s*.-ptr%s+', '' ):gsub( '^%s*ds:', '' ):gsub( '%s+', '' )

  if expression:lower():find( 'rip', 1, true ) then return nil end

  return getAddressSafe(expression)
end

--- Find variable table from registration
-- @param state table
-- @param cancellation function|nil
function Runtime.Discovery.findVariableTableFromRegistration(state, cancellation)
  local text = state.sections['.text'] or state.sections.image

  local matches = Runtime.Memory.scan( 'F4 01 00 00 75 *', text.start, text.finish - 1, '+X-W-C', 1, cancellation )

  local layout = variableLayout(state)

  for _, match in ipairs(matches) do
    if cancellation and cancellation() then return nil end

    local jump = match + 4

    if readU8(jump) ~= 0x75 then goto nextMatch end

    local displacement = signed8( readU8( jump + 1 ) )

    local target = displacement and (jump + 2 + displacement) or nil

    if not target or not rangeContains( text, target ) then goto nextMatch end

    local cursor, candidates, seen = target, {}, {}

    while cursor < target + 0x80 and #candidates < 32 do
      local instruction = decodedInstruction(cursor)
      if not instruction then break end

      if instruction.mnemonic == 'lea' or instruction.mnemonic == 'movsxd' or instruction.mnemonic == 'mov' then
        local address = instructionMemoryAddress( instruction, state.pointerSize )
        
        if address and not seen[address] then
          seen[address] = true
          candidates[#candidates + 1] = address
        end

      end

      cursor = cursor + instruction.size
    end

    for _, address in ipairs(candidates) do

      for _, tableAddress in ipairs( { address, readPtr(address) } ) do

        if not tableAddress or tableAddress == 0 then goto nextTable end
        if not readVariableEntry( state, tableAddress, layout ) then goto nextTable end

        local candidate = collectVariableTable( state, tableAddress, layout )
        if #candidate.entries >= 16 and (candidate.byName.background_color or candidate.byName.room_width) then
          return candidate
        end

        ::nextTable::
      end
    end

    ::nextMatch::
  end

  return nil
end

--- Resolve global CRoom* used by a built-in room setter
-- YYToolkit's stable invariant is MOV [Run_Room], TEST, JZ in the first 0x50 bytes
function Runtime.Discovery.findRunRoomFromSetter(state, setter)
  if not setter or setter == 0 then return nil, 'room setter is unavailable' end

  local instructions, cursor = {}, setter

  while cursor < setter + 0x50 and #instructions < 32 do
    
    local instruction = decodedInstruction( cursor )

    if not instruction then break end
    instructions[#instructions + 1] = instruction
    cursor = cursor + instruction.size
  end

  local nullCandidate

  --- Validate and retain one Run_Room global candidate
  -- @param candidate table
  local function accept(candidate)
    if not candidate or candidate == 0 then return false end
    local room = readPtr(candidate)

    if not room or room == 0 then
      nullCandidate = nullCandidate or candidate
      return false
    end

    local roomHeader = state.profile.layouts.roomHeader
    local width, height = readI32(room + roomHeader.widthOffset), readI32( room + roomHeader.heightOffset )

    return width and height and width > 0 and width < 1000000 and height > 0 and height < 1000000
  end

  for index = 1, #instructions - 2 do
    local first, second, third = instructions[index], instructions[index + 1], instructions[index + 2]

    if first.mnemonic == 'mov' and second.mnemonic == 'test' and (third.mnemonic == 'je' or third.mnemonic == 'jz') then
      local candidate = instructionMemoryAddress( first, state.pointerSize )
      if accept(candidate) then return candidate, first.address end
    end

  end

  if state.pointerSize == 4 then

    for _, instruction in ipairs(instructions) do

      if instruction.mnemonic == 'mov' or instruction.mnemonic == 'cmp' then
        local candidate = instructionMemoryAddress( instruction, state.pointerSize )
        if accept(candidate) then return candidate, instruction.address end
      end

    end

  end

  if nullCandidate then return nullCandidate, nil end
  return nil, 'Run_Room reference was not found in the room setter'
end

-- ///---///--///---///--///---///--///--///---///--///---///--///---///--///--///--///--///--///--///--///--///--///--///--/// ROOMS & INSTANCES

--- Room layout candidates
-- @param state table
local function roomLayoutCandidates(state)
  local result = {}

  for index, layout in ipairs( state.profile.layouts.roomLayouts ) do

    result[index] =
    {
      name = layout.name,
      activeListOffset = layout.activeListOffset,
      roomInternalOffset = layout.roomInternalOffset,
      profile = state.profile.id,
    }

  end

  return result
end

--- Read room list
-- @param state table
-- @param room number
-- @param layout table
local function readRoomList(state, room, layout)

  -- CRoom owns an intrusive list header: first, last, count
  -- requiring empty endpoints to agree with count rejects random triples that merely contain a small integer in the candidate count position
  local list = room + layout.activeListOffset
  local first, last = readPtr(list), readPtr( list + state.pointerSize )

  local count = readI32( list + state.pointerSize * 2 )

  if count == nil or count < 0 or count > (state.options.maximumInstances or 100000) then return nil end

  if count == 0 then

    if (first or 0) ~= 0 or (last or 0) ~= 0 then return nil end

  elseif not first or first == 0 or not last or last == 0 then

    return nil
  end

  return
  {
    address = list,
    first = first or 0,
    last = last or 0,
    count = count
  }
end

--- Member offset candidates
-- @param state table
local function memberOffsetCandidates(state)
  return state.profile.layouts.instance.membersOffsets
end

--- Validate a candidate CObjectGM pointer in an instance
-- @param state table
-- @param instance table
-- @param membersOffset number
local function plausibleObjectAt(state, instance, membersOffset)
  -- m_Object precedes version-dependent CInstanceInternal union and doesnt move when SequenceInstance/SkeletonMask fields are added to that union
  -- YYToolkit's classic x64 YYObjectBase is 0x88, followed by create-counter, placing m_Object at 0x90 for every A8/B0/B8 member variant

  local objectOffset = state.profile.layouts.instance.objectOffset
  
  local object = readPtr( instance + objectOffset )
  if not object or object == 0 then return nil end

  local namePointer = readPtr(object)

  local name = readCString( namePointer, MAX_STRING )

  if not isPlausibleName(name) then return nil end

  return object, name, objectOffset
end

--- Finite motion number
-- @param value any
local function finiteMotionNumber(value)
  return type(value) == 'number' and value == value and math.abs(value) < 1000000000
end

--- CInstanceInternal can be 4-byte field in some builds after imageScaleY linked-list pointer remains at the same aligned offset
local function selectMotionOffsetShift(state, list, membersOffset, flinkRelative)
  if type(state.options.instanceMotionOffsetShift) == 'number' then
    return state.options.instanceMotionOffsetShift, { explicit = state.options.instanceMotionOffsetShift }
  end

  local candidates = state.profile.layouts.instance.motionShifts
  local scores, current, sampled = {}, list.first, 0

  for _, shift in ipairs(candidates) do scores[shift] = 0 end

  -- Score several instances
  while current and current ~= 0 and sampled < math.min(list.count, 16) do

    local base = current + membersOffset

    for _, shift in ipairs(candidates) do

      local angle = readF32( base + 0x2C + shift )
      local alpha = readF32( base + 0x30 + shift )
      local x, y = readF32( base + 0x38 + shift ), readF32( base + 0x3C + shift )

      local previousX, previousY = readF32( base + 0x48 + shift ), readF32( base + 0x4C + shift )

      if finiteMotionNumber(angle)
         and finiteMotionNumber(alpha)
         and finiteMotionNumber(x)
         and finiteMotionNumber(y)
         and finiteMotionNumber(previousX)
         and finiteMotionNumber(previousY)
      then
        
        local score = 8
        if alpha >= 0 and alpha <= 1.001 then score = score + 4 else score = score - 8 end
        if math.abs(angle) <= 360000 then score = score + 1 end
        
        local delta = math.abs(x - previousX) + math.abs(y - previousY)
        score = score - math.min(delta, 1000000) / 1000
        scores[shift] = scores[shift] + score
      else
        scores[shift] = scores[shift] - 100
      end

    end

    sampled = sampled + 1
    current = readPtr( current + membersOffset + flinkRelative )
  end

  local selected = candidates[1]

  for index = 2, #candidates do
    if scores[candidates[index]] > scores[selected] + 0.25 then selected = candidates[index] end
  end

  scores.sampled = sampled
  return selected, scores
end

--- Validate instance layout
-- @param state table
-- @param list table
-- @param membersOffset number
-- @param flinkRelative number
local function validateInstanceLayout(state, list, membersOffset, flinkRelative)
  if list.count == 0 then return nil end

  local current, visited, final = list.first, 0, 0
  local limit = math.min( list.count, state.options.maximumInstances or 100000 )

  -- The list is accepted only when traversal count, final node, and null tail all agree with the room header
  while current and current ~= 0 and visited < limit do

    if visited < 8 and not plausibleObjectAt( state, current, membersOffset ) then return nil end

    local id = readI32( current + membersOffset + 4 )

    local objectIndex = readI32( current + membersOffset + 8 )
    
    if id == nil or id < 0 or objectIndex == nil or objectIndex < -1 or objectIndex > 10000000 then return nil end
    
    visited = visited + 1
    final = current
    current = readPtr( current + membersOffset + flinkRelative )
  end

  if visited ~= list.count or final ~= list.last or (current or 0) ~= 0 then return nil end

  local _, _, objectOffset = plausibleObjectAt( state, list.first, membersOffset )

  local motionOffsetShift, motionValidationScores = selectMotionOffsetShift( state, list, membersOffset, flinkRelative )

  return
  {
    name = ('CInstance.members@%X'):format(membersOffset),
    membersOffset = membersOffset,
    flinkOffset = membersOffset + flinkRelative,
    objectOffset = objectOffset,
    motionOffsetShift = motionOffsetShift,
    motionValidationScores = motionValidationScores,
    validated = true
  }
end

--- Validate GMS1 CInstance layout with direct field offsets
-- @param state table
-- @param list table
-- @param candidate table
-- @return table|nil
local function validateDirectInstanceLayout(state, list, candidate)

  local objectNames = state.gameData and state.gameData.objectNames or {}

  local current, previous, final, visited = list.first, 0, 0, 0

  -- GMS1 CInstance layout is different, no CObjectGM pointer at the modern offset.
  -- Object indices are validated against data.win names, while both directions of the active list prove the direct link offsets
  while current and current ~= 0 and visited < list.count do

    local instanceId = readI32( current + candidate.idOffset )

    local objectIndex = readI32( current + candidate.objectIndexOffset )

    local objectName = objectIndex and objectNames[objectIndex] or nil

    local previousLink = readPtr( current + candidate.previousOffset ) or 0

    local x, y = readF32( current + candidate.xOffset ), readF32( current + candidate.yOffset )

    if not instanceId or instanceId < 0 or not objectName then return nil end

    if previousLink ~= previous then return nil end

    if not finiteMotionNumber(x) or not finiteMotionNumber(y) then return nil end

    visited = visited + 1
    final, previous = current, current
    current = readPtr( current + candidate.nextOffset )
  end

  if visited ~= list.count or final ~= list.last or (current or 0) ~= 0 then return nil end

  local layout = {}
  for key, value in pairs(candidate) do layout[key] = value end
  layout.direct = true
  layout.flinkOffset = candidate.nextOffset
  layout.validated = true
  return layout
end

--- Select instance layout
-- @param state table
-- @param list any
local function selectInstanceLayout(state, list)
  if list.count == 0 then return nil end

  for _, candidate in ipairs( state.profile.layouts.instance.directLayouts or {} ) do
    local layout = validateDirectInstanceLayout( state, list, candidate )
    if layout then return layout end
  end
  
  if type(state.options.instanceMembersOffset) == 'number' then
    
    local relative = state.options.instanceFlinkRelative
    
    if type(relative) ~= 'number' and type(state.options.instanceFlinkOffset) == 'number' then
      relative = state.options.instanceFlinkOffset - state.options.instanceMembersOffset
    end

    relative = relative or state.profile.layouts.instance.flinkRelatives[1]
    return validateInstanceLayout( state, list, state.options.instanceMembersOffset, relative )
  end

  local flinkRelatives = state.profile.layouts.instance.flinkRelatives

  for _, membersOffset in ipairs(memberOffsetCandidates(state)) do

    for _, flinkRelative in ipairs(flinkRelatives) do

      local layout = validateInstanceLayout( state, list, membersOffset, flinkRelative )
      if layout then return layout end
    end

  end

  return nil
end

--- Collect executable relative-call targets from a small x86 routine
-- @param state table
-- @param address number
-- @param length number
-- @return table
local function relativeCallTargets(state, address, length)
  local result = {}

  for offset = 0, length - 5 do

    if readU8(address + offset) == 0xE8 then

      local displacement = signed32( readI32( address + offset + 1 ) )

      local target = displacement and address + offset + 5 + displacement or nil

      if Runtime.Memory.isExecutable( state, target ) then
        
        result[#result + 1] =
        {
          address = address + offset,
          target = target,
          offset = offset
        }
      end

    end

  end

  return result
end

--- Find GMS1 user-variable name registry
-- @param state table
-- @return table|nil
-- @return string|nil
local function discoverGms1VariableReflection(state)
  if state.pointerSize ~= 4 then return nil, 'GMS1 reflection requires an x86 runner' end

  local entry = state.functionTable and state.functionTable.byName and state.functionTable.byName.variable_local_get
  if not entry or not entry.routine then return nil, 'variable_local_get is unavailable' end

  -- variable_local_get is stable semantic anchor. Its short wrapper calls a name-to-ID resolver, which calls the user-variable registry lookup.
  local wrapperCalls = relativeCallTargets( state, entry.routine, 0x60 )
  if #wrapperCalls < 1 then return nil, 'variable_local_get name resolver was not found' end

  for _, wrapperCall in ipairs(wrapperCalls) do

    local resolver = wrapperCall.target

    local resolverCalls = relativeCallTargets( state, resolver, 0x40 )

    for _, resolverCall in ipairs(resolverCalls) do

      local registryLookup = resolverCall.target
      local globals, seen = {}, {}

      -- GMS1 loads registry globals with x86 absolute MOV instructions
      -- The candidates are not trusted until one behaves as a bounded count and the other as a char** containing plausible GML identifiers
      for offset = 0, 0x40 - 6 do

        if readU8( registryLookup + offset ) ~= 0x8B then goto nextOffset end

        local modrm = readU8( registryLookup + offset + 1 )
        if not modrm or (modrm & 0xC7) ~= 0x05 then goto nextOffset end

        local address = readPtr( registryLookup + offset + 2 )
        if not address or address == 0 or seen[address] then goto nextOffset end

        seen[ address ] = true
        globals[ #globals + 1 ] = address

        ::nextOffset::
      end

      for _, countAddress in ipairs(globals) do

        local count = readI32(countAddress)
        if not count or count <= 0 or count > 1000000 then goto nextCount end

        for _, arrayAddress in ipairs(globals) do

          if arrayAddress == countAddress then goto nextArray end

          local names = readPtr(arrayAddress)
          if not names or names == 0 then goto nextArray end

          local plausible = 0

          for index = 0, math.min(count, 16) - 1 do

            local namePointer = readPtr( names + index * 4 )
            local name = namePointer and readCString( namePointer, MAX_STRING ) or nil

            if isPlausibleVariableName(name) then
              plausible = plausible + 1
            end
          end

          if plausible < math.min(count, 2) then goto nextArray end

          do -- for labels
            return
            {
              available = true,
              source = 'variable_local_get registry',
              nameResolver = resolver,
              registryLookup = registryLookup,
              nameCountAddress = countAddress,
              nameArrayAddress = arrayAddress,
              idBase = 100000,
            }
          end

          ::nextArray::
        end

        ::nextCount::
      end
    end
  end

  return nil, 'GMS1 user-variable registry globals didnt validate'
end

--- Validate GMS1 global bucket-map candidate against the name registry
-- @param state table
-- @param storage number
-- @param layout table
-- @param reflection table
-- @return boolean
local function validateGms1GlobalStorage(state, storage, layout, reflection)
  if not storage or storage == 0 then return false end

  local nameCount = readI32( reflection.nameCountAddress )
  local names = readPtr( reflection.nameArrayAddress )

  if not nameCount or nameCount <= 0 or nameCount > 1000000 or not names or names == 0 then return false end

  local validated = 0

  for bucket = 0, layout.variableBucketCount - 1 do

    local node = readPtr( storage + layout.variableBucketOffset + bucket * state.pointerSize )

    local chainLength = 0

    while node and node ~= 0 do

      chainLength = chainLength + 1

      if chainLength > 100000 then return false end

      local variableId = readI32( node + layout.variableNodeIdOffset )
      local nameIndex = variableId and variableId - (layout.variableIdBase or reflection.idBase) or -1

      if nameIndex < 0 or nameIndex >= nameCount then return false end

      local namePointer = readPtr( names + nameIndex * state.pointerSize )
      local name = namePointer and readCString( namePointer, MAX_STRING ) or nil

      if not isPlausibleVariableName( name ) then return false end

      if not Runtime.Reflection.decodeLegacyRValue( node + layout.variableNodeValueOffset ) then return false end

      validated = validated + 1
      if validated >= 2 then return true end

      node = readPtr( node + layout.variableNodeNextOffset )
    end
  end

  return validated > 0
end

--- Discover GMS1 global variable container
-- variable_global_get calls a small wrapper which loads the global container through an x86 absolute mov ecx,[address]
-- The object has same bucket/node format as instance variables
-- @param state table
-- @param layout table
-- @param reflection table
-- @return table|nil
-- @return string|nil
local function discoverGms1GlobalStorage(state, layout, reflection)

  if not layout or not layout.direct then return nil, 'GMS1 instance layout unavailable' end

  if not reflection then return nil, 'GMS1 variable name registry unavailable' end

  local entry = state.functionTable and state.functionTable.byName and state.functionTable.byName.variable_global_get

  if not entry or not entry.routine then return nil, 'variable_global_get unavailable' end

  for _, callSite in ipairs( relativeCallTargets( state, entry.routine, 0x80 ) ) do

    local wrapper = callSite.target

    for offset = 0, 0x40 - 6 do

      if readU8( wrapper + offset ) ~= 0x8B or readU8( wrapper + offset + 1 ) ~= 0x0D then goto nextOffset end

      local pointerAddress = readPtr( wrapper + offset + 2 )

      local storage = pointerAddress and readPtr(pointerAddress) or nil

      if validateGms1GlobalStorage( state, storage, layout, reflection ) then

        return
        {
          available = true,
          source = 'variable_global_get container',
          pointerAddress = pointerAddress,
          address = storage,
        }
      end

      ::nextOffset::
    end
  end

  return nil, 'GMS1 global variable container wasnt discovered'
end


--- Find instance runtime
-- @param state table
-- @param cancellation function|nil
function Runtime.Discovery.findInstanceRuntime(state, cancellation)
  local result = { available = false }
  state.instances = result

  -- Dependency chain
  --   built-in variable table -> room-related setter -> Run_Room global -> active-list layout -> CInstance layout -> optional named reflection
  -- each failed step records a capability error
  local variableError

  state.variableTable, variableError = Runtime.Discovery.findVariableTable( state, cancellation )
  result.variableTableError = variableError

  local runRoom

  if type(state.options.runRoomAddress) == 'number' then

    runRoom = state.options.runRoomAddress
    result.runRoomSource = 'explicit'
  elseif state.variableTable then

    local roomVariable = state.variableTable.byName.background_color or state.variableTable.byName.room_width

    if roomVariable then
      runRoom, result.runRoomInstruction = Runtime.Discovery.findRunRoomFromSetter( state, roomVariable.setter )
      result.runRoomSource = roomVariable.name .. ' setter'
    end

  end

  if not runRoom then

    result.error = variableError and ('Run_Room wasnt discovered: ' .. variableError) or 'Run_Room wasnt discovered'
    return result
  end

  result.runRoomAddress = runRoom

  local room = readPtr(runRoom)

  result.currentRoom = room or 0

  if not room or room == 0 then
    result.error = 'Run_Room is valid but no room is currently active'
    return result
  end

  local candidates = roomLayoutCandidates(state)

  if type( state.options.roomActiveListOffset ) == 'number' then
    table.insert( candidates, 1, { name = 'explicit', activeListOffset = state.options.roomActiveListOffset } )
  end

  result.layoutAttempts = {}

  -- version profile orders room candidates but never selects one directly
  -- active-list header and complete instance traversal must validate first
  for _, roomLayout in ipairs(candidates) do

    local list = readRoomList( state, room, roomLayout )
    
    local attempt =
    {
      roomLayout = roomLayout.name,
      activeListOffset = roomLayout.activeListOffset,
      listValid = list ~= nil,
      count = list and list.count or nil
    }
    
    result.layoutAttempts[ #result.layoutAttempts + 1 ] = attempt
    
    if list then

      local instanceLayout = selectInstanceLayout( state, list )

      attempt.instanceLayoutValid = list.count == 0 or instanceLayout ~= nil

      if list.count == 0 or instanceLayout then

        result.roomLayout, result.list, result.instanceLayout = roomLayout, list, instanceLayout

        if instanceLayout and instanceLayout.direct then
          result.variableReflection, result.variableReflectionError = discoverGms1VariableReflection(state)

          if result.variableReflection then
            local globals

            globals, result.globalStorageError = discoverGms1GlobalStorage( state, instanceLayout, result.variableReflection )
            state.globals = globals or { kind = 'gms1', error = result.globalStorageError }

            if globals then globals.kind = 'gms1' end
          else
            result.globalStorageError = result.variableReflectionError
            state.globals = { kind = 'gms1', error = result.globalStorageError }
          end

        end

        result.available = true
        result.validated = list.count > 0
        return result
      end

    end

  end

  local details = {}

  for _, attempt in ipairs( result.layoutAttempts ) do

    details[#details + 1] = ('%s@+0x%X:list=%s,count=%s,instance=%s'):format(
                                                                              attempt.roomLayout,
                                                                              attempt.activeListOffset,
                                                                              tostring(attempt.listValid),
                                                                              tostring(attempt.count or 'n/a'),
                                                                              tostring(attempt.instanceLayoutValid or false)
                                                                            ) -- TODO: debug mode
  end
  result.error = 'Current room was found, but no room/instance layout passed validation (' .. table.concat(details, '; ') .. ')'
  return result
end

--- Read validated instance header through generation layout
-- @param state table
-- @param address number
-- @param layout table
-- @return table|nil
local function readInstanceHeader(state, address, layout)
  
  if layout.direct then

    local objectIndex = readI32( address + layout.objectIndexOffset )

    local objectName = objectIndex and state.gameData and state.gameData.objectNames and state.gameData.objectNames[objectIndex] or nil

    local instanceId = readI32( address + layout.idOffset )

    if not objectName or not instanceId then return nil end

    return
    {
      address = address,
      id = instanceId,
      object = 0x100000000 + objectIndex,
      objectSynthetic = true,
      objectIndex = objectIndex,
      objectName = objectName,
      spriteIndex = readI32( address + layout.spriteIndexOffset ),
      imageIndex = readF32( address + layout.imageIndexOffset ),
      imageSpeed = readF32( address + layout.imageSpeedOffset ),
      imageScaleX = readF32( address + layout.imageScaleXOffset ),
      imageScaleY = readF32( address + layout.imageScaleYOffset ),
      imageAngle = readF32( address + layout.imageAngleOffset ),
      imageAlpha = readF32( address + layout.imageAlphaOffset ),
      imageBlend = readI32( address + layout.imageBlendOffset ),
      x = readF32( address + layout.xOffset ),
      y = readF32( address + layout.yOffset ),
      xStart = readF32( address + layout.xStartOffset ),
      yStart = readF32( address + layout.yStartOffset ),
      xPrevious = readF32( address + layout.xPreviousOffset ),
      yPrevious = readF32( address + layout.yPreviousOffset ),
      legacyVariableStorage = true
    }
  end

  local object, objectName = plausibleObjectAt( state, address, layout.membersOffset )
  if not object then return nil end

  local instanceProfile = state.profile.layouts.instance

  return
  {
    address = address,
    id = readI32( address + layout.membersOffset + 4 ),
    objectIndex = readI32( address + layout.membersOffset + 8 ),
    spriteIndex = readI32( address + layout.membersOffset + 12 ),
    object = object,
    objectName = objectName,
    yyVars = readPtr( address + instanceProfile.yyVarsOffset ),
    variableMap = readPtr( address + instanceProfile.variableMapOffset ),
    variableCount = readI32( address + instanceProfile.variableCountOffset ),
    variableCapacity = readI32( address + instanceProfile.variableCapacityOffset ),
    x = readF32( address + layout.membersOffset + 0x38 + (layout.motionOffsetShift or 0) ),
    y = readF32( address + layout.membersOffset + 0x3C + (layout.motionOffsetShift or 0) )
  }
end

--- Enumerate active instances in the current room
-- @param state table
function Runtime.Instances.list(state)

  local runtime = state.instances
  if not runtime or not runtime.available then return nil, runtime and runtime.error or 'instance runtime unavailable' end

  local room = readPtr( runtime.runRoomAddress )
  if not room or room == 0 then return {}, 'no active room' end
  
  local list = readRoomList( state, room, runtime.roomLayout )
  if not list then return nil, 'active instance list no longer validates; rescan the runtime' end
  
  local layout = runtime.instanceLayout or selectInstanceLayout( state, list )

  if list.count > 0 and not layout then return nil, 'CInstance layout couldnt be validated from the active room' end

  if layout then runtime.instanceLayout = layout end

  local instances, current, seen = {}, list.first, {}
  
  while current and current ~= 0 and #instances < list.count do

    if seen[current] then return nil, 'cycle detected in active instance list' end
    seen[current] = true

    local instance = readInstanceHeader( state, current, layout )
    if not instance then return nil, ('invalid CInstance header at 0x%X'):format(current) end

    instances[#instances + 1] = instance
    current = readPtr( current + layout.flinkOffset )
  end

  runtime.currentRoom, runtime.list = room, list

  return instances
end

--- Walk the active list
-- Object asset pointers survive individual instance destruction/recreation
function Runtime.Instances.findActiveTargets(state, objectAddresses, instanceIds, objectNames)

  local runtime = state.instances
  if not runtime or not runtime.available then return nil, runtime and runtime.error or 'instance runtime unavailable' end

  local room = readPtr( runtime.runRoomAddress )
  if not room or room == 0 then
    return
    {
      instances = {},
      byObjectAddress = {},
      byObjectName = {},
      byId = {},
      room = 0
    }
  end

  local list = readRoomList(state, room, runtime.roomLayout)
  if not list then return nil, 'active instance list no longer validates; rescan the runtime' end

  local layout = runtime.instanceLayout or selectInstanceLayout( state, list )

  if list.count > 0 and not layout then return nil, 'CInstance layout couldnt be validated from the active room' end

  if layout then runtime.instanceLayout = layout end

  local result =
  {
    instances = {},
    byObjectAddress = {},
    byObjectName = {},
    byId = {},
    room = room,
    count = list.count
  }

  local current = list.first

  runtime.objectNameByAddress = runtime.objectNameByAddress or {}

  local objectNameByAddress = runtime.objectNameByAddress

  local needsObjectNames = objectNames and next(objectNames) ~= nil

  for _ = 1, list.count do

    if not current or current == 0 then return nil, 'active instance list ended before its declared count' end

    local header = readInstanceHeader( state, current, layout )

    if not header then return nil, 'active instance header is unreadable' end

    local object, instanceId = header.object, header.id

    local objectName = objectAddresses and objectAddresses[object] or nil

    if needsObjectNames and not objectName then

      local candidate = header.objectName or objectNameByAddress[object]

      if not candidate and not layout.direct then

        local namePointer = readPtr(object)

        candidate = namePointer and readCString( namePointer, MAX_STRING ) or nil

        if candidate and isPlausibleName(candidate) then
          objectNameByAddress[object] = candidate
        end

      end

      if candidate and objectNames[candidate] then
        objectName = candidate
      end

    end

    if (objectAddresses and objectAddresses[object]) or objectName or (instanceIds and instanceIds[instanceId]) then

      local instance = header

      instance.objectName = objectName or header.objectName

      result.instances[ #result.instances + 1 ] = instance

      result.byId[instanceId] = instance
      local matches = result.byObjectAddress[object] or {}
      matches[ #matches + 1 ] = instance
      result.byObjectAddress[object] = matches

      if objectName then
        local namedMatches = result.byObjectName[objectName] or {}
        namedMatches[ #namedMatches + 1 ] = instance
        result.byObjectName[ objectName ] = namedMatches
      end

    end

    current = readPtr( current + layout.flinkOffset )
  end

  if current and current ~= 0 then return nil, 'active instance list exceeds its declared count' end

  runtime.currentRoom, runtime.list = room, list
  return result
end

--- Read sparse variable map
-- @param state table
-- @param address number
-- @param maximum number
local function readSparseVariableMap(state, address, maximum)
  
  if not address or address == 0 then
    return nil, 'sparse variable map is null'
  end

  local currentSize = readI32( address )
  local usedCount = readI32( address + 4 )
  local currentMask = readI32( address + 8 )
  local growThreshold = readI32( address + 0xC )
  local elements = readPtr( address + 0x10 )
  local maximumBuckets = tonumber( state.options.maximumVariableMapBuckets ) or 0x100000

  if not currentSize
     or currentSize < 0
     or not usedCount
     or usedCount < 0
     or not currentMask
     or currentMask < 0
     or currentMask + 1 > maximumBuckets
     or usedCount > currentMask + 1
     or ( usedCount > 0 and ( not elements or elements == 0 ) )
  then
    return nil, 'sparse variable map header is invalid'
  end

  local limit = math.min(usedCount, tonumber(maximum) or tonumber(state.options.maximumRawVariables) or 0x1000)

  local mapLayout = state.profile.layouts.sparseVariableMap

  local stride = mapLayout.stride

  local keyOffset, hashOffset = mapLayout.keyOffset, mapLayout.hashOffset
  
  local variables = {}

  -- YYObjectBase's sparse map stores a pointer to each populated RValue beside
  -- its runtime slot and hash.  Empty buckets have hash zero and are skipped;
  -- the slot-domain count on CInstance is not the number of populated buckets.
  for bucket = 0, currentMask do

    local element = elements + bucket * stride
    local hash = readI32(element + hashOffset)

    if hash and hash ~= 0 then
      local valueAddress = readPtr(element)
      local slot = signed32( readI32( element + keyOffset ) )
      local decoded, decodeError
      
      if valueAddress and valueAddress ~= 0 then
        decoded, decodeError = Runtime.Reflection.decodeRValue(valueAddress)
      else
        decodeError = 'sparse variable value pointer is null'
      end
      
      if decoded then
        decoded.slot, decoded.hash, decoded.bucket = slot, hash & 0xFFFFFFFF, bucket
        variables[#variables + 1] = decoded
      else
        variables[#variables + 1] = { slot = slot, hash = hash & 0xFFFFFFFF, bucket = bucket, address = valueAddress, error = decodeError }
      end
      
      if #variables >= limit then break end
    end

  end

  return
  {
    address = address,
    currentSize = currentSize,
    usedCount = usedCount,
    currentMask = currentMask,
    bucketCount = currentMask + 1,
    growThreshold = growThreshold,
    elements = elements,
    variables = variables,
    truncated = #variables < usedCount,
  }
end

--- Enumerate YYObjectBase RValue storage
-- Instances may use either a dense m_YYVars array (can be null) or sparse m_YYVarsMap
local function resolveVariableNames(state, storage)
  local resolved = storage
  local resolver = state.resolveInstanceVariableNames
  local authorityAvailable = false

  if type(resolver) == 'function' then
    local bridgeResolved, resolverError = resolver(storage)

    if bridgeResolved then
      resolved = bridgeResolved
      authorityAvailable = true
    else
      storage.nameResolutionError = resolverError
    end
  end

  local resolvedCount = 0

  for _, variable in ipairs(resolved.variables or {}) do
    if variable.name then resolvedCount = resolvedCount + 1 end
  end

  resolved.resolvedNameCount = resolvedCount
  resolved.namesAvailable = authorityAvailable and resolvedCount == #(resolved.variables or {})

  if resolved.namesAvailable then
    resolved.nameResolutionError = nil
  end

  return resolved
end

--- Enumerate reflected user variables from (early) GMS1 CInstance
-- @param state table
-- @param instance table
-- @param maximum number|nil
-- @return table|nil
-- @return string|nil
local function listGms1Variables(state, instance, maximum)
  
  local runtime = state.instances
  
  local layout = runtime and runtime.instanceLayout
  
  local reflection = runtime and runtime.variableReflection

  if not layout or not layout.direct then return nil, 'GMS1 CInstance layout unavailable' end

  if not reflection then
    reflection, runtime.variableReflectionError = discoverGms1VariableReflection(state)
    runtime.variableReflection = reflection
  end

  if not reflection then return nil, runtime.variableReflectionError or 'GMS1 variable reflection unavailable' end

  -- GMS1 stores user variables in 64 intrusive bucket chains owned directly by CInstance
  -- null map is a valid instance with no user-defined fields
  local storage = instance.legacyVariableMap or readPtr( instance.address + layout.variableStorageOffset )

  if not storage or storage == 0 then
    return
    {
      instance = instance,
      storageKind = 'gms1-bucket-map',
      variableMap = storage or 0,
      variableCount = 0,
      variableCapacity = 0,
      namesAvailable = true,
      resolvedNameCount = 0,
      variables = {},
      map =
      {
        address = storage or 0,
        bucketCount = layout.variableBucketCount,
        usedCount = 0
      },
    }
  end

  -- the registry array can be reallocated as names are introduced,
  -- reread both globals for every enumeration
  local nameCount = readI32( reflection.nameCountAddress )
  local names = readPtr( reflection.nameArrayAddress )

  if not nameCount or nameCount < 0 or nameCount > 1000000 or not names or names == 0 then return nil, 'GMS1 user-variable name registry no longer validates' end

  local variables, visited = {}, {}
  local limit = tonumber(maximum) or tonumber(state.options.maximumRawVariables) or 0x1000
  local bucketCount = layout.variableBucketCount

  for bucket = 0, bucketCount - 1 do
    local node = readPtr( storage + layout.variableBucketOffset + bucket * state.pointerSize )
    local chainLength = 0

    while node and node ~= 0 do
      
      if visited[node] then return nil, 'cycle detected in GMS1 variable bucket map' end
      visited[node] = true
      
      chainLength = chainLength + 1
      
      if chainLength > 100000 then return nil, 'GMS1 variable bucket chain is invalid' end

      -- runtime IDs are authoritative keys
      -- GMS1 allocates user IDs from idBase and indexes the global name array by their zero-based remainder
      local variableId = readI32( node + layout.variableNodeIdOffset )
      local nameIndex = variableId and variableId - (layout.variableIdBase or reflection.idBase) or -1
      
      if nameIndex < 0 or nameIndex >= nameCount then return nil, ('GMS1 variable ID %s is outside the runtime name registry'):format( tostring(variableId) ) end

      local namePointer = readPtr( names + nameIndex * state.pointerSize )
      local name = namePointer and readCString( namePointer, MAX_STRING ) or nil
      
      if not isPlausibleVariableName(name) then return nil, ('GMS1 variable ID %d has invalid runtime name'):format( variableId ) end

      local rvalueAddress = node + layout.variableNodeValueOffset

      local decoded, decodeError = Runtime.Reflection.decodeLegacyRValue( rvalueAddress )
      if not decoded then return nil, decodeError end

      decoded.slot = variableId
      decoded.name = name
      decoded.bucket = bucket
      decoded.node = node
      
      variables[ #variables + 1 ] = decoded
      
      if #variables >= limit then break end
      node = readPtr( node + layout.variableNodeNextOffset )
    end

    if #variables >= limit then break end
  end

  return
  {
    instance = instance,
    storageKind = 'gms1-bucket-map',
    variableMap = storage,
    variableCount = #variables,
    variableCapacity = #variables,
    truncated = #variables >= limit,
    namesAvailable = true,
    resolvedNameCount = #variables,
    variables = variables,
    map =
    {
      address = storage,
      elements = storage + layout.variableBucketOffset,
      bucketCount = bucketCount,
      usedCount = #variables,
    },
  }
end

--- List variables raw
-- @param state table
-- @param selector any
-- @param maximum number
-- @param includeNames any
-- @param knownInstances any
function Runtime.Instances.listVariablesRaw(state, selector, maximum, includeNames, knownInstances)
  
  -- on modern targets reflection comes from game-threaded 'api'. GMS1 names come from its live ID registry
  local instances, listError = knownInstances or Runtime.Instances.list(state)
  if not instances then return nil, listError end
  
  local selected
  
  local requestedAddress = type(selector) == 'table' and selector.address or selector
  local requestedId = type(selector) == 'table' and selector.id or selector
  
  for _, instance in ipairs(instances) do

    if selector == instance or requestedAddress == instance.address or requestedId == instance.id then
      selected = instance
      break
    end

  end
  
  if not selected then return nil, 'instance isnt in the current active-room list' end
  if selected.legacyVariableStorage then return listGms1Variables( state, selected, maximum ) end

  local count, capacity = selected.variableCount, selected.variableCapacity

  if not count or count < 0 or count > 1000000 then return nil, 'YYObjectBase variable count is invalid' end
  if not capacity or capacity < count or capacity > 10000000 then return nil, 'YYObjectBase variable capacity is invalid' end

  -- either a dense array or a sparse map, they are mutually exclusive storage views for the same runtime slot domain
  if selected.yyVars and selected.yyVars ~= 0 then

    local limit = math.min( count, tonumber(maximum) or tonumber( state.options.maximumRawVariables ) or 0x1000 )
    local variables = {}

    for slot = 0, limit - 1 do
      local decoded, decodeError = Runtime.Reflection.decodeRValue( selected.yyVars + slot * 16 )

      if decoded then
        decoded.slot = slot
        variables[ #variables + 1 ] = decoded
      else
        variables[ #variables + 1 ] = { slot = slot, error = decodeError }
      end

    end

    local storage =
    {
      instance = selected,
      storageKind = 'dense-array',
      yyVars = selected.yyVars,
      variableMap = selected.variableMap,
      variableCount = count,
      variableCapacity = capacity,
      truncated = limit < count,
      namesAvailable = false,
      variables = variables,
    }

    return includeNames == false and storage or resolveVariableNames(state, storage)
  end

  local sparse, sparseError = readSparseVariableMap( state, selected.variableMap, maximum )
  
  if not sparse then

    if count == 0 then
      sparse =
      {
        variables = {},
        usedCount = 0,
        truncated = false
      }
    else
      return nil, sparseError
    end

  end

  local storage =
  {
    instance = selected,
    storageKind = 'sparse-map',
    yyVars = selected.yyVars,
    variableMap = selected.variableMap,
    variableCount = count,
    variableCapacity = capacity,
    truncated = sparse.truncated,
    namesAvailable = false,
    map = sparse,
    variables = sparse.variables,
  }
  return includeNames == false and storage or resolveVariableNames(state, storage)
end

--- Build a descriptor for the target global scope
-- @param state table
-- @return table|nil
-- @return string|nil
function Runtime.Globals.instance(state)
  local globals = state.globals

  if globals and globals.kind == 'gms1' and not globals.pointerAddress then

    local runtime = state.instances

    local discovered, discoveryError = discoverGms1GlobalStorage( state, runtime and runtime.instanceLayout, runtime and runtime.variableReflection )
    if not discovered then
      globals.error = discoveryError
      return nil, discoveryError
    end

    discovered.kind = 'gms1'
    state.globals = discovered
    globals = discovered
  end

  if globals and globals.pointerAddress then

    local address = readPtr( globals.pointerAddress )
    if not address or address == 0 then return nil, 'GMS1 global variable container unavailable' end

    globals.address = address

    return
    {
      address = address,
      id = -5,
      object = address,
      objectName = 'global',
      legacyVariableStorage = true,
      legacyVariableMap = address,
      globalScope = true,
    }
  end

  globals = globals or {}
  state.globals = globals

  local instanceProfile = state.profile and state.profile.layouts and state.profile.layouts.instance
  if not instanceProfile then return nil, 'global YYObjectBase profile unavailable' end

  local function header(address)
    if not address or address == 0 then return nil end

    local count = readI32( address + instanceProfile.variableCountOffset )
    local capacity = readI32( address + instanceProfile.variableCapacityOffset )

    if not count or count < 0 or count > 1000000 then return nil end
    if not capacity or capacity < count or capacity > 10000000 then return nil end

    return
    {
      address = address,
      id = -5,
      object = address,
      objectName = 'global',
      yyVars = readPtr( address + instanceProfile.yyVarsOffset ),
      variableMap = readPtr( address + instanceProfile.variableMapOffset ),
      variableCount = count,
      variableCapacity = capacity,
      globalScope = true,
    }
  end

  local instance = header( globals.address )
  if instance then return instance end

  if type(state.resolveGlobalObject) ~= 'function' then return nil, globals.error or 'global-scope reflection unavailable' end

  local address, resolveError = state.resolveGlobalObject()
  instance = header(address)

  if not instance then return nil, resolveError or 'runner returned invalid global scope' end

  globals.available = true
  globals.source = '@@GlobalScope@@'
  globals.address = address

  return instance
end

--- Enumerate user-defined global variables
-- @param state table
-- @param maximum number|nil
-- @param includeNames boolean|nil
-- @return table|nil
-- @return string|nil
function Runtime.Globals.listVariablesRaw(state, maximum, includeNames)
  
  local instance, instanceError = Runtime.Globals.instance( state )
  if not instance then return nil, instanceError end

  return Runtime.Instances.listVariablesRaw( state, instance, maximum, includeNames, { instance } )
end

--- Find a user-defined global variable
-- @param state table
-- @param nameOrSlot string|number
-- @return table|nil
-- @return string|nil
function Runtime.Globals.findVariable(state, nameOrSlot)

  local storage, storageError = Runtime.Globals.listVariablesRaw( state, nil, type(nameOrSlot) == 'string' )
  if not storage then return nil, storageError end

  for _, variable in ipairs(storage.variables or {}) do

    if ( type(nameOrSlot) == 'string' and variable.name == nameOrSlot ) or ( type(nameOrSlot) == 'number' and variable.slot == nameOrSlot ) then
      return variable
    end

  end

  return nil, 'global variable not found: ' .. tostring(nameOrSlot)
end

--- Find variable
-- @param state table
-- @param selector any
-- @param nameOrSlot number
function Runtime.Instances.findVariable(state, selector, nameOrSlot)

  local storage, storageError = Runtime.Instances.listVariablesRaw( state, selector, nil, type(nameOrSlot) == 'string' )
  if not storage then return nil, storageError end

  if type(nameOrSlot) == 'string' and not storage.namesAvailable then return nil, storage.nameResolutionError or 'authoritative variable names unavailable; use num slot fallback' end

  local matches = {}

  for _, variable in ipairs(storage.variables) do

    if ( type(nameOrSlot) == 'number' and variable.slot == nameOrSlot ) or ( type(nameOrSlot) == 'string' and variable.name == nameOrSlot ) then
      matches[ #matches + 1 ] = variable
    end

  end

  if #matches == 0 then return nil, ('instance variable %s isnt populated'):format( tostring(nameOrSlot) ) end

  if #matches > 1 then return nil, ('instance variable %s ambiguous (%d populated slots)'):format( tostring(nameOrSlot), #matches ) end

  local result = matches[1]
  result.storageKind = storage.storageKind
  result.instance = storage.instance
  result.storage = storage
  return result
end

-- ///---///--///---///--///---///--///--///---///--///---///--///---///--///--///--///--///--///--///--///--///--///--///--/// INITIALIZATION & REFLECTION

--- Release snapshot
-- @param state table
function Runtime.Instances.releaseSnapshot(state)

  local runtime = state and state.instances
  if not runtime then return end

  for _, address in ipairs( runtime.snapshotAddresses or {} ) do
    deAlloc(address)
  end

  runtime.snapshotAddresses, runtime.snapshotAddress = {}, nil
end

--- Create snapshot
-- @param state table
function Runtime.Instances.createSnapshot(state)

  local instances, listError = Runtime.Instances.list(state)
  if not instances then return nil, listError end

  if #instances == 0 then
    return
    {
      address = 0,
      instances = instances,
      size = 0
    }
  end

  local size = #instances * state.pointerSize

  local address = allocateMemory(size)

  if not address or address == 0 then return nil, 'failed to allocate the instance pointer snapshot' end

  for index, instance in ipairs(instances) do
    writePointer( address + (index - 1) * state.pointerSize, instance.address )
  end

  state.instances.snapshotAddresses = state.instances.snapshotAddresses or {}
  state.instances.snapshotAddresses[ #state.instances.snapshotAddresses + 1 ] = address
  state.instances.snapshotAddress = address
  return
  {
    address = address,
    instances = instances,
    size = size
  }
end

--- Scan & init GM runtime
-- @param options table
-- @param cancellation function|nil
function Runtime.initialize(options, cancellation)
  
  options = options or {}
  
  local module = Runtime.Memory.mainModule()

  -- capture process traits
  local sections, sectionError = Runtime.Memory.sections(module)
  if not sections then return nil, sectionError end

  local state =
  {
    module = module,
    sections = sections,
    identity = Runtime.Memory.executableIdentity(module),
    pointerSize = targetIs64Bit() and 8 or 4,
    options = options,
  }

  -- collect version/evidence, select a profile; profile offsets remain vague until validated
  Runtime.Discovery.defineVersion(state)
  
  state.profile = Versioning.resolve( { version = state.version , pointerSize = state.pointerSize , profileHint = state.profileHint } )
  
  Runtime.Discovery.runnerEvidence( state, cancellation )

  -- built-in function registry is the mandatory reflection root
  local tableResult, tableError

  if type( options.functionTableAddress ) == 'number' then
    
    local selectedLayout

    for _, layout in ipairs( Runtime.Discovery.functionLayouts(state) ) do

      if layout.kind ~= 'registration' and (not options.functionEntryKind or options.functionEntryKind == layout.kind) then
        selectedLayout = layout
        break
      end

    end

    if not selectedLayout then return nil, 'functionEntryKind must select a contiguous reference / inline table' end

    tableResult = collectTable( state, options.functionTableAddress, selectedLayout )

    if #tableResult.functions < (options.minimumFunctionCount or 1) then return nil, 'Explicit function table didnt validate with the selected layout' end

    tableResult.source = 'explicit'
  else
    tableResult, tableError = Runtime.Discovery.findFunctionTable( state, cancellation )
  end

  if not tableResult then
    local text = state.sections['.text']
    local packagedRunner = extractFilePath( state.module.PathToFile ) .. 'compile\\' .. extractFileName( state.module.PathToFile )

    if text and text.size < 0x10000 and fileExistsReadable(packagedRunner) then return nil, 'attached exe is a launcher/container; attach the process: ' .. packagedRunner end

    return nil, tableError
  end

  state.functionTable = tableResult

  -- optional execution/script capabilities
  if type(options.codeExecuteAddress) == 'number' then
    state.codeExecute = options.codeExecuteAddress
    state.codeExecutePattern = 'explicit'
  else
    state.codeExecute, state.codeExecuteCall, state.codeExecutePattern = Runtime.Discovery.findCodeExecute( state, cancellation )
  end

  state.scripts = options.scanScripts == false and {} or Runtime.Discovery.findCompiledScripts( state, cancellation )
  state.runnerKind = classifyRunner(state)

  -- rooms & instances are an optional here (eg init before a room exists)
  if options.scanInstances ~= false then
    Runtime.Discovery.findInstanceRuntime( state, cancellation )
  end

  state.ready = true
  return state
end

--- Find function
-- @param state table
-- @param name string
function Runtime.Reflection.findFunction(state, name)
  return state and state.functionTable and state.functionTable.byName[ name ] or nil
end

--- List functions
-- @param state table
-- @param pattern string
function Runtime.Reflection.listFunctions(state, pattern)
  local result = {}

  pattern = pattern and pattern:lower() or nil

  for _, entry in ipairs( state and state.functionTable and state.functionTable.functions or {} ) do

    if not pattern or entry.name:lower():find(pattern, 1, true) then
      result[ #result + 1 ] = entry
    end
  end

  return result
end

local RVALUE_KINDS =
{
  [0] = 'real',
  [1] = 'string',
  [2] = 'array',
  [3] = 'pointer',
  [4] = 'vec3',
  [5] = 'undefined',
  [6] = 'object',
  [7] = 'int32',
  [8] = 'vec4',
  [9] = 'matrix',
  [10] = 'int64',
  [11] = 'accessor',
  [12] = 'null',
  [13] = 'bool',
  [14] = 'iterator',
  [15] = 'ref',
}

--- Resolve a numeric RValue kind name
-- @param kind string
function Runtime.Reflection.rvalueKindName(kind)
  return RVALUE_KINDS[kind] or ('unknown_%s'):format(tostring(kind))
end

--- Decode RValue from address
-- @param address number
function Runtime.Reflection.decodeRValue(address)
  local kind = readI32( address + 12 )
  local flags = readI32( address + 8 )

  if kind == nil then return nil, 'Unreadable RValue at ' .. tostring(address) end
  local result =
  {
    address = address,
    kind = kind,
    kindName = Runtime.Reflection.rvalueKindName(kind),
    flags = flags
  }

  if kind == 0 then
    result.value = readDouble(address)
  elseif kind == 7 or kind == 13 then
    result.value = readI32(address)
  elseif kind == 10 then
    result.value = readQword(address)
  elseif kind == 1 then
    result.pointer = readPtr(address) -- GM strings require YYGetString, pointer is just a representation
  else
    result.pointer = readPtr(address)
  end

  return result
end

--- Decode 16-byte GMS1 RValue
-- kind precedes payload, ptr-sized values begin at +4, doubles & int64 values are aligned at +8
-- @param address number
-- @return table|nil
-- @return string|nil
function Runtime.Reflection.decodeLegacyRValue(address)
  
  local rawType = readI32(address)
  
  local kind = rawType and (rawType & 0x00FFFFFF) or nil
  
  if kind == nil or kind > 15 then return nil, 'Unreadable legacy RValue at ' .. tostring(address) end

  local valueOffset = (kind == 0 or kind == 10) and 8 or 4

  local result =
  {
    address = address + valueOffset,
    rvalueAddress = address,
    valueOffset = valueOffset,
    rawType = rawType & 0xFFFFFFFF,
    kind = kind,
    kindName = Runtime.Reflection.rvalueKindName(kind),
    flags = rawType & 0xFF000000,
  }

  if kind == 0 then
    result.value = readDouble( address + 8 )
  elseif kind == 7 or kind == 13 then
    result.value = readI32( address + 4 )
  elseif kind == 10 then
    result.value = readQword( address + 8 )
  else
    result.pointer = readPtr( address + 4 )
  end

  return result
end

-- ///---///--///---///--///---///--///--///---///--///---///--///---///--///--///--///--///--///--///--///--///--///--///--/// OBJECT DUMPING

--- Dump address
-- @param state table
-- @param address number
local function dumpAddress(state, address)
  if not address then return 'null' end

  return state.pointerSize == 8 and ('0x%016X'):format(address) or ('0x%08X'):format(address)
end

--- Dump name
-- @param value any
local function dumpName(value)
  value = tostring(value or '<unnamed>'):gsub('[\r\n\t]', ' ')

  return value ~= '' and value or '<unnamed>'
end

--- Dump value
-- @param state table
-- @param variable table
local function dumpValue(state, variable)

  if variable.error then return '<error: ' .. dumpName( variable.error ) .. '>' end

  if variable.kindName == 'bool' then return variable.value == 0 and 'false' or 'true' end

  if variable.value ~= nil then return tostring( variable.value ) end

  if variable.pointer ~= nil then return dumpAddress( state, variable.pointer ) end

  return '<unreadable>'
end

--- Default object dump path
-- @param state table
local function defaultObjectDumpPath(state)

  local directory = extractFilePath( state.identity.path or '' )

  local stem = extractFileNameWithoutExt( state.identity.name or 'game' ):gsub( '[^%w_.-]', '_' )

  return directory .. stem .. '-GMDumper-Objects.txt'
end

--- Write runtime object & gameplay-field dump
-- @param state table
-- @param outputPath string
-- @param options table
function Runtime.Dump.objects(state, outputPath, options)
  -- member names are reflected once per object layout and reused by numeric slot for sibling instances.
  -- second bridge query is made only when an instance introduces unseen slots

  options = options or {}

  local instances, listError = Runtime.Instances.list(state)
  if not instances then return nil, listError end

  -- selection is completed before the file is opened
  local pattern = options.pattern and tostring( options.pattern ):lower() or nil

  local maximumInstances = tonumber( options.maximumInstances ) or #instances

  local selected = {}

  for _, instance in ipairs(instances) do

    if #selected >= maximumInstances then break end

    if not pattern or instance.objectName:lower():find( pattern, 1, true ) or tostring( instance.id ) == pattern then
      selected[ #selected + 1 ] = instance
    end

  end

  -- group by asset identity
  local groups, byKey = {}, {}

  for _, instance in ipairs(selected) do

    local key = ('%s\0%d\0%X'):format( instance.objectName, instance.objectIndex or -1, instance.object or 0 )

    local group = byKey[key]

    if not group then
      group =
      {
        name = instance.objectName,
        objectIndex = instance.objectIndex,
        object = instance.object,
        objectSynthetic = instance.objectSynthetic == true,
        instances = {},
        names = {},
        seenSlots = {}
      }

      byKey[key], groups[#groups + 1] = group, group

    end

    group.instances[ #group.instances + 1 ] = instance
  end

  table.sort(groups,
    function(a, b)
      local an, bn = a.name:lower(), b.name:lower()
      if an ~= bn then
        return an < bn
      end

      if a.objectIndex ~= b.objectIndex then
        return (a.objectIndex or -1) < (b.objectIndex or -1)
      end

      return (a.object or 0) < (b.object or 0)
    end
  )

  for _, group in ipairs(groups) do

    table.sort(group.instances,
      function(a, b)

        if a.id ~= b.id then
          return (a.id or -1) < (b.id or -1)
        end

        return a.address < b.address
      end
    )

  end

  -- Global vars arent inside the instance list.
  -- Resolve them independently
  local includeGlobals = options.includeGlobals ~= false

  local globalStorage
  local globalError

  if includeGlobals then
    globalStorage, globalError = Runtime.Globals.listVariablesRaw( state, options.maximumGlobalVariables or options.maximumVariables, true )
  end

  outputPath = outputPath or defaultObjectDumpPath(state)

  local file, openError = io.open(outputPath, 'wb')
  if not file then return nil, openError end

  file:setvbuf( 'full', 1024 * 1024 )

  --- Write CRLF-terminated dump line
  -- @param value any
  local function line(value)
    file:write(value or '', '\r\n')
  end

  local stats =
  {
    objectCount = #groups,
    instanceCount = #selected,
    globalAvailable = globalStorage ~= nil,
    globalFieldCount = 0,
    globalError = globalError,
    fieldCount = 0,
    errorCount = 0
  }

  local ok, writeError = xpcall(
    function()
      local globalSummary = not includeGlobals and 'omitted' or globalStorage and tostring( #(globalStorage.variables or {}) ) or 'unavailable'

      line('// GMDumper global, object & instance fields')
      
      line(
            ('// Exe: %s | Runner: %s | Ver: %s | Arch: %s')
            :format( dumpName( state.identity.path ), dumpName( state.runnerKind ), dumpName( state.version and state.version.text ), state.pointerSize == 8 and 'x86_64' or 'x86')
          )

      line(('// Objects: %d | Instances: %d | Globals: %s | Reflected fields'):format( #groups, #selected, globalSummary ) )
      line()

      if globalStorage then
        local globalInstance = globalStorage.instance or {}

        line( ('global // addr=%s storage=%s populated=%d slots=%d capacity=%d')
              :format(
                       dumpAddress( state, globalInstance.address ),
                       globalStorage.storageKind or 'unknown',
                       #(globalStorage.variables or {}),
                       globalStorage.variableCount or -1,
                       globalStorage.variableCapacity or -1
                     )
            )

        line('{')

        if globalStorage.nameResolutionError then
          line('  // Name reflection unavailable: ' .. dumpName( globalStorage.nameResolutionError ) )
        end

        table.sort( globalStorage.variables,
          function(a, b)
            local an = (a.name or ''):lower()
            local bn = (b.name or ''):lower()

            if an ~= bn then return an < bn end

            return (a.slot or -1) < (b.slot or -1)
          end
        )

        for _, variable in ipairs( globalStorage.variables ) do
          local name = variable.name or ( 'slot_' .. tostring(variable.slot) )

          local location = ('slot=%d/0x%X'):format( variable.slot or -1, (variable.slot or 0) & 0xFFFFFFFF )

          if variable.bucket ~= nil then
            location = location .. (' bucket=%d'):format( variable.bucket )
          end

          line( ('  %s %-11s %-40s = %s; // %s%s')
                :format(
                          dumpAddress( state, variable.address ),
                          dumpName( variable.kindName or 'unknown' ),
                          dumpName(name),
                          dumpValue( state, variable ),
                          location,
                          variable.name and '' or ' name=unresolved'
                        )
              )

          stats.globalFieldCount = stats.globalFieldCount + 1
          stats.fieldCount = stats.fieldCount + 1
        end

        line('}')
        line()

      elseif includeGlobals then
        line('// Global scope unavailable: ' .. dumpName( globalError ) )
        line()
      end

      for _, group in ipairs(groups) do

        local descriptor = group.objectSynthetic and 'synthetic' or dumpAddress( state, group.object )

        line( ('object %s // index=%d descriptor=%s instances=%d'):format( dumpName( group.name ), group.objectIndex or -1, descriptor, #group.instances ) )
        line('{')

        for _, instance in ipairs(group.instances) do

          local storage, storageError = Runtime.Instances.listVariablesRaw( state, instance, options.maximumVariables, false, instances )

          if storage then
            -- modern bridge reflection is shared per object shape.
            -- resolve once, ask again only when another instance introduces an unseen slot
            -- GMS1 fields already carry authoritative registry names and skip this
            
            local needsNames = not group.nameResolutionFailed and next( group.seenSlots ) == nil

            if not needsNames and not group.nameResolutionFailed then

              for _, variable in ipairs( storage.variables ) do

                if not group.seenSlots[ variable.slot ] then
                  needsNames = true
                  break
                end

              end

            end

            if needsNames then

              local named, namedError = Runtime.Instances.listVariablesRaw( state, instance, options.maximumVariables, true, instances )

              if named then
                storage = named

                for _, variable in ipairs( named.variables ) do
                  group.seenSlots[ variable.slot ] = true
                  
                  if variable.name then
                    group.names[variable.slot] = variable.name
                  end
                end

                if named.nameResolutionError then
                  group.nameResolutionFailed = true
                  group.nameResolutionError = named.nameResolutionError
                end

              else
                group.nameResolutionFailed = true
                group.nameResolutionError = namedError
                storage.nameResolutionError = namedError
              end

            end

            line( ('  inst %d // addr=%s pos=(%.3f, %.3f) storage=%s populated=%d slots=%d capacity=%d')
                  :format(
                           instance.id or -1,
                           dumpAddress( state, instance.address ),
                           instance.x or 0,
                           instance.y or 0,
                           storage.storageKind or 'unknown',
                           #(storage.variables or {}),
                           storage.variableCount or -1,
                           storage.variableCapacity or -1
                        )
                )

            line('  {')

            if storage.nameResolutionError then
              line('    // Name reflection unavailable: ' .. dumpName( storage.nameResolutionError ) )
            end

            table.sort( storage.variables,
              function(a, b)
                local an = (a.name or group.names[a.slot] or ''):lower()

                local bn = (b.name or group.names[b.slot] or ''):lower()

                if an ~= bn then return an < bn end

                return (a.slot or -1) < (b.slot or -1)
              end)

            for _, variable in ipairs( storage.variables ) do

              local name = variable.name or group.names[ variable.slot ] or ( 'slot_' .. tostring(variable.slot) )

              local location = ('slot=%d/0x%X'):format( variable.slot or -1, (variable.slot or 0) & 0xFFFFFFFF )

              if variable.bucket ~= nil then
                location = location .. (' bucket=%d'):format( variable.bucket )
              end

              line( ('    %s %-11s %-40s = %s; // %s%s')
                    :format(
                            dumpAddress(state, variable.address),
                            dumpName(variable.kindName or 'unknown'),
                            dumpName(name),
                            dumpValue(state, variable),
                            location,
                            (variable.name or group.names[variable.slot]) and '' or ' name=unresolved'
                          )
                  )

              stats.fieldCount = stats.fieldCount + 1
            end

            line('  }')

          else

            line(('  inst %d // addr=%s ERROR: %s'):format( instance.id or -1, dumpAddress( state, instance.address ), dumpName( storageError ) ) )
            stats.errorCount = stats.errorCount + 1
          end

          line()
        end

        line('}')

        line()
      end
    end,
    debug.traceback
  )

  file:close()

  if not ok then return nil, writeError end

  stats.path = outputPath

  return outputPath, stats
end

-- ///---///--///---///--///---///--///--///---///--///---///--///---///--///--///--///--///--///--///--///--///--///--///--/// CE STRUCTURES

--- Create instance layouts
-- @param state table
function Runtime.Structures.createInstanceLayouts(state)
  
  --- Add element to the structure
  -- @param structure table
  -- @param nameText string
  -- @param offset number
  -- @param vartype any
  -- @param child any
  local function field(structure, nameText, offset, vartype, child)
    local element = structure.addElement()
    element.Name = nameText
    element.Offset = offset
    element.Vartype = vartype
    if child then
      element.ChildStruct = child
    end
    return element
  end

  local instanceLayout = state.instances and state.instances.instanceLayout

  -- GMS1 CInstance predates YYObjectBase; its variable storage is incompatible with modern dense/sparse RValue containers
  if instanceLayout and instanceLayout.direct then
    local instance = createStructure('CInstance.GMS1')
    field( instance, 'InstanceID', instanceLayout.idOffset, vtDword ).DisplayMethod = 'dtSignedInteger'
    field( instance, 'ObjectIndex', instanceLayout.objectIndexOffset, vtDword ).DisplayMethod = 'dtSignedInteger'
    field( instance, 'SpriteIndex', instanceLayout.spriteIndexOffset, vtDword ).DisplayMethod = 'dtSignedInteger'
    field( instance, 'ImageIndex', instanceLayout.imageIndexOffset, vtSingle )
    field( instance, 'ImageSpeed', instanceLayout.imageSpeedOffset, vtSingle )
    field( instance, 'ImageScaleX', instanceLayout.imageScaleXOffset, vtSingle )
    field( instance, 'ImageScaleY', instanceLayout.imageScaleYOffset, vtSingle )
    field( instance, 'ImageAngle', instanceLayout.imageAngleOffset, vtSingle )
    field( instance, 'ImageAlpha', instanceLayout.imageAlphaOffset, vtSingle )
    field( instance, 'ImageBlend', instanceLayout.imageBlendOffset, vtDword )
    field( instance, 'X', instanceLayout.xOffset, vtSingle )
    field( instance, 'Y', instanceLayout.yOffset, vtSingle )
    field( instance, 'XStart', instanceLayout.xStartOffset, vtSingle )
    field( instance, 'YStart', instanceLayout.yStartOffset, vtSingle )
    field( instance, 'XPrevious', instanceLayout.xPreviousOffset, vtSingle )
    field( instance, 'YPrevious', instanceLayout.yPreviousOffset, vtSingle )
    field( instance, 'NextActive', instanceLayout.nextOffset, vtPointer, instance )
    field( instance, 'PreviousActive', instanceLayout.previousOffset, vtPointer, instance )
    
    return
    {
      instance = instance
    }
  end

  local cString = createStructure('CString')
  local characters = cString.addElement()
  characters.Name = 'Characters'
  characters.Offset = 0
  characters.Vartype = vtString
  characters.ByteSize = MAX_STRING

  local rvalue = createStructure('RValue')
  local value = rvalue.addElement()
  value.Name = 'Value'
  value.Offset = 0
  value.Vartype = vtQword

  local flags = rvalue.addElement()
  flags.Name = 'Flags'
  flags.Offset = 8
  flags.Vartype = vtDword

  local kind = rvalue.addElement()
  kind.Name = 'Kind'
  kind.Offset = 12
  kind.Vartype = vtDword

  local rawSlots = createStructure('Variables.RawSlots')

  local rawSlotCount = math.max( 1, math.min( tonumber( state.options.rawVariableSlots ) or 64, 512 ) )

  for slot = 0, rawSlotCount - 1 do
    local slotOffset = slot * 16

    local raw = rawSlots.addElement()
    raw.Name = ('[%03d] RawValue'):format(slot)
    raw.Offset = slotOffset
    raw.Vartype = vtQword

    local asDouble = rawSlots.addElement()
    asDouble.Name = ('[%03d] AsDouble'):format(slot)
    asDouble.Offset = slotOffset
    asDouble.Vartype = vtDouble

    local slotKind = rawSlots.addElement()
    slotKind.Name = ('[%03d] Kind'):format(slot)
    slotKind.Offset = slotOffset + 12
    slotKind.Vartype = vtDword
  end

  local rawBuckets = createStructure('Variables.SparseBuckets')

  local rawBucketCount = math.max( 1, math.min( tonumber( state.options.rawVariableMapBuckets ) or 64, 512 ) )
  local mapProfile = state.profile.layouts.sparseVariableMap
  local bucketStride = mapProfile.stride

  for bucket = 0, rawBucketCount - 1 do
    local bucketOffset = bucket * bucketStride

    field( rawBuckets, ('[%03d] Value'):format( bucket ), bucketOffset, vtPointer, rvalue )
    field( rawBuckets, ('[%03d] Slot'):format( bucket ), bucketOffset + mapProfile.keyOffset, vtDword ).DisplayMethod = 'dtSignedInteger'
    field( rawBuckets, ('[%03d] Hash'):format( bucket ), bucketOffset + mapProfile.hashOffset, vtDword )
  end

  local variableMap = createStructure('Variables.SparseMap')
  field( variableMap, 'CurrentSize', 0, vtDword )
  field( variableMap, 'UsedCount', 4, vtDword )
  field( variableMap, 'CurrentMask', 8, vtDword )
  field( variableMap, 'GrowThreshold', 0xC, vtDword )
  field( variableMap, ('Buckets (only first %d raw)'):format( rawBucketCount ), 0x10, vtPointer, rawBuckets )

  local yyObject = createStructure('YYObjectBase')
  local instanceProfile = state.profile.layouts.instance

  field( yyObject, 'vTable', 0, vtPointer )
  field( yyObject, ('DenseYYVars (optional; first %d slots)'):format( rawSlotCount ), instanceProfile.yyVarsOffset, vtPointer, rawSlots )
  field( yyObject, 'ObjectListNext', instanceProfile.objectListNextOffset, vtPointer, yyObject )
  field( yyObject, 'ObjectListPrev', instanceProfile.objectListPreviousOffset, vtPointer, yyObject )
  field( yyObject, 'Prototype', instanceProfile.prototypeOffset, vtPointer, yyObject )
  field( yyObject, 'ClassName', instanceProfile.classNameOffset, vtPointer, cString )
  field( yyObject, 'SparseYYVarsMap', instanceProfile.variableMapOffset, vtPointer, variableMap )
  field( yyObject, 'VariableSlotCount', instanceProfile.variableCountOffset, vtDword )
  field( yyObject, 'ObjectFlags', instanceProfile.objectFlagsOffset, vtDword )
  field( yyObject, 'VariableSlotCapacity', instanceProfile.variableCapacityOffset, vtDword )
  field( yyObject, 'ObjectKind', instanceProfile.objectKindOffset, vtDword )

  local result =
  {
    cString = cString,
    rvalue = rvalue,
    rawSlots = rawSlots,
    rawBuckets = rawBuckets,
    variableMap = variableMap,
    yyObject = yyObject
  }

  local object = createStructure('CObjectGM')
  local objectProfile = state.profile.layouts.object

  field( object, 'Name', 0, vtPointer, cString )
  field( object, 'ParentObject', objectProfile.parentOffset, vtPointer, object )
  field( object, 'Flags', objectProfile.flagsOffset, vtDword )
  field( object, 'SpriteIndex', objectProfile.spriteIndexOffset, vtDword )
  field( object, 'Depth', objectProfile.depthOffset, vtDword )
  field( object, 'ParentIndex', objectProfile.parentIndexOffset, vtDword )
  field( object, 'MaskIndex', objectProfile.maskIndexOffset, vtDword )
  field( object, 'ObjectID', objectProfile.objectIdOffset, vtDword )
  result.object = object

  if instanceLayout then

    local instance = createStructure( ('CInstance.%X'):format( instanceLayout.membersOffset ) )
    field( instance, 'vTable', 0, vtPointer )
    field( instance, ('DenseYYVars (optional; first %d slots)'):format( rawSlotCount ), instanceProfile.yyVarsOffset, vtPointer, rawSlots )
    field( instance, 'Prototype', instanceProfile.prototypeOffset, vtPointer, yyObject )
    field( instance, 'ClassName', instanceProfile.classNameOffset, vtPointer, cString )
    field( instance, 'SparseYYVarsMap', instanceProfile.variableMapOffset, vtPointer, variableMap )
    field( instance, 'VariableSlotCount', instanceProfile.variableCountOffset, vtDword )
    field( instance, 'VariableSlotCapacity', instanceProfile.variableCapacityOffset, vtDword )
    field( instance, 'Object', instanceLayout.objectOffset, vtPointer, object )
    field( instance, 'InstanceID', instanceLayout.membersOffset + 4, vtDword ).DisplayMethod = 'dtSignedInteger'
    field( instance, 'ObjectIndex', instanceLayout.membersOffset + 8, vtDword ).DisplayMethod = 'dtSignedInteger'
    field( instance, 'SpriteIndex', instanceLayout.membersOffset + 0xC, vtDword ).DisplayMethod = 'dtSignedInteger'
    field( instance, 'ImageIndex', instanceLayout.membersOffset + 0x1C, vtSingle )
    field( instance, 'ImageSpeed', instanceLayout.membersOffset + 0x20, vtSingle )
    field( instance, 'ImageScaleX', instanceLayout.membersOffset + 0x24, vtSingle )
    field( instance, 'ImageScaleY', instanceLayout.membersOffset + 0x28, vtSingle )

    local motionShift = instanceLayout.motionOffsetShift or 0
    field( instance, 'ImageAngle', instanceLayout.membersOffset + 0x2C + motionShift, vtSingle )
    field( instance, 'ImageAlpha', instanceLayout.membersOffset + 0x30 + motionShift, vtSingle )
    field( instance, 'ImageBlend', instanceLayout.membersOffset + 0x34 + motionShift, vtDword )
    field( instance, 'X', instanceLayout.membersOffset + 0x38 + motionShift, vtSingle )
    field( instance, 'Y', instanceLayout.membersOffset + 0x3C + motionShift, vtSingle )
    field( instance, 'XStart', instanceLayout.membersOffset + 0x40 + motionShift, vtSingle )
    field( instance, 'YStart', instanceLayout.membersOffset + 0x44 + motionShift, vtSingle )
    field( instance, 'XPrevious', instanceLayout.membersOffset + 0x48 + motionShift, vtSingle )
    field( instance, 'YPrevious', instanceLayout.membersOffset + 0x4C + motionShift, vtSingle )
    field( instance, 'Direction', instanceLayout.membersOffset + 0x50 + motionShift, vtSingle )
    field( instance, 'Speed', instanceLayout.membersOffset + 0x54 + motionShift, vtSingle )
    field( instance, 'HorizontalSpeed', instanceLayout.membersOffset + 0x64 + motionShift, vtSingle )
    field( instance, 'VerticalSpeed', instanceLayout.membersOffset + 0x68 + motionShift, vtSingle )
    field( instance, 'NextActive', instanceLayout.flinkOffset, vtPointer, instance )

    result.instance = instance
  end

  return result
end

--- Create instance dissect overview
-- @param state table
function Runtime.Structures.createInstanceOverview(state)
  
  local snapshot, snapshotError = Runtime.Instances.createSnapshot(state)
  if not snapshot then return nil, nil, snapshotError end

  if #snapshot.instances == 0 then return nil, snapshot, 'current room has no active instances' end

  local structures = Runtime.Structures.createInstanceLayouts(state)
  if not structures.instance then return nil, snapshot, 'CInstance layout is not validated' end

  local overview = createStructure( ('Instances [%d]'):format( #snapshot.instances ) )
  
  overview.beginUpdate()

  for index, instance in ipairs( snapshot.instances ) do

    local element = overview.addElement()

    element.Name = ('[%04d] %s id=%d object=%d @ (%.3f, %.3f)'):format( index - 1, instance.objectName, instance.id or -1, instance.objectIndex or -1, instance.x or 0, instance.y or 0 )
    element.Offset = (index - 1) * state.pointerSize
    element.Vartype = vtPointer
    element.ChildStruct = structures.instance
  end

  overview.endUpdate()

  return overview, snapshot
end

Runtime.bytePattern = bytePattern
Runtime.pointerPattern = pointerPattern
return Runtime