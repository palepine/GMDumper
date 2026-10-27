--[[
  GMDumper runner layout and bridge ABI profiles
  Copyright (C) 2026 palepine

  GPL-3.0-or-later. See LICENSE in the project root.
]]

--[[
  Every profile contains the complete candidate families inherited from base.
  GMRuntime still validates each candidate against runtime & may fall back to any generic candidate

  To support another runner:
    1. add a candidate layout to base when its shape is genuinely new;
    2. add a small derived profile that changes preference order;
    3. keep proof (pointer ranges, list integrity, IDs, names) in GMRuntime.

  The bridge profile follows the same rule.
  Slot offsets describe one known YYRunnerInterface ABI, while the native bridge verifies the recovered function
  addresses & disables optional capabilities that can't be proven.
]]

-- ///---///--///---///--///---///--///--///---///--///---///--///---///--///--///--///--///--///--///--///--///--///--///--/// PROFILE HELPERS

local Versioning = {}
local ProfileResolver = {}
ProfileResolver.__index = ProfileResolver

--- Copy a value recursively
-- @param value any
-- @return any
local function copyValue(value)
  if type(value) ~= 'table' then return value end

  local result = {}

  for key, item in pairs(value) do
    result[ copyValue( key ) ] = copyValue( item )
  end

  return result
end

--- Merge inherited profile tables recursively.
-- Maps inherit per key.
-- Arrays & scalar values are replacements keeping derived profiles small w/o combining priorities.
-- @param parent table|nil
-- @param child table|nil
-- @return table
local function mergeTable(parent, child)
  local result = copyValue( parent or {} )

  for key, value in pairs( child or {} ) do

    if type(value) == 'table' and type( result[ key ] ) == 'table' and value[1] == nil and result[ key ][1] == nil then
      result[ key ] = mergeTable( result[ key ], value )
    else
      result[ key ] = copyValue(value)
    end
  end

  return result
end

--- Compare two version triples
-- @param left table
-- @param right table
-- @return number
local function compareVersion(left, right)

  for index, key in ipairs( { 'major', 'minor', 'release', 'build' } ) do

    local a = tonumber( left and left[ key ] ) or 0

    local b = tonumber( right and ( right[ key ] or right[ index ] ) ) or 0

    if a ~= b then return a < b and -1 or 1 end
  end

  return 0
end

--- Test a target against a version profile match
-- @param target table
-- @param match table|nil
-- @return boolean
local function matches(target, match)
  if not match then return false end

  if match.pointerSize and target.pointerSize ~= match.pointerSize then return false end

  if match.min and compareVersion( target.version, match.min ) < 0 then return false end

  if match.max and compareVersion( target.version, match.max ) > 0 then return false end

  return true
end

--- Prefer known candidates w/o discarding generic fallbacks.
-- @param candidates table
-- @param preferred table|nil
-- @param keySelector function|nil
-- @return table
local function orderedCandidates(candidates, preferred, keySelector)

  keySelector = keySelector or function(value)
    return value
  end

  local byKey, result, emitted = {}, {}, {}

  for _, candidate in ipairs(candidates or {}) do
    byKey[ keySelector( candidate ) ] = candidate
  end

  for _, key in ipairs(preferred or {}) do
    local candidate = byKey[key]

    if candidate and not emitted[key] then
      result[ #result + 1 ] = copyValue(candidate)
      emitted[key] = true
    end

  end

  for _, candidate in ipairs( candidates or {} ) do
    local key = keySelector( candidate )

    if not emitted[key] then
      result[ #result + 1 ] = copyValue(candidate)
      emitted[key] = true
    end

  end

  return result
end

--- Create a profile resolver
-- @return table
function ProfileResolver.new()
  return setmetatable( { specs = {}, compiled = {} } , ProfileResolver)
end

--- Register one profile specification
-- @param spec table
-- @return table
function ProfileResolver:register(spec)
  assert( type(spec) == 'table', 'profile spec must be a table' )
  assert( type(spec.id) == 'string' and spec.id ~= '', 'profile id must be a non-empty string' )
  assert( self.specs[ spec.id ] == nil, 'duplicate profile: ' .. spec.id )

  self.specs[ spec.id ] = spec
  self.compiled = {}
  return self
end

--- Compile a profile and its inherited values
-- @param profileId string
-- @param visited table|nil
-- @return table
function ProfileResolver:compile(profileId, visited)

  if self.compiled[ profileId ] then
    return self.compiled[ profileId ]
  end

  local spec = assert( self.specs[profileId], 'unknown profile: ' .. tostring(profileId) )
  
  visited = visited or {}
  assert( not visited[ profileId ], 'circular profile inheritance: ' .. profileId )
  visited[ profileId ] = true

  -- Compile inheritance once so callers receive an ordinary table
  local parent = spec.extends and self:compile( spec.extends, visited ) or {}

  local compiled = mergeTable( parent, spec )
  
  compiled.match, compiled.extends = nil, nil

  self.compiled[profileId] = compiled

  visited[ profileId ] = nil

  return compiled
end

--- Resolve the most specific matching profile
-- @param target table
-- @return table
function ProfileResolver:resolve(target)

  local selected = self.specs[ target.profileHint ] or self.specs.base

  -- Priority expresses specificity. Overlapping ranges are expected (eg 2024.14+ also matches 2024.6+) and the narrower profile wins.
  for _, spec in pairs(self.specs) do

    if matches( target, spec.match ) and (not selected or (spec.priority or 0) > (selected.priority or 0)) then
      selected = spec
    end

  end
  
  return self:compile( assert( selected, 'base profile is not registered' ).id )
end

-- ///---///--///---///--///---///--///--///---///--///---///--///---///--///--///--///--///--///--///--///--///--///--///--/// PROFILE DEFINITIONS

--- Define classic GameMaker runner profiles
-- @return table
local function defineProfiles()
  local resolver = ProfileResolver.new()

  -- base owns the complete set of layouts that discovery is allowed to test.
  -- Derived profiles below should generally change preferences, not copy these structures and create a second source of truth.
  resolver:register(
    {
      id = 'base',
      priority = 0,
      family = 'classic-runner',
      supported = true,
      capabilities =
      {
        structuralDiscovery = true,
        namedReflection = true,
        bridgeAutomaticX64 = true,
        bridgeAutomaticX86 = true,
      },
      layouts =
      {
        functionEntries =
        {
          x64 =
          {
            {
              kind = 'reference',
              stride = 24,
              nameOffset = 0,
              routineOffset = 8,
              argumentOffset = 16,
              usageOffset = 20
            },
            
            {
              kind = 'inline',
              stride = 80,
              nameOffset = 0,
              routineOffset = 64,
              argumentOffset = 72,
              usageOffset = 76
            },
          },
          x86 =
          {
            {
              kind = 'reference',
              stride = 16,
              nameOffset = 0,
              routineOffset = 4,
              argumentOffset = 8,
              usageOffset = 12
            },
            {
              kind = 'inline',
              stride = 76,
              nameOffset = 0,
              routineOffset = 64,
              argumentOffset = 68,
              usageOffset = 72
            },
            {
              kind = 'registration',
              stride = 0,
              pattern = '6A * 6A * 68 * * * * 68 * * * * E8 * * * *',
              usageOffset = 1,
              argumentOffset = 3,
              routineOffset = 5,
              nameOffset = 10,
              callOffset = 14,
              instructionSize = 19
            },
          },
        },
        builtInVariables =
        {
          x64 =
          {
            stride = 32,
            nameOffset = 0,
            getterOffset = 8,
            setterOffset = 16,
            canSetOffset = 24
          },
          x86 =
          {
            stride = 16,
            nameOffset = 0,
            getterOffset = 4,
            setterOffset = 8,
            canSetOffset = 12
          },
        },
        codeExecutePatterns =
        {
          x64 = { 'E8 * * * * 0F B6 D8 3C 01', 'E8 * * * * 3C 01 74 *' },
          x86 = { 'E8 * * * * 8A D8 83 C4 14' },
        },
        rooms =
        {
          x64 =
          {
            {
              name = 'legacy-backgrounds',
              activeListOffset = 0xD8,
              roomInternalOffset = 0x70
            },
            {
              name = '2024.6+',
              activeListOffset = 0x90,
              roomInternalOffset = 0x28
            },
          },
          x86 =
          {
            {
              name = 'legacy-backgrounds',
              activeListOffset = 0x80,
              roomInternalOffset = 0x44
            },
            {
              name = '2024.6+',
              activeListOffset = 0x58,
              roomInternalOffset = 0x1C
            },
          },
        },
        roomHeaders =
        {
          x64 =
          {
            widthOffset = 0x1C,
            heightOffset = 0x20
          },
          x86 =
          {
            widthOffset = 0x10,
            heightOffset = 0x14
          },
        },
        instances =
        {
          x64 =
          {
            membersOffsets =
            {
              0xA8,
              0xB0,
              0xB8
            },
            flinkRelatives = { 0xE8 },
            motionShifts = { 0, 4 },
            objectOffset = 0x90,
            yyVarsOffset = 0x08,
            objectListNextOffset = 0x10,
            objectListPreviousOffset = 0x18,
            variableMapOffset = 0x48,
            variableCountOffset = 0x5C,
            variableCapacityOffset = 0x64,
            objectFlagsOffset = 0x60,
            objectKindOffset = 0x7C,
            prototypeOffset = 0x20,
            classNameOffset = 0x28,
          },
          x86 =
          {
            membersOffsets =
            {
              0x60,
              0x64,
              0x68,
              0x6C,
              0x70,
              0x74,
              0x78,
              0x7C,
              0x80,
              0x84,
              0x88,
              0x8C,
              0x90
            },
            flinkRelatives =
            {
              0xD0,
              0xD4
            },
            motionShifts = { 0 },
            objectOffset = 0x68,
            yyVarsOffset = 0x04,
            objectListNextOffset = 0x08,
            objectListPreviousOffset = 0x0C,
            variableMapOffset = 0x24,
            variableCountOffset = 0x30,
            variableCapacityOffset = 0x38,
            objectFlagsOffset = 0x34,
            objectKindOffset = 0x50,
            prototypeOffset = 0x10,
            classNameOffset = 0x14,
          },
        },
        objects =
        {
          x64 =
          {
            parentOffset = 0x08,
            flagsOffset = 0x80,
            spriteIndexOffset = 0x84,
            depthOffset = 0x88,
            parentIndexOffset = 0x8C,
            maskIndexOffset = 0x90,
            objectIdOffset = 0x94
          },
          x86 =
          {
            parentOffset = 0x04,
            flagsOffset = 0x58,
            spriteIndexOffset = 0x5C,
            depthOffset = 0x60,
            parentIndexOffset = 0x64,
            maskIndexOffset = 0x68,
            objectIdOffset = 0x6C
          },
        },
        sparseVariableMaps =
        {
          x64 =
          {
            stride = 16,
            keyOffset = 8,
            hashOffset = 12
          },
          x86 =
          {
            stride = 12,
            keyOffset = 4,
            hashOffset = 8
          },
        },
      },
      bridge =
      {
        -- pointer-slot indexes in YYRunnerInterface
        -- GMBridge scales them by the target pointer size before native discovery.
        id = 'yy-runner-interface-v1',
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
          arrayGetLength = 98,
        },
        discovery =
        {
          minimumAssignments = 88,
          minimumAssignmentsX86 = 60,
          maximumAssignments = 160,
          maximumSpan = 0x380,
          maximumInstructionSpan = 0x1400,
          maximumFunctionDistance = 0x800,
          maximumBaseSlack = 0,
        },
      },
      preferences =
      {
        functionKinds = { 'reference', 'inline' },
        codeExecutePatterns = {},
        roomLayouts = { 'legacy-backgrounds', '2024.6+' },
        membersOffsets = {},
      },
    }
  )

  resolver:register(
    {
      -- GameMaker Studio 1 uses x86 registration calls and direct linked CInstance nodes (not modern room-member wrapper)
      id = 'gms1',
      extends = 'base',
      priority = 10,
      capabilities =
      {
        bridgeAutomaticX86 = false,
      },
      match =
      {
        min = { 1, 0 },
        max = { 1, 999 }
      },
      preferences =
      {
        functionKinds = { 'registration', 'reference', 'inline' }
      },
      layouts =
      {
        instances =
        {
          x86 =
          {
            directLayouts =
            {
              {
                name = 'gms1-direct',
                nextOffset = 0x104,
                previousOffset = 0x108,
                idOffset = 0x18,
                objectIndexOffset = 0x1C,
                spriteIndexOffset = 0x28,
                imageIndexOffset = 0x2C,
                imageSpeedOffset = 0x30,
                imageScaleXOffset = 0x34,
                imageScaleYOffset = 0x38,
                imageAngleOffset = 0x3C,
                imageAlphaOffset = 0x40,
                imageBlendOffset = 0x44,
                xOffset = 0x50,
                yOffset = 0x54,
                xStartOffset = 0x58,
                yStartOffset = 0x5C,
                xPreviousOffset = 0x60,
                yPreviousOffset = 0x64,
                variableStorageOffset = 0xC4,
                variableBucketOffset = 0x04,
                variableBucketCount = 64,
                variableNodeNextOffset = 0x00,
                variableNodeValueOffset = 0x08,
                variableNodeIdOffset = 0x18,
                variableIdBase = 100000
              },
              {
                name = 'gms1-direct-reversed-links',
                nextOffset = 0x108,
                previousOffset = 0x104,
                idOffset = 0x18,
                objectIndexOffset = 0x1C,
                spriteIndexOffset = 0x28,
                imageIndexOffset = 0x2C,
                imageSpeedOffset = 0x30,
                imageScaleXOffset = 0x34,
                imageScaleYOffset = 0x38,
                imageAngleOffset = 0x3C,
                imageAlphaOffset = 0x40,
                imageBlendOffset = 0x44,
                xOffset = 0x50,
                yOffset = 0x54,
                xStartOffset = 0x58,
                yStartOffset = 0x5C,
                xPreviousOffset = 0x60,
                yPreviousOffset = 0x64,
                variableStorageOffset = 0xC4,
                variableBucketOffset = 0x04,
                variableBucketCount = 64,
                variableNodeNextOffset = 0x00,
                variableNodeValueOffset = 0x08,
                variableNodeIdOffset = 0x18,
                variableIdBase = 100000
              }
            }
          }
        }
      }
    }
  )

  resolver:register(
    {
      -- x86 YYObjectBase contains 2 additional callback pointers before m_YYVarsMap.
      -- the larger base shifts CInstance::m_Object and the map metadata while CInstanceInternal begins at +0x80
      id = 'gms2',
      extends = 'base',
      priority = 20,
      match =
      {
        min = { 2, 0 },
        max = { 2, 999 }
      },
      layouts =
      {
        instances =
        {
          x86 =
          {
            variants =
            {
              {
                name = 'gms2-2.3+',
                membersOffset = 0x80,
                flinkRelative = 0xC8,
                objectOffset = 0x70,
                sequenceOffsetShift = 0
              },
              {
                -- GMS2 2.2 has no sequence-position triplet at the beginning of CInstanceInternal.
                -- built-in getters in this generation expose ID@+0x78, X@+0xA0 and the active-list link at +0x130
                -- variable access checks the slot domain at YYObjectBase+0x30; this revision doesnt expose a separate capacity
                name = 'gms2-2.2',
                membersOffset = 0x74,
                flinkRelative = 0xBC,
                objectOffset = 0x68,
                sequenceOffsetShift = -0x0C,
                variableCountOffset = 0x30,
                variableCapacityOffset = 0x30
              }
            },
            membersOffsets = { 0x80 },
            flinkRelatives = { 0xC8 },
            objectOffset = 0x70,
            variableMapOffset = 0x2C,
            variableCountOffset = 0x38,
            variableCapacityOffset = 0x40,
            objectFlagsOffset = 0x3C,
            objectKindOffset = 0x58
          }
        }
      }
    }
  )

  resolver:register(
    {
      -- the modern profiles document observed ordering changes
      -- their shared fallback set remains inherited from base for patched/custom runners.
      id = 'runtime-2022',
      extends = 'base',
      priority = 30,
      match =
      {
        min = { 2022, 0 },
        max = { 2022, 999 }
      },
      preferences =
      {
        membersOffsets = { 0xA8, 0xB0, 0xB8 }
      },
    }
  )

  resolver:register(
    {
      id = 'runtime-2023',
      extends = 'base',
      priority = 40,
      match =
      {
        min = { 2023, 0 },
        max = { 2023, 999 }
      },
      preferences =
      {
        membersOffsets = { 0xB0, 0xB8, 0xA8 }
      },
    }
  )

  resolver:register(
    {
      id = 'runtime-2024-pre6',
      extends = 'runtime-2023',
      priority = 50,
      match =
      {
        min = { 2024, 0 },
        max = { 2024, 5, 999, 999999 }
      },
    }
  )

  resolver:register(
    {
      id = 'runtime-2024.6+',
      extends = 'runtime-2023',
      priority = 60,
      match =
      {
        min = { 2024, 6 },
        max = { 2024, 999 }
      },
      preferences =
      {
        roomLayouts = { '2024.6+', 'legacy-backgrounds' }
      },
    }
  )

  resolver:register(
    {
      id = 'runtime-2024.14+',
      extends = 'runtime-2024.6+',
      priority = 70,
      match =
      {
        min = { 2024, 14 },
        max = { 9999, 999 }
      },
      preferences =
      {
        codeExecutePatterns = { 'E8 * * * * 3C 01 74 *', 'E8 * * * * 0F B6 D8 3C 01' }
      },
    }
  )

  return resolver
end

--- Resolve and get a profile for one runtime
-- Version-specific preferences only reorder the complete generic candidate sets.
-- @param target table
-- @return table
function Versioning.resolve(target)
  assert(type(target) == 'table' and type(target.pointerSize) == 'number', 'profile target requires pointerSize')
  local resolver = defineProfiles()
  local compiled = resolver:resolve(target)
  local architecture = target.pointerSize == 8 and 'x64' or 'x86'
  local layouts = compiled.layouts
  local preferences = compiled.preferences or {}
  
  -- Select arch after inheritance compiled.
  local result =
  {
    id = compiled.id,
    family = compiled.family,
    supported = compiled.supported == true,
    architecture = architecture,
  
    version = copyValue( target.version ),
    versionConfidence = target.version and target.version.confidence or 'unknown',
    capabilities = copyValue( compiled.capabilities ),
  
    layouts =
    {
      functionEntries = orderedCandidates( layouts.functionEntries[architecture], preferences.functionKinds, function(candidate) return candidate.kind end ),

      builtInVariables = copyValue( layouts.builtInVariables[architecture] ),
      
      codeExecutePatterns = orderedCandidates( layouts.codeExecutePatterns[architecture], preferences.codeExecutePatterns ),

      roomLayouts = orderedCandidates( layouts.rooms[architecture], preferences.roomLayouts, function(candidate) return candidate.name end ),

      roomHeader = copyValue( layouts.roomHeaders[architecture] ),

      instance = copyValue( layouts.instances[architecture] ),

      object = copyValue( layouts.objects[architecture] ),

      sparseVariableMap = copyValue( layouts.sparseVariableMaps[architecture] ),
    },

    bridge = copyValue( compiled.bridge ),
  }

  result.layouts.instance.membersOffsets = orderedCandidates( result.layouts.instance.membersOffsets, preferences.membersOffsets )
  
  if target.pointerSize == 8 then
    result.bridge.automatic = result.capabilities.bridgeAutomaticX64 == true
  else
    result.bridge.automatic = result.capabilities.bridgeAutomaticX86 == true
    result.bridge.discovery.minimumAssignments = result.bridge.discovery.minimumAssignmentsX86
  end

  return result
end

Versioning.ProfileResolver = ProfileResolver

return Versioning