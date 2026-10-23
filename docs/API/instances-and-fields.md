# Instances and gameplay fields

## Find active instances

#### `gm_listInstances(pattern)`
> List instances for the current room. Returns `instances` or `nil, errorMessage`.

    Notes: pattern may be an object-name substring/exact instance ID.

```lua
local players = assert( gm_listInstances('obj_player') )

for _, instance in ipairs(players) do
  print( instance.objectName, instance.id, ('0x%X'):format( instance.address ), instance.x, instance.y )
end

```

| Field | Description |
|---|---|
| `address` | Live `CInstance*` |
| `id` | Instance ID |
| `objectName` | Exact object asset name |
| `objectIndex` | Object asset index |
| `object` | Shared object identity (`CObjectGM*`; synthetic asset key on early GMS1) |
| `x`, `y` | Current position |
| `variableCount`, `variableCapacity` | Runtime variable-slot domain |

#### `gm_rescanInstances(overrides)`
> Rescan the room & instance layouts.

```lua
assert( gm_rescanInstances() )
```

## Enumerate fields

#### `gm_listInstanceVariables(instanceOrId, maximum)`
> Return the variable-storage descriptor for an instance record, instance address or instance ID.

```lua
local player = assert( gm_listInstances( 'obj_player' ) )[1]

local storage = assert( gm_listInstanceVariables( player ) )

print( storage.storageKind, storage.namesAvailable, #storage.variables )

for _, field in ipairs( storage.variables ) do
  print( field.name or '<unresolved>', field.slot, field.kindName, field.value or field.pointer )
end
```

#### `gm_findInstanceVariable(instanceOrId, nameOrSlot)`
> Find a field by its name / numeric runtime slot. Returns the field descriptor or `nil, errorMessage`.

```lua
local hp = assert( gm_findInstanceVariable( player, 'hp' ) )
print( hp.address, hp.slot, hp.kindName, hp.value )
```

#### `gm_getInstanceVariableAddress(instanceOrId, nameOrSlot)`
> Return current field address or `nil, errorMessage`.

```lua
local address = assert( gm_getInstanceVariableAddress( player, 'hp') )
print( ('0x%X'):format( address ) )
```

## Global gameplay fields

#### `gm_listGlobalVariables(maximum)`
> just like `gm_listInstanceVariables`, but for the global-scoped variables

```lua
local globals = assert( gm_listGlobalVariables() )

for _, field in ipairs(globals.variables) do
  print( field.name, field.kindName, field.value or field.pointer )
end
```

#### `gm_findGlobalVariable(nameOrSlot)`
> Find a global field by name / numeric runtime slot.

```lua
local score = assert( gm_findGlobalVariable('score') )
print( ('0x%X'):format(score.address), score.value )
```
