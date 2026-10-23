# RValues, arrays, structs, GML calls

## Decode a value

#### `gm_decodeRValue(address)`
> Decode an `RValue` or return `nil, errorMessage`.

```lua
local value = assert( gm_decodeRValue( address ) )
print( value.kindName, value.value or value.pointer )
```

## Object and struct members

#### `gm_listRValueMembers(value, options)`
> Reflect all members of an object/struct-valued `RValue`.
> `value` may be a field descriptor or its `RValue` address.

    Notes: pass { rawObject = true } when value is already a raw GameMaker object ptr.
    options.maximum and options.timeout limit the bridge request

```lua
local stats = assert( gm_findInstanceVariable( player, 'stats' ) )
local result = assert( gm_listRValueMembers( stats ) )

for _, member in ipairs( result.members ) do
  print( member.name, member.kindName, member.value or member.pointer )
end
```

#### `gm_findRValueMember(value, name, options)`
> Return a reflected member or `nil, errorMessage`.

```lua
local health = assert( gm_findRValueMember( stats, 'health' ) )
```

## Arrays

#### `gm_listRValueArray(value, options)`
> Enumerate an array-valued `RValue`.

```lua
local inventory = assert( gm_findInstanceVariable( player, 'inventory' ) )
local array = assert( gm_listRValueArray( inventory ) )

for _, element in ipairs( array.elements ) do
  print( element.index, element.kindName, element.value or element.pointer )
end
```

#### `gm_getRValueArrayElement(value, index, options)`

> Return an array element (zero-based).

```lua
-- Member, element addresses can be reallocated!
local first = assert( gm_getRValueArrayElement( inventory, 0 ) )
```

## Call a user-defined GML function

#### `gm_callUserFunction(name, arguments, options)`
> Invoke a user-defined function (game-thread), return the resulting `RValue` or `nil, errorMessage`.

    Notes: arguments support scalar values or references.

```lua
local args =
{
  25,
}

local callOptions = 
{
  self = player,
  other = player,
  timeout = 5000,
}

local result = assert( gm_callUserFunction( 'heal', args, callOptions ) )

print( result.kindName, result.value or result.pointer )
```