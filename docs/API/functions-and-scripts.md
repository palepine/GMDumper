# Functions and scripts

## Built-in runner functions

#### `gm_findFunction(name)`
> Find one built-in by the name and return its descriptor or `nil`.

```lua
local fn = assert( gm_findFunction('show_debug_message') )

print( fn.name, ('0x%X'):format( fn.routine ), fn.argumentCount )
```

#### `gm_listFunctions(pattern)`
> List built-ins whose names contain the case-insensitive `pattern`.

    Notes: omit the pattern to return all entries.

```lua
for _, fn in ipairs( gm_listFunctions( 'instance_' ) ) do
  print( fn.index, fn.name, fn.argumentCount, ('0x%X'):format( fn.routine ) )
end
```

| Field | Description |
|---|---|
| `index` | Entry index in the runtime table |
| `name` | Built-in function name |
| `routine` | Native implementation address |
| `argumentCount` | Runner argument count metadata |
| `address` | Address of the table entry |

#### `gm_getFunctionTable()`
> Return the validated function-table descriptor.

```lua
local tableInfo = gm_getFunctionTable()
print( ('0x%X'):format( tableInfo.start ), tableInfo.layout.kind, #tableInfo.functions )
```

## YYC scripts

#### `gm_listScripts(pattern)`
> List native `gml_Script_*` descriptors discovered in a YYC executable.

    Notes: an empty result doesn't prove the target has no scripts.

```lua
for _, script in ipairs( gm_listScripts( 'player' ) ) do
  print( script.name, ('0x%X'):format( script.routine ) )
end
```

## CE function symbols

#### `gm_registerFunctionSymbols(prefix)`

> Register every discovered built-in and YYC routine as a CE symbol. Returns the set of registered names.

```lua
printTable( gm_registerFunctionSymbols( 'smth.' ) )
```