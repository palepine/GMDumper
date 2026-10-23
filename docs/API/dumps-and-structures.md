# Object dumps, Structure Dissect, and cleanup

## Dump objects and fields

#### `gm_dumpObjects(path, options)`
> Write a snapshot of reflected global fields followed by active instances grouped by object asset.
> Returns `writtenPath, statistics` or `nil, errorMessage`.

    Notes: nil `path` writes besides executable
```lua
return assert( gm_dumpObjects( [[C:\temp\my-game-objects.txt]] ) )
```

| Option | Description |
|---|---|
| `pattern` | Object-name substring or exact instance ID |
| `maximumInstances` | Maximum instances to dump |
| `maximumVariables` | Maximum fields per instance |
| `maximumGlobalVariables` | Maximum global fields to dump; defaults to `maximumVariables` |
| `includeGlobals` | Include reflected global fields; defaults to `true` |

## Structure Dissect

#### `gm_openInstanceOverview()`
> Create the snapshot and open it in CE Structure Dissect. Returns `form, structure, snapshot`.

```lua
local form = assert( gm_openInstanceOverview() )
```

## Cleanup

#### `gm_cleanup()`
> Stop symbol monitoring, remove GMDumper symbols and the bridge dispatcher, release snapshots, clear runtime state.

```lua
gm_cleanup()
```