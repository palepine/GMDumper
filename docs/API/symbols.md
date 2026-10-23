# Stable Cheat Table symbols

## `gm_watchObjectFields(objectName, fields, options)`
> Continuously publish selected fields from a uniquely (!) active object as a symbols

```lua
local fieldsINeed =
{
  'hp',
  'mp',
  'move_speed',
}

assert( gm_watchObjectFields('obj_player', fieldsINeed, { id = 'player' } ) ) -- obj_player.hp symbol
```

    Notes: use reserved object name 'global' for the global user-defined fields:

```lua
assert( gm_watchObjectFields('global', { 'score', 'difficulty' } ) )

-- Published symbols:
-- global.score
-- global.difficulty
```

| Option | Default | Description |
|---|---:|---|
| `id` | `objectName` | identifier used to replace or remove this watch |
| `immediate` | `false` | Perform a sync refresh instead of only waking the worker |

## `gm_getObjectFieldWatches()`
> Return watches keyed by ID, including each field's `registered`, `address`, `instanceId` and `error` status.

```lua
printTable( gm_getObjectFieldWatches() )
```

## `gm_unwatchObjectFields(watchId)`
> Remove a declaration and unregister symbols owned by the watch.

```lua
gm_unwatchObjectFields( 'player' )
```
