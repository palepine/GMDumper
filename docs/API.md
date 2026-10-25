# GMDumper Lua API reference

## Quick start

```lua
assert( gm_initDumper() )

local player = assert( gm_listInstances( 'obj_player' ) )[1]

local hp = assert( gm_findInstanceVariable( player, 'hp' ) )

print( hp.name, ('0x%X'):format( hp.address ), hp.kindName, hp.value )
```

## [Portable Cheat Tables](API/portability.md)

`gm_attachToTable`

## [Initialization, status, version, and profiles](API/initialization.md)

`gm_initDumper`

`gm_getStatus`

`gm_getState`

`gm_getLayout`

`gm_getVersion`

`gm_getProfile`

`gm_clearDiscoveryCache`

`gm_getBridgeStatus`

`gm_configureBridge`

`gm_isGameMakerProcess`

`gm_getDetectionEvidence`

## [Functions and scripts](API/functions-and-scripts.md)

`gm_findFunction`

`gm_listFunctions`

`gm_getFunctionTable`

`gm_listScripts`

`gm_registerFunctionSymbols`

## [Instances and gameplay fields](API/instances-and-fields.md)

`gm_listInstances`

`gm_rescanInstances`

`gm_listInstanceVariables`

`gm_findInstanceVariable`

`gm_getInstanceVariableAddress`

`gm_listGlobalVariables`

`gm_findGlobalVariable`

## [Stable Cheat Table symbols](API/symbols.md)

`gm_watchObjectFields`

`gm_unwatchObjectFields`

`gm_getObjectFieldWatches`

## [RValues, arrays, structs, and GML calls](API/values-and-calls.md)

`gm_decodeRValue`

`gm_listRValueMembers`

`gm_findRValueMember`

`gm_listRValueArray`

`gm_getRValueArrayElement`

`gm_callUserFunction`

## [Object dumps, Structure Dissect, and cleanup](API/dumps-and-structures.md)

`gm_dumpObjects`

`gm_createInstanceOverview`

`gm_openInstanceOverview`

`gm_cleanup`