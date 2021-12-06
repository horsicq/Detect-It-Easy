###This is a description of the global functions

* You could use all functions from all scripts.

**includeScript(sScriptName)** Include another script into this one.

* sScriptName - The script name. Default path is $APP/db.

```
includeScript("Cab"); // include script $APP/db/Cab
```
**_log(sString)** Display a message in the log window or as a console error. It is used to debug signatures.

* sString - The message.

```
_log("Hello world!"); // display a string
_log(123); // display a number
```
**result(bShowType,bShowVersion,bShowOptions)** Get a result string appropriate to the class.

* bShowType - True to include the type.
* bShowVersion - True to include the version.
* bShowOptions - True to include the options.

```
```
**_setResult(sType,sName,sVersion,sOptions)** set result

```
```