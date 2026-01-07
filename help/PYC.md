# PYC Class Reference

* You could use all functions from Binary class but with PYC prefix (Binary.compare -> PYC.compare)

**bool isConstPresent(QString sConstValue)**

```
Check if a constant string is present in the Python bytecode constants table.
Returns true if the specified string constant exists in the code object's consts tuple.

Example:
if (PYC.isConstPresent("UPP!1.10")) {
    // UPP packer detected
}
```
