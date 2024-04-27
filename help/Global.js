/**
 * Include another script into this one.
 * @param {String} sScriptName - The script name. Default path is <code>$APP/db</code>.
 * @example
 * includeScript("Cab"); // include script $APP/db/Cab
 */
function includeScript(sScriptName){}
/**
 * Display a message in the log window or as a console error. It is used to debug signatures.
 * @param {String} sString - The message.
 * @example
 * _log("Hello world!"); // display a string
 * _log(123); // display a number
 */
function _log(sString){}

/**
 * Get a result string appropriate to the class.
 * @param {Bool} bShowType - True to include the type.
 * @param {Bool} bShowVersion - True to include the version.
 * @param {Bool} bShowOptions - True to include the options.
 * @returns {String}
 */
function result(bShowType,bShowVersion,bShowOptions){}
