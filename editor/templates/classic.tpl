// DIE's signature file
// Author: @AUTHOR@
/*
@COMMENT@
*/
function detect(bShowType,bShowVersion,bShowOptions)
{
    var sType="@TYPE@";
    var sName="@NAME@";
    var sVersion="-";
    var sOptions="-";
    var sResult="";
    var nDetected=0;

    // Start of user's code

    // End of user's code

    if(nDetected)
    {
        if(bShowType)
        {
            sResult+=sType+": ";
        }
        sResult+=sName;
        if(bShowVersion)
        {
            sResult+="("+sVersion+")";
        }
        if(bShowOptions)
        {
            sResult+="["+sOptions+"]";
        }
    }

    return sResult;
}
