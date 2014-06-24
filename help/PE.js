/**
 * @class
 * @classdesc This is a description of the PE class.
 */
function PE(){};
/**
 * @see {@link Binary.calculateEntropy}
 */
PE.calculateEntropy=function(nOffset,nSize){};
/**
 * Calculate size of headers
 * @returns {UInt} 
 */
PE.calculateSizeOfHeaders=function(){};
/**
 * @see {@link Binary.compare}
 */
PE.compare=function(sSignature,nOffset){};
/**
 * The function compares bytes at the EntryPoint 
 * @see {@link Binary.compare}
 * @param {String} sString - The Signature.
 * @param {UInt} nOffset - The offset from the EntryPoint. By default is 0.
 * @returns {Bool} 
 * @example
    if(PE.compareEP("2C81",8))
    {
        sVersion="1.98";
    }
    
    if(PE.compareEP("EB016860E8000000008B1C2483C312812BE8B10600FE4BFD822C24"))
    {
        bDetected=1;
    }
 */
PE.compareEP=function(sSignature,nOffset){};
/**
 * The function compares bytes at the EntryPoint of .NET
 * @see {@link Binary.compare}
 * @param {String} sString - The Signature.
 * @param {UInt} nOffset - The offset from the EntryPoint of .NET. By default is 0.
 * @returns {Bool} 
 * @example
    if(PE.compareEP_NET("4228070000066f09000006283800000a2a1b3004006f0000000d0000110272b9"))
    {
        bDetected=1;
        sVersion="2.X";
    }
 */
PE.compareEP_NET=function(sSignature,nOffset){};
/**
 * The function compares bytes of overlay
 * @param {String} sString - The Signature.
 * @param {UInt} nOffset - The offset from the overlay offset. By default is 0.
 * @returns {Bool} 
 * @example
    if(PE.compareOverlay("';!@Install@!UTF-8!'"))
    {
        bDetected=1;
    }
 */
PE.compareOverlay=function(sSignature,nOffset){};
/**
 * @see {@link Binary.findByte}
 */
PE.findByte=function(nOffset,nSize,cValue){};
/**
 * @see {@link Binary.findDword}
 */
PE.findDword=function(nOffset,nSize,nValue){};
/**
 * @see {@link Binary.findSignature}
 * @example
    nOffset=PE.findSignature(nOffset,1024,"'7z'BCAF271C");
    if(nOffset!=-1)
    {
        bDetected=1;
    }
 */
PE.findSignature=function(nOffset,nSize,Signature){};
/**
 * @see {@link Binary.findString}
 * @example
    nOffset=PE.findString(0,1024,"UPX!");
    if(nOffset==-1)
    {
        return;
    }
 */
PE.findString=function(nOffset,nSize,sValue){};
/**
 * @see {@link Binary.findWord}
 */
PE.findWord=function(nOffset,nSize,sValue){};
/**
 * Get address of EntryPoint
 * @returns {UInt} 
 * @example
    var nSection=PE.nLastSection;
    if(nSection>=2)
    {
        if(PE.getAddressOfEntryPoint()==PE.section[nSection].VirtualAddress)
        {
            if(PE.section[nSection].Characteristics==0xe0000040)
            {
                if(PE.section[nSection-1].Characteristics==0xe0000040)
                {
                    if(PE.getNumberOfImportThunks(0)==1)
                    {
                        bDetected=1;
                    }
                }
            }
        }
    }
 */
PE.getAddressOfEntryPoint=function(){};
/**
 * Get compiler version.
 * @returns {String} The function returns the string [MajorLinkerVersion].[MinorLinkerVersion]
 * @example
    if(bDetected)
    {
        switch(PE.getCompilerVersion())
        {
        case "6.0":  sVersion="6.0";  break;
        case "7.0":  sVersion="2002"; break;
        case "7.10": sVersion="2003"; break;
        case "8.0":  sVersion="2005"; break;
        case "9.0":  sVersion="2008"; break;
        case "10.0": sVersion="2010"; break;
        case "11.0": sVersion="2012"; break;
        case "12.0": sVersion="2013"; break;
        }
    }
 */
PE.getCompilerVersion=function(){};
/**
 * The function returns the number of a section, where the point of entry is located (address of entry point) (0…N)
 * @returns {Int} if no entry point returns -1
 * @example
if(PE.getEntryPointSection()==PE.nLastSection)
{
    bDetected=1;
}
 */
PE.getEntryPointSection=function(){};
/**
 * @see {@link Binary.getFileDirectory}
 */
PE.getFileDirectory=function(){};
/**
 * This function returns the version of the opened file. If the version can be found in the resources.
 * @returns {String}
 */
PE.getFileVersion=function(){};
/**
 * This function returns a string in the form of [PEtype][PEmоde} For example "EXE32" or "Driver32"
 * @returns {String}
 */
PE.getGeneralOptions=function(){};
/**
 * Get image base
 * @returns {UInt} 
 */
PE.getImageBase=function(){};
/**
 * This function returns the name of the imported function.
 * @param {UInt} nImport - The sequence number of the imported library (0…N).
 * @param {UInt} nFunctionNumber - The sequence number of the function in the library (0…N)
 * @returns {String}
 */
PE.getImportFunctionName=function(nImport,nFunctionNumber){};
/**
 * This function returns the name of the imported library.
 * @param {UInt} nImport - The sequence number of the imported library (0…N)
 * @returns {String}
 */
PE.getImportLibraryName=function(nImport){};
/**
 * The function returns the number of a section, where the import is located (address of entry point) (0…N)
 * @returns {Int} if no import returns -1
 */
PE.getImportSection=function(){};
/**
 * Get machine type
 * @returns {UShort} 
 */
PE.getMachineType=function(){};
/**
 * Get major linker version
 * @returns {UInt} 
 * @example
    var nMajor=PE.getMajorLinkerVersion();
    if(nMajor>3)
    {
        sName="Microsoft Linker";
        bDetected=1;
    }
 */
PE.getMajorLinkerVersion=function(){};
/**
 * This XML manifest from the resources.
 * @returns {String}
 * @example
    if(PE.getManifest().match(/requireAdministrator/))
    {
        sOptions=sOptions.append("admin");
    }
 */
PE.getManifest=function(){};
/**
 * Get minor linker version
 * @returns {UInt} 
 * @example
    var nMinor=PE.getMinorLinkerVersion();
    if(nMinor==55)
    {
        sName="LCC Linker";
        sVersion+="*";
        bDetected=1;
    }
 */
PE.getMinorLinkerVersion=function(){};
/**
 * This function returns .NET version.
 * @returns {String}
 * @example
    if(PE.isNET())
    {
        sVersion=PE.getNETVersion();
        bDetected=1;
    }
 */
PE.getNETVersion=function(){};
/**
 * Get number of imports
 * @returns {Int} 
 * @example
    if(PE.getNumberOfImports()==1)
    {
        if(PE.getNumberOfImportThunks(0)==2)
        {
            if(PE.section[0].Name=="ANDpakk2")
            {
                sVersion="2.X";
                bDetected=1;
            }
        }
    }
 */
PE.getNumberOfImports=function(){};
/**
 * This function returns the number of functions in the imported library.  
 * @param {UInt} nImport - The sequence number of the imported library (0…N).
 * @returns {UInt}
 * @example
    if(PE.getNumberOfImportThunks(0)==1)
    {
        bDetected=1;
    }
 */
PE.getNumberOfImportThunks=function(nImport){};
/**
 * Get number of sections
 * @returns {Int} 
 */
PE.getNumberOfSections=function(){};
/**
 * Get overlay offset
 * @returns {UInt} 
 */
PE.getOverlayOffset=function(){};
/**
 * Get overlay size
 * @returns {UInt} 
 */
PE.getOverlaySize=function(){};
/**
 * This function returns the version of the file. If the version can be found in resources. 
 * @param {String} sFileName - The file name.
 * @returns {String}
 */
PE.getPEFileVersion=function(sFileName){};
/**
 * This function returns a offset to resource with a specific name in the file.
 * @param {String} sFileName - The name of the resource.
 * @returns {Int} If an error occurs, -1 will be returned.
 */
PE.getResourceNameOffset=function(sName){};
/**
 * This function returns a size of resource with a specific name in the file.
 * @param {String} sFileName - The name of the resource.
 * @returns {Int} 
 */
PE.getResourceNameSize=function(sName){};
/**
 * Get section characteristics
 * @param {Int} nSectionNumber - Section number
 * @returns {UInt} 
 */
PE.getSectionCharacteristics=function(nSectionNumber){};
/**
 * Get section file offset
 * @param {Int} nSectionNumber - Section number
 * @returns {UInt} 
 */
PE.getSectionFileOffset=function(nSectionNumber){};
/**
 * Get section file size
 * @param {Int} nSectionNumber - Section number
 * @returns {UInt} 
 */
PE.getSectionFileSize=function(nSectionNumber){};
/**
 * Get section name
 * @param {Int} nSectionNumber - Section number
 * @returns {String} 
 */
PE.getSectionName=function(nSectionNumber){};
/**
 * Get section virtual address
 * @param {Int} nSectionNumber - Section number
 * @returns {UInt} 
 */
PE.getSectionVirtualAddress=function(nSectionNumber){};
/**
 * Get section virtual size
 * @param {Int} nSectionNumber - Section number
 * @returns {UInt} 
 */
PE.getSectionVirtualSize=function(nSectionNumber){};
/**
 * If the file contains sections with names “UPX0”, “UPX1”, this function  will return the string "UPX"
 * @param {String} sString1 - Section name 1
 * @param {String} sString2 - Section name 2
 * @returns {String} 
 */
PE.getSectionNameCollision=function(sString1,sString2){};
/**
 * This function returns the number of a section with a specific name 
 * @param {String} sSectionName - Section name
 * @returns {Int} (0-N) If there is no section with such name, -1 will be returned.
 */
PE.getSectionNumber=function(sSectionName){};
/**
 * This function returns the number of a section with a specific name. Can use regular expressions as the section name.
 * @param {String} sSectionName - Section name
 * @returns {Int} (0-N) If there is no section with such name, -1 will be returned.
 */
PE.getSectionNumberExp=function(sSectionName){};
/**
 * This function checks whether there exists a section with a specific name.
 * @param {String} sSectionName - Section name
 * @returns {Bool} 
 */
PE.isSectionNamePresent=function(sSectionName){};
/**
 * This function checks whether there exists a section with a specific name. Can use regular expressions as the section name.
 * @param {String} sSectionName - Section name
 * @returns {Bool} 
 */
PE.isSectionNamePresentExp=function(sSectionName){};
/**
 * @see {@link Binary.getSignature}
 */
PE.getSignature=function(){};
/**
 * @see {@link Binary.getSize}
 */
PE.getSize=function(){};
/**
 * Get size of code
 * @returns {Int} 
 */
PE.getSizeOfCode=function(){};
/**
 * Get size of unitialized data
 * @returns {Int} 
 */
PE.getSizeOfUninitializedData=function(){};
/**
 * This function checks whether the file is a console application.
 * @returns {Bool} 
 */
PE.isConsole=function(){};
/**
 * This function checks whether the file is a DLL
 * @returns {Bool} 
 */
PE.isDll=function(){};
/**
 * This function checks whether the file is a .NET application.
 * @returns {Bool} 
 */
PE.isNET=function(){};
/**
 * This function checks whether there is an overlay in the file.
 * @returns {Bool} 
 */
PE.isOverlayPresent=function(){};
/**
 * This function checks whether the file is 64 bit (PE+)
 * @returns {Bool} 
 * @example
    if(PE.isPEPlus())
    {
        sOptions="PE+";
    }
 */
PE.isPEPlus=function(){};
/**
 * This function checks whether there is a Rich signature in the file. For more information check {@link http://www.ntсоre.соm/files/riсhsign.htm|http://www.ntсоre.соm/files/riсhsign.htm} It is typical for the files made by using the MS Linker. 
 * @returns {Bool} 
  * @example
    if(PE.isRichSignaturePresent())
    {
        sName="Microsoft Linker";
        bDetected=1;
    }
 */
PE.isRichSignaturePresent=function(){};
/**
 * This function checks whether there is a resource with a specific name in the file.
 * @param {String} sFileName - The name of the resource
 * @returns {Bool} 
 * @example
    if(PE.isResourceNamePresent("PACKAGEINFO"))
    {
        bDetected=1;
    }
 */
PE.isResourceNamePresent=function(sName){};
/**
 * This function checks whether there is a string with a specific name in .NET.
 * @param {String} sString
 * @returns {Bool} 
 * @example
    if(PE.isNETStringPresent(0,"DotfuscatorAttribute"))
    {
        bDetected=1;
    }
 */
PE.isNETStringPresent=function(sString){};
/**
 * This function checks whether there is a unicode string with a specific name in .NET.
 * @param {String} sString
 * @returns {Bool} 
 * @example
    if(PE.isNETUnicodeStringPresent("E_TamperDetected"))
    {
        sVersion="3.X-4.X";
        bDetected=1;
    }
 */
PE.isNETUnicodeStringPresent=function(sString){};
/**
 * This function checks whether there is a function with a specific name in the import.
 * @param {String} sLibraryName - The name of the library
 * @param {String} sFunctionName - The name of the function
 * @returns {Bool} 
 * @example
 
 */
PE.isLibraryFunctionPresent=function(sLibraryName,sFunctionName){};
/**
 * This function checks whether there is a library with a specific name in the import.
 * @param {String} sLibraryName - The name of the library
 * @returns {Bool} 
 * @example
    if(PE.isLibraryPresent("MSVBVM50.DLL"))
    {
        sVersion="5.0";
        bDetected=1;
    }
 */
PE.isLibraryPresent=function(sLibraryName){};
/**
 * This function checks whether there is a signature int the section.
 * @see {@link Binary.compare}
 * @param {Int} nSection - Section number
 * @param {String} sSignature - Signature
 * @returns {Bool} 
 * @example
    if(PE.isSignatureInSectionPresent(0,"'ENIGMA'"))
    {
        bDetected=1;
    }
 */
PE.isSignatureInSectionPresent=function(nSection,sSignature){};
/**
 * @see {@link Binary.isSignaturePresent}
 */
PE.isSignaturePresent=function(nOffset,nSize,sSignature){};
/**
 * This function converts a file offset to a relative virtual address. 
 * @param {UInt} nOffset 
 * @returns {UInt} If an error occurs, -1 will be returned
 */
PE.OffsetToRVA=function(nOffset){};
/**
 * This function converts a file offset to a virtual address. 
 * @param {UInt} nOffset 
 * @returns {UInt} 
 */
PE.OffsetToVA=function(nOffset){};
/**
 * @see {@link Binary.readByte}
 */
PE.readByte=function(nOffset){};
/**
 * @see {@link Binary.readDword}
 */
PE.readDword=function(nOffset){};
/**
 * @see {@link Binary.readWord}
 */
PE.readWord=function(nOffset){};
/**
 * This function converts a relative virtual address to a file offset. 
 * @param {UInt} nRVA 
 * @returns {Int} If an error occurs, -1 will be returned.
 */
PE.RVAToOffset=function(nRVA){};
/**
 * This function converts a virtual address to a file offset. 
 * @param {UInt} nVA 
 * @returns {Int} If an error occurs, -1 will be returned
 */
PE.VAToOffset=function(nVA){};
/**
 * @see {@link Binary.getString}
 */
PE.getString=function(nOffset,nSize){};
/**
 * Get VersionString info
 * @param {String} sKey 
 * @returns {String} 
 */
PE.getVersionStringInfo=function(sKey){};