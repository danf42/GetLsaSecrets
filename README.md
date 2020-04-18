# Get LSA Secrets
C# Implementation of Get-LSASecrets

## Background
Attempted to use Get-LSASecrets documented in the article[Use PowerShell to Decrypt LSA Secrets from the Registry](https://devblogs.microsoft.com/scripting/use-powershell-to-decrypt-lsa-secrets-from-the-registry/).  However, on my Windows 10 1909 VM, the script was immediately detected on download.  I decided to implement the solution in C#.  This was also a good opportunity to start learning C# 

## Implementation
- Project build configuration is set to build 32-bit binary to satisfy the 32-bit session requirement.  
- The program will check if it is running with elevated privliges or as SYSTEM.  If running as SYSTEM, it will not attempt to duplicate the LSASS token.  If running with Administrative privileges, it will duplicate the LSASS token before continuing.  Otherwise the program will exit.  

## Results
This implementation has been successfully tested against 64-bit versions of Windows 10 1909, Windows 7, and Windows 2008 R2.   
The C# version was not detected by Windows Defender and successfully dumped the LSA Secrets.  

# Acknowledgments
The following resources were used to create the C# solution.  
 - [Use PowerShell to Decrypt LSA Secrets from the Registry](https://devblogs.microsoft.com/scripting/use-powershell-to-decrypt-lsa-secrets-from-the-registry/)
 - [Get-LSASecrets](https://github.com/samratashok/nishang/blob/master/Gather/Get-LSASecret.ps1) from Nishang
 - [Enable-DuplicateToken](https://github.com/samratashok/nishang/blob/master/Escalation/Enable-DuplicateToken.ps1) from Nishang
 - [LSAUtil](http://www.pinvoke.net/default.aspx/advapi32/LSARetrievePrivateData.html) class from [Pinvoke.net](http://www.pinvoke.net)
 
 # Disclaimer
You are only authorized to use this tool on systems that you have permission to use it on. It was created for research purposes only.  The creator takes no responsibility of any mis-use of this program.