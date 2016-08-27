Function Test-ConnectionEncryption
{
<#
.SYNOPSIS
    This Cmdlet tests a Network Stream's Security context and will return
    True or False. 
.DESCRIPTION
    This Cmdlet tests a Network Stream's Security context and will return
    True or False. If an SSL Stream is provided as input this Cmdlet will
    check the .Net IsEncrypted property and return its True or False value, if
    the property is True it will supply details on the encryption used in its verbose
    output. If a standard Network Stream is provided as input True will be returned as
    no security was neccesary.
.PARAMETER FTPServerConnection
    This parameter is required and is the 1st positional parameter. It will
    accept a Network Stream as input.
.EXAMPLE
    Test-ConnectionEncryption -FTPServerConnection $FTPServerConnection

    This command will return a True or False value based on the type of
    Network Stream that is provided.
.NOTES
    Author: Michael J. Patterson
#>
    [CmdLetBinding()]
    [OutputType('System.Boolean')]
    Param([Parameter(Mandatory=$True, Position=0)]
          [ValidateNotNullorEmpty()]
          $FTPServerConnection)

    Write-Verbose "Testing Network Stream's Transmission Context"
    if ($FTPServerConnection -is [System.Net.Security.SslStream])
    {
        if ($FTPServerConnection.IsEncrypted -eq $True) 
        {
            Write-Verbose "Encryption Test Response: Test Passed, .Net SSLStream' IsEncrypted Property is True, details below"
            Write-Verbose "CipherAlgorithm: $($FTPServerConnection.CipherAlgorithm)"
            Write-Verbose "CipherStrength: $($FTPServerConnection.CipherStrength)"
            Write-Verbose "HashAlgorithm: $($FTPServerConnection.HashAlgorithm)"
            Write-Verbose "HashStrength: $($FTPServerConnection.HashStrength)"
            Return $True
        }
        else
        {
            Write-Verbose "Encryption Test Response: Test Failed, .Net SSLStream's IsEncrypted Property is False"
            Return $False
        }
    }
    else
    {
        Write-Verbose "Encryption Test Response: User defined default FTP which occurs over Plain Text no encryption test required"
        Return $True
    }
}
