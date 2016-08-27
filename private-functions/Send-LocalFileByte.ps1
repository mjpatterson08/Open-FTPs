Function Send-LocalFileByte
{
<#
.SYNOPSIS
    This Cmdlet handles writing the actual file bytes of the local file
    to be transferred to the FTP Server.
.DESCRIPTION
    This Cmdlet handles writing the actual file bytes of the local file
    to be transferred to the FTP Server. This is accomplished by reading in the
    local file bytes and writing them to the Data Connection Stream.
.PARAMETER FTPServerConnection
    This parameter is required and is the 1st positional parameter. It will accept
    a Network Stream as input and will be used to read the FTP Server's Responses to the
    written commands.
.PARAMETER LocalFilePath
    This parameter is required and is the 2nd positional parameter. It will accept
    a String Type as input and should be the full path to the local file that is to be
    uploaded to the FTP Server.
.EXAMPLE
    Send-LocalFileByte -FTPServerConnection $FTPServerConnection -LocalFilePath "C:\Example.txt"

    This command will send the bytes of the local file to the FTP Server through the FTP Server
    Connection.
.NOTES
    Author: Michael J. Patterson
#>
    [CmdletBinding()]
    Param([Parameter(Mandatory = $False, Position = 0)]
          [ValidateNotNullorEmpty()]
          $FTPServerConnection,
          
          [Parameter(Mandatory = $True, Position = 1)]
          [ValidateScript({Test-Path $_})]
          [String]$LocalFilePath)

    Write-Verbose "Retreiving Local File Bytes"
    $LocalFileBytes = Get-Content -Path $LocalFilePath -Encoding Byte
    $LocalFileLength = $LocalFileBytes.Length
    Write-Verbose "Sending bytes from local file"
    $FTPServerConnection.Write($LocalFileBytes, 0, $LocalFileLength)
    Write-Verbose "Local file bytes transferred"
}
