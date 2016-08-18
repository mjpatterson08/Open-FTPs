Function Send-FTPFileTransferCommand
{
<#
.SYNOPSIS
    This Cmdlet handles sending the FTP Command to upload a file on the FTP
    Server.
.DESCRIPTION
    This Cmdlet handles sending the FTP Command to upload a file on the FTP
    Server. This is accomplished by wrapping a Command Writing Delegate and FTP
    Server Connection to send the appropriate command.
.PARAMETER CommandWriter
    This parameter is required and is the 1st positional parameter. It will accept
    a CommandWritingDelegate as input. This will be used to write the commands to the FTP
    Server Stream.
.PARAMETER FTPServerConnection
    This parameter is required and is the 2nd positional parameter. It will accept
    a Network Stream as input and will be used to read the FTP Server's Responses to the
    written commands.
.PARAMETER LocalFilePath
    This parameter is required and is the 3rd positional parameter. It will accept
    a String Type as input and should be the full path to the local file that is to be
    uploaded to the FTP Server.
.PARAMETER RemoteFilePathRoot
    This parameter is required and is the 4th positional parameter. It will accept
    a String Type as input and should be the full path for the remote file once it has
    been uploaded to the FTP Server.
.EXAMPLE
    Send-FTPFileTransferCommand -CommandWriter $CommandWriter -FTPServerConnection $FTPServerConnection -LocalFilePath "c:\example.txt" -RemoteFilePathRoot "/Inbound/ExampleFolder"

    This command will send the FTP Command required to store the local file in the provided remote
    folder location.
.NOTES
    Author: Michael J. Patterson
#>
    [CmdletBinding()]
    Param([Parameter(Mandatory = $True, Position = 0)]
          [ValidateNotNullorEmpty()]
          $CommandWriter,

          [Parameter(Mandatory = $True, Position = 1)]
          [ValidateNotNullorEmpty()]
          $FTPServerConnection,

          [Parameter(Mandatory = $True, Position = 2)]
          [ValidateScript({Test-Path $_})]
          [String]$LocalFilePath,
          
          [Parameter(Mandatory = $True, Position = 3)]
          [ValidateNotNullorEmpty()]
          [String]$RemoteFilePathRoot)

    $LocalFileName = Get-Item -Path $LocalFilePath
    $CompleteRemoteFilePath = $RemoteFilePathRoot + '/' + $LocalFileName.Name
    $FTPFileUploadCommand = "STOR $CompleteRemoteFilePath"
    Write-FTPCommand -FTPCommand $FTPFileUploadCommand -CommandWriter $CommandWriter -FTPServerConnection $FTPServerConnection
}
