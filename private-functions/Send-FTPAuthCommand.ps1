Function Send-FTPAuthCommand
{
<#
.SYNOPSIS
    This Cmdlet handles FTP authentication with the FTP Server.
.DESCRIPTION
    This Cmdlet handles FTP authentication with the FTP Server.
    That is accomplished by wrapping a Command Writing Delegate and
    and FTP Server Connection.
.PARAMETER CommandWriter
    This parameter is required and is the 1st positional parameter. It will accept
    a CommandWritingDelegate as input. This will be used to write the commands to the FTP
    Server Stream.
.PARAMETER FTPServerConnection
    This parameter is required and is the 2nd positional parameter. It will accept
    a Network Stream as input and will be used to read the FTP Server's Responses to the
    written commands.
.PARAMETER UserName
    This parameter is required and is the 3rd positional parameter. It will accept
    a string as input, that string needs to be the UserName of the FTP Account.
.PARAMETER Password
    This parameter is required and is the 4th positional parameter. It will accept
    a string as input, that string is to be the Password of the FTP Account.
.EXAMPLE
    Send-FTPAuthCommand -CommandWriter $CommandWriter -FTPServerConnection $FTPServerConnection -UserName ExampleUsername -Password ExamplePassword

    This command will authenticate with the FTP Server by sending the UserName and Password commands
    to the FTP server.
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
          
          [Parameter(Mandatory = $False, Position = 2)]
          [ValidateNotNullorEmpty()]
          [String]$UserName,
          
          [Parameter(Mandatory = $False, Position = 3)]
          [ValidateNotNullorEmpty()]
          [String]$Password)

    Write-FTPCommand -FTPCommand @("USER $UserName","PASS $Password") -CommandWriter $CommandWriter -FTPServerConnection $FTPServerConnection -Verbose
}
