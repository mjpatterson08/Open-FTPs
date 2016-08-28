Function Send-FTPTransferSetUpCommand
{
<#
.SYNOPSIS
    This Cmdlet handles setting various transfer settings required to complete and
    FTP File Transfer.
.DESCRIPTION
    This Cmdlet handles setting various transfer settings required to complete and
    FTP File Transfer. These settings inlcude the following FTP Commands TYPE, STRU,
    MODE, and PROT. This is accomplished by wrapping a Command Writing Delegate and
    an FTP Server Connection.
.PARAMETER CommandWriter
    This parameter is required and is the 1st positional parameter. It will accept
    a CommandWritingDelegate as input. This will be used to write the commands to the FTP
    Server Stream.
.PARAMETER FTPServerConnection
    This parameter is required and is the 2nd positional parameter. It will accept
    a Network Stream as input and will be used to read the FTP Server's Responses to the
    written commands.
.PARAMETER TypeCommand
    This parameter is not required and is the 3rd positional parameter. It will accept
    a string as input; however, the appropriate FTP Command is already the default value of this
    parameter.
.PARAMETER StruCommand
    This parameter is not required and is the 4th positional parameter. It will accept
    a string as input; however, the appropriate FTP Command is already the default value of this
    parameter.
.PARAMETER ModeCommand
    This parameter is not required and is the 5th positional parameter. It will accept
    a string as input; however, the appropriate FTP Command is already the default value of this
    parameter.
.PARAMETER ProtCommand
    This parameter is not required and is the 6th positional parameter. It will accept
    a string as input; however, the appropriate FTP Command is already the default value of this
    parameter.
.EXAMPLE
    Send-FTPTransferSetUpCommand -CommandWriter $CommandWriter -FTPServerConnection $FTPServerConnection

    This command will send the Passive FTP Command to the FTP Server, parse the Server's Response
    for the new Port Number that will be used to set up the Data Connection and returns the required
    Port Number.
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
          [String]$TypeCommand = 'TYPE I',
          
          [Parameter(Mandatory = $False, Position = 3)]
          [ValidateNotNullorEmpty()]
          [String]$StruCommand = 'STRU F',
          
          [Parameter(Mandatory = $False, Position = 4)]
          [ValidateNotNullorEmpty()]
          [String]$ModeCommand = 'MODE S',
          
          [Parameter(Mandatory = $False, Position = 5)]
          [ValidateNotNullorEmpty()]
          [String]$ProtCommand = 'PROT P')

    Write-FTPCommand -FTPCommand @($TypeCommand, $StruCommand, $ModeCommand, $ProtCommand) -CommandWriter $CommandWriter -FTPServerConnection $FTPServerConnection
}
