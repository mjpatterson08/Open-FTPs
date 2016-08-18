Function Send-FTPPassiveCommand
{
<#
.SYNOPSIS
    This Cmdlet handles setting the FTP Server into Passive Mode and
    then parses the Passive Response to formulate the secondary
    data connection that will be used to transfer the bytes of the files
    being transferred back and forth.
.DESCRIPTION
    This Cmdlet handles setting the FTP Server into Passive Mode and
    then parses the Passive Response to formulate the secondary
    data connection that will be used to transfer the bytes of the files
    being transferred back and forth. This is accomplished by wrapping a
    Command Writing Delegate and an FTP Server Connection.
.PARAMETER CommandWriter
    This parameter is required and is the 1st positional parameter. It will accept
    a CommandWritingDelegate as input. This will be used to write the commands to the FTP
    Server Stream.
.PARAMETER FTPServerConnection
    This parameter is required and must is the 2nd positional parameter. It will accept
    a Network Stream as input and will be used to read the FTP Server's Responses to the
    written commands.
.PARAMETER PassiveCommand
    This parameter is not required and is the 3rd positional parameter. It will accept
    a string as input; however, the default FTP Command is already the default value of this
    parameter.
.EXAMPLE
    Send-FTPPassiveCommand -CommandWriter $CommandWriter -FTPServerConnection $FTPServerConnection

    This command will send the Passive FTP Command to the FTP Server, parse the Server's Response
    for the new Port Number that will be used to set up the Data Connection and returns the required
    Port Number to the pipeline.
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
          [String]$PassiveCommand = 'PASV')

    $Command = Write-FTPCommand -FTPCommand $PassiveCommand -CommandWriter $CommandWriter -FTPServerConnection $FTPServerConnection -ReturnResponse
    $RawResponse             = $Command -split '\s'
    $IPandPorts              = $RawResponse[4]
    $RemoveOpenParen         = $IPandPorts.Replace('(', '')
    $RemoveCloseParen        = $RemoveOpenParen.Replace(')', '')
    $SplitonComma            = $RemoveCloseParen.Split(',')
    [int]$FirstNumforPort    = $SplitonComma[-2]
    [int]$SecondNumforPort   = $SplitonComma[-1]
    [int]$DataConnectionPort = (($FirstNumforPort * 256) + $SecondNumforPort)
    Write-Output $DataConnectionPort
}
