Function New-FTPCommandDelegate
{
<#
.SYNOPSIS
    This Cmdlet creates a .Net Stream Writer that can be used as a delegate to
    write FTP Commands to the Control Connection.
.DESCRIPTION
    This Cmdlet creates a .Net Stream Writer that can be used as a delegate to
    write FTP Commands to the Control Connection.
.PARAMETER FTPServerConnection
    This parameter is required and is the 1st positional parameter. It will
    accept a Network Stream as input.
.EXAMPLE
    New-FTPCommandDelegate -FTPServerConnection $FTPServerConnection

    This Command will return an FTP Command Writing Delegate that can be
    used to write FTP Commands to the FTP Control Connection.
.NOTES
    Author: Michael J. Patterson
#>
    [CmdletBinding()]
    Param([Parameter(Mandatory = $True, Position = 0)]
          [ValidateNotNullorEmpty()]
          $FTPServerConnection)
    Write-Verbose "Creating .Net Stream Writer to act as a FTP Command Delegate"
    $CommandWriter = New-Object System.IO.StreamWriter($FTPServerConnection)
    Write-Output $CommandWriter
}
