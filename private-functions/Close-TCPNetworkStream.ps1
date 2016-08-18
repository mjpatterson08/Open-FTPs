Function Close-TCPNetworkStream
{
<#
.SYNOPSIS
    This Cmdlet handles the clean up of an FTP Server Connection.
.DESCRIPTION
    This Cmdlet handles the clean up of an FTP Server Connection.
    Cmdlet will run both the dispose and close methods of the Network
    Stream that is passed to it. Also for clarity a connection type is passed
    in to indicate whether or not it is the Control Connection or the Data
    Connection that is being cleaned up.
.PARAMETER FTPServerConnection
    This parameter is required and is the 1st positional parameter. It will
    accept a Network Stream as input.
.PARAMETER ConnectionType
    This parameter is required and is the 2nd positional parameter. It will only
    accept two possible string inputs, ControlConnection and DataConnection, and is used
    for clear verbose output.
.EXAMPLE
    Close-TCPNetworkStream -FTPServerConnection $FTPServerConnection -ConnectionType ControlConnection

    This command will run the dispose and close methods of the Stream provided as input and will use
    ControlConnection in it's verbose output.
.EXAMPLE
    Close-TCPNetworkStream -FTPServerConnection $FTPServerConnection -ConnectionType DataConnection

    This command will run the dispose and close methods of the Stream provided as input and will use
    DataConnection in it's verbose output.
.NOTES
    Author: Michael J. Patterson
#>
    [CmdletBinding()]
    Param([Parameter(Mandatory = $True, Position = 0)]
          [ValidateNotNullorEmpty()]
          $FTPServerConnection,
          
          [Parameter(Mandatory = $True, Position = 1)]
          [ValidateSet("ControlConnection", "DataConnection")]
          [String]$ConnectionType)

    Write-Verbose "Handling $ConnectionType Network Stream Clean Up"
    Write-Verbose "Closing, $ConnectionType"
    $FTPServerConnection.Dispose()
    $FTPServerConnection.Close()
    Write-Verbose "$ConnectionType Closed"
}
