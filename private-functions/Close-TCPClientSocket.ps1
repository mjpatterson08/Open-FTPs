
Function Close-TCPClientSocket
{
<#
.SYNOPSIS
    This Cmdlet handles the clean up of a TCP Client Socket.
.DESCRIPTION
    This Cmdlet handles the clean up of a TCP Client Socket.
    Cmdlet will run both the dispose and close methods of the TCP Client Socket
    that is passed to it. Also for clarity a SocketType is passed
    in to indicate whether or not it is the ControlSocket or the DataSocket that
    is being cleaned up.
.PARAMETER TCPClientSocket
    This parameter is required and is the 1st positional parameter. It will
    accept a TCP Client Socket as input.
.PARAMETER SocketType
    This parameter is required and is the 2nd positional parameter. It will only
    accept two possible string inputs, ControlSocket and DataSocket, and is used
    for clear verbose output.
.EXAMPLE
    Close-TCPClientSocket -TCPClientSocket $TCPClientSocket -SocketType ControlSocket

    This command will run the dispose and close methods of the Socket provided as input and will use
    ControlSocket in it's verbose output.
.EXAMPLE
    Close-TCPClientSocket -TCPClientSocket $TCPClientSocket -SocketType DataSocket

    This command will run the dispose and close methods of the Socket provided as input and will use
    DataSocket in it's verbose output.
.NOTES
    Author: Michael J. Patterson
#>
    [CmdletBinding()]
    Param([Parameter(Mandatory = $True, Position = 0)]
          [ValidateNotNullorEmpty()]
          $TCPClientSocket,
          
          [Parameter(Mandatory = $True, Position = 1)]
          [ValidateSet("ControlSocket", "DataSocket")]
          [String]$SocketType)

    Write-Verbose "Handling $SocketType TCP Socket Clean Up"
    Write-Verbose "Closing, $SocketType"
    $TCPClientSocket.Dispose()
    $TCPClientSocket.Close()
    Write-Verbose "$SocketType Closed"
}
