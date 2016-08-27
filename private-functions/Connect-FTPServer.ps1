Function Connect-FTPServer
{
<#
.SYNOPSIS
    This Cmdlet acts a wrapper function to make connecting to an FTP Server
    as simple as possible.
.DESCRIPTION
    This Cmdlet acts a wrapper function to make connecting to an FTP Server
    as simple as possible. Cmdlet takes a Server IP Address, TCP Client Socket,
    and a given Transmission Context and returns back the requested type of connection.
    If SSL is requested the stream is tested using the Test-ConnectionEncryption Cmdlet
    before before returning the Network Stream and will fail if it is not encrypted.
.PARAMETER ServerIPAddress
    This parameter is required and is the 1st positional parameter. It will only accept
    valid IP Addresses and is validated using the .Net IPAddress Type Accelerator. It will be
    used as the Destination IP to authenticate an SSL Stream.
.PARAMETER TCPClientSocket
    This parameter is required and is the 2nd positional parameter. It will accept
    the TCP Client Socket the Network Stream will be built on.
.PARAMETER TransmissionContext
    This parameter is required and is the 3rd positional parameter. It will only
    accept 3 possible string inputs. ClearText, StandardSSL, SSLSelfSigned are the acceptable
    inputs and will set the mode of the Network Stream used for FTP communication.
.EXAMPLE
    Connect-FTPServer -ServerIPAddress 1.2.3.4 -TCPClientSocket $TCPClientSocket -TransmissionContext ClearText

    This will open a Network Stream as plain text to allow standard FTP communication and return it
    to the pipeline.
.EXAMPLE
    Connect-FTPServer -ServerIPAddress 1.2.3.4 -TCPClientSocket $TCPClientSocket -TransmissionContext StandardSSL

    This will open a Network Stream and upgrade it to an SSL Stream to allow FTP communication and
    return it to the pipeline. This will use the Windows default SSL Cert Validation.
.EXAMPLE
    Connect-FTPServer -ServerIPAddress 1.2.3.4 -TCPClientSocket $TCPClientSocket -TransmissionContext SSLSelfSigned

    This will open a Network Stream and upgrade it to an SSL Stream to allow FTP communication and
    return it to the pipeline. This will allow any cert to be provided to secure the stream including self
    signed.
.NOTES
    Author: Michael J. Patterson
#>
    [CmdletBinding()]
    Param([Parameter(Mandatory = $True, Position = 0)]
          [ValidateNotNullorEmpty()]
          [IpAddress]$ServerIPAddress,

          [Parameter(Mandatory = $True, Position = 1)]
          [ValidateNotNullorEmpty()]
          $TCPClientSocket,
          
          [Parameter(Mandatory = $True, Position = 2)]
          [ValidateSet("ClearText", "StandardSSL", "SSLSelfSigned")]
          [String]$TransmissionContext)
    
    $FTPServerConnection = Open-TCPNetworkStream -TCPClientSocket $TCPClientSocket -ServerIPAddress $ServerIPAddress -TransmissionContext $TransmissionContext
    $TestStreamSecurity  = Test-ConnectionEncryption -FTPServerConnection $FTPServerConnection

    if ($TestStreamSecurity)
    {
        Write-Output $FTPServerConnection
    }
    else
    {
        Throw "Error: Network Stream Security is compromised ending process."
    }
}
