Function New-TCPClientSocket
{
<#
.SYNOPSIS
    This Cmdlet creates a TCP Client Socket by accepting an IP Address and Port Number
    and returns the Socket to the Pipeline.
.DESCRIPTION
    This Cmdlet creates a TCP Client Socket by accepting an IP Address and Port Number
    and returns the Socket to the Pipeline. Cmdlet is built on top of the .Net TCP Client
    Class, see MSDN TCP Client Class for more details. This is used to hanlde the set up
    of Control and Data Connections to the FTP Server.
.PARAMETER ServerIPAddress
    This parameter is required and is the 1st positional parameter. It will only accept
    valid IP Addresses and is validated using the .Net IPAddress Type Accelerator. Parameter 
    will be used as the IP Address to connect on.
.PARAMETER ServerPortNumber
    This parameter is required and is the 2nd positional parameter. It will accept
    a value of type Int as input and will be used as the port number to connect on.
.EXAMPLE
    New-TCPClientSocket -ServerIPAddress 1.2.3.4 -ServerPortNumber 990

    This Command will return a TCP Client Socket object to the pipeline connected
    to the specified IP Address and Port.

.NOTES
    Author: Michael J. Patterson
#>
    [CmdletBinding()]
    Param([Parameter(Mandatory = $True, Position = 0)]
          [ValidateNotNullorEmpty()]
          [IpAddress]$ServerIPAddress,
          
          [Parameter(Mandatory = $True, Position = 1)]
          [ValidateRange(1,65535)]
          [Int]$ServerPortNumber)

    Try
    {
        Write-Verbose "Creating TCP connection to FTP Server Address: $ServerIPAddress on Port Number: $ServerPortNumber"
        $TCPClientSocket = New-Object -TypeName System.Net.Sockets.TcpClient($ServerIPAddress, $ServerPortNumber)
        Write-Verbose "TCP Connection to FTP Server Established"
    }
    Catch [Exception]
    {
        Write-Verbose "Error: Failed to establish TCP Connection to FTP Server Address: $ServerIPAddress on Port Number: $ServerPortNumber"
        Return $_.Exception.Message
    }
    Write-Output $TCPClientSocket
}

Function Open-TCPNetworkStream
{
<#
.SYNOPSIS
    This Cmdlet opens a TCP Network Stream and sets the transmission context using
    the provided TCP Client Socket and returns it to the pipeline.
.DESCRIPTION
    This Cmdlet opens a TCP Network Stream and sets the transmission context using
    the provided TCP Client Socket and returns it to the pipeline.. Cmdlet can return
    a plain text Network Stream for standard FTP communication or an SSL Stream
    for secure FTPS communication.
.PARAMETER TCPClientSocket
    This parameter is required and is the 1st positional parameter. It will accept
    the TCP Client Socket the Network Stream will be built on.
.PARAMETER ServerIPAddress
    This parameter is required and is the 2nd positional parameter. It will only accept
    valid IP Addresses and is validated using the .Net IPAddress Type Accelerator. It will be
    used as the Destination IP to authenticate an SSL Stream.
.PARAMETER TransmissionContext
    This parameter is required and is the 3rd positional parameter. It will only
    accept 3 possible string inputs. ClearText, StandrdSSL, SSLSelfSigned are the acceptable
    inputs and will set the mode of the Network Stream used for FTP communication.
.EXAMPLE
    Open-TCPNetworkStream -TCPClientSocket $TCPClient -ServerIPAddress 1.2.3.4 -TransmissionContext ClearText

    This will open a Network Stream as plain text to allow standard FTP communication and return it
    to the pipeline.
.EXAMPLE
    Open-TCPNetworkStream -TCPClientSocket $TCPClient -ServerIPAddress 1.2.3.4 -TransmissionContext StandardSSL

    This will open a Network Stream and upgrade it to an SSL Stream to allow FTP communication and
    return it to the pipeline. This will use the Windows default SSL Cert Validation.
.EXAMPLE
    Open-TCPNetworkStream -TCPClientSocket $TCPClient -ServerIPAddress 1.2.3.4 -TransmissionContext SSLSelfSigned

    This will open a Network Stream and upgrade it to an SSL Stream to allow FTP communication and
    return it to the pipeline. This will allow any cert to be provided to secure the stream including self
    signed.
.NOTES
    Author: Michael J. Patterson
#>
    [CmdletBinding()]
    Param([Parameter(Mandatory = $True, Position = 0)]
          [ValidateNotNullorEmpty()]
          $TCPClientSocket,

          [Parameter(Mandatory = $True, Position = 1)]
          [ValidateNotNullorEmpty()]
          [IpAddress]$ServerIPAddress,

          [Parameter(Mandatory = $True, Position = 2)]
          [ValidateSet("ClearText", "StandardSSL", "SSLSelfSigned")]
          [String]$TransmissionContext)

    Try
    {
        Write-Verbose "Attempting to Open Network Stream to FTP Server over Client Socket"
        $NetworkStream = $TCPClientSocket.GetStream()
        Write-Verbose "Network Stream Established, Setting Transmission Context"

        Switch ($TransmissionContext)
        {
            "ClearText"
            {
                Write-Verbose "Transmition Context: $TransmissionContext, FTP will occur in Plain Text"
                Write-Output $NetworkStream
            }
            "StandardSSL"
            {
                Write-Verbose "Transmition Context: $TransmissionContext, FTP will occur using Standard SSL\TLS"
                Try
                {
                    Write-Verbose "Beginning SSL\TLS Handshake"
                    $SSLStream = New-Object -TypeName System.Net.Security.SslStream($NetworkStream, $False)
                    $SSLStream.AuthenticateAsClient($ServerIPAddress)
                }
                Catch [Exception]
                {
                    Write-Verbose "SSL\TLS Connection Failed, Channel is Insecure, Closing Connection"
                    $NetworkStream.Close()
                    Return $_.Exception.Message
                }
                Write-Verbose "SSL\TLS Handshake Authenticated, Channel is Secure"
                $NetworkStream = $SSLStream
                Write-Output $NetworkStream
            }
            "SSLSelfSigned"
            {
                Write-Verbose "Transmition Context: $TransmissionContext, FTP will occur allowing Self Signed SSL\TLS"
                Try
                {
                    Write-Verbose "Beginning SSL\TLS Handshake"
                    $SSLDelegate = {
                    Param([Object]$Sender,
                          [System.Security.Cryptography.X509Certificates.X509Certificate]$Certificate,
                          [System.Security.Cryptography.X509Certificates.X509Chain]$Chain,
                          [System.Net.Security.SslPolicyErrors]$SSLPolicyErrors)
                          Return $True}

                    $SSLStream = New-Object -TypeName System.Net.Security.SslStream($NetworkStream, $False, $SSLDelegate)
                    $SSLStream.AuthenticateAsClient($ServerIPAddress)
                }
                Catch [Exception]
                {
                    Write-Verbose "SSL\TLS Connection Failed, Channel is Insecure, Closing Connection"
                    $NetworkStream.Close()
                    Return $_.Exception.Message
                }
                Write-Verbose "SSL\TLS Handshake Authenticated"
                $NetworkStream = $SSLStream
                Write-Output $NetworkStream
            }
        }
    }
    Catch [Exception]
    {
        Write-Verbose "Error: Failed to Open TCP Network Stream"
        Return $_.Exception.Message
    }
}
