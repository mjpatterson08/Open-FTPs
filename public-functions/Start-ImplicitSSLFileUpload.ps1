Function Start-ImplicitSSLFileUpload
{
<#
.SYNOPSIS
    Cmdlet acts as a wrapper function to make uploading a file to an FTP
    Server that is configured to use Implicit SSL as simple as possible.
.DESCRIPTION
    Cmdlet acts as a wrapper function to make uploading a file to an FTP
    Server that is configured to use Implicit SSL as siple as possible.
    FTP over Implicit SSL typically uses a Control Connection that is set up
    on Port 990 of the server that must be an SSL connection. Also data transfers are
    typically done Passively over a seperate Data Connection on a Port provided by the
    Server that also must be an SSL Connection.
.PARAMETER ServerIPAddress
    This parameter is required and is the 1st positional parameter. It will only accept
    valid IP Addresses and is validated using the .Net IPAddress Type Accelerator. Parameter 
    will be used as the IP Address to connect on.
.PARAMETER ControlPortNumber
    This parameter is required and is the 2nd positional parameter. This is the Port
    that will be used as the Control Connection for FTP. Typically if configured for Impilicit
    SSL this Port number is 990.
.PARAMETER LocalFilePath
    This parameter is required and is the 3rd positional parameter. It will accept
    a String Type as input and should be the full path to the local file that is to be
    uploaded to the FTP Server.
    Ex. "C:\FileArchive\ExampleFile.txt"
.PARAMETER RemoteDirectory
    This parameter is required and is the 4th positional parameter. It will accept
    a String Type as input and should be the full path for the remote file once it has
    been uploaded to the FTP Server.
    Ex. "/FTPServerArchive/InboundFileDirectory"
.PARAMETER UserName
    This parameter is required and is the 5th positional parameter. It will accept
    a string as input, that string needs to be the UserName of the FTP Account.
.PARAMETER Password
    This parameter is required and is the 6th positional parameter. It will accept
    a string as input, that string needs to be the Password of the FTP Account.
.PARAMETER SelfSigned
    This parameter is not required and is a switch parameter that is used to configure the SSL
    Connection. If provided it will allow a self signed Certificate to be used to configure the SSL
    Connection, if not provided the default .Net SSL constructor will be used which may throw an
    error when connecting.
.EXAMPLE
    Start-ImplicitSSLFileUpload -SeverIPAddress "1.2.3.4" -ControlPortNumber 990 -LocalFilePath "C:\ExampleFile.txt" -RemoteDirectory /FTPServerArchive/InboundFileDirectory" -UserName "ExampleUserName" -Password "ExamplePassword"

    This command will upload the file specified in the LocalFilePath parameter to the directory on the FTP
    Server specified in the RemoteDirectory parameter. This will use the default .net SSL stream constructor
    which may throw an error when validating the Server SSL Certificate.
.EXAMPLE
    Start-ImplicitSSLFileUpload -SeverIPAddress "1.2.3.4" -ControlPortNumber 990 -LocalFilePath "C:\ExampleFile.txt" -RemoteDirectory /FTPServerArchive/InboundFileDirectory" -UserName "ExampleUserName" -Password "ExamplePassword" -SelfSigned

    This command will upload the file specified in the LocalFilePath parameter to the directory on the FTP
    Server specified in the RemoteDirectory parameter. This will use a custom .net SSL constructor that will
    return True for the Server's SSL Certificate.
.NOTES
    Author: Michael J. Patterson
#>
    [CmdletBinding()]
    Param([Parameter(Mandatory = $True, Position = 0)]
          [ValidateNotNullorEmpty()]
          [IPAddress]$ServerIPAddress,
          
          [Parameter(Mandatory = $True, Position = 1)]
          [ValidateRange(1,65535)]
          [Int]$ControlPortNumber,
          
          [Parameter(Mandatory = $True, Position = 2)]
          [ValidateScript({Test-Path $_})]
          [String]$LocalFilePath,

          [Parameter(Mandatory = $True, Position = 3)]
          [ValidateNotNullorEmpty()]
          [String]$RemoteDirectory,
          
          [Parameter(Mandatory = $True, Position = 4)]
          [ValidateNotNullorEmpty()]
          [String]$UserName,
          
          [Parameter(Mandatory = $True, Position = 5)]
          [ValidateNotNullorEmpty()]
          [String]$Password,
          
          [Parameter(Mandatory = $False)]
          [ValidateNotNullorEmpty()]
          [Switch]$SelfSigned)

    Write-Verbose "BEGIN Control Connection Verbose Stream--------------"
    $TCPControlSocket = New-TCPClientSocket -ServerIPAddress $ServerIPAddress -ServerPortNumber $ControlPortNumber

    $FTPServerParams = @{
        ServerIPAddress = $ServerIPAddress
        TCPClientSocket = $TCPControlSocket
    }
    if ($SelfSigned)
    {
        $FTPServerParams.TransmissionContext = SSLSelfSigned
    }
    else
    {
         $FTPServerParams.TransmissionContext = StandardSSL
    }

    $FTPServerControlConnection = Connect-FTPServer @FTPServerParams

    $ControlConnectionCommandWriter = New-FTPCommandDelegate -FTPServerConnection $FTPServerControlConnection

    $controlConnection = @{
        CommandWriter = $ControlConnectionCommandWriter
        FTPServerConnection = $FTPServerControlConnection
    }
    Send-FTPAuthCommand -UserName $UserName -Password $Password @controlConnection | Out-Null 
    Send-FTPTransferSetUpCommand @controlConnection| Out-Null
    $PassiveHandshakePortResponse = Send-FTPPassiveCommand @controlConnection
    Send-FTPFileTransferCommand -LocalFilePath $LocalFilePath -RemoteFilePathRoot $RemoteDirectory @controlConnection | Out-Null
    Write-Verbose "END Control Connection Verbose Stream---------------"

    Write-Verbose "BEGIN Data Connection Verbose Stream---------------"
    $TCPDataSocket = New-TCPClientSocket -ServerIPAddress $ServerIPAddress -ServerPortNumber $PassiveHandshakePortResponse

    # reuse FTPServerParams from above and just change the socket
    $FTPServerParams.TCPClientSocket = $TCPDataSocket
    $FTPServerDataConnection = Connect-FTPServer @FTPServerParams

    Send-LocalFileByte -FTPServerConnection $FTPServerDataConnection -LocalFilePath $LocalFilePath
    Close-TCPNetworkStream -FTPServerConnection $FTPServerDataConnection -ConnectionType DataConnection
    Close-TCPClientSocket -TCPClientSocket $TCPDataSocket -SocketType DataSocket
    Write-Verbose "END Data Connection Verbose Stream---------------"
    
    Write-Verbose "BEGIN Control Connection Clean Up Verbose Stream---------------"
    Close-FTPCommandDelegate -CommandWritingDelegate $ControlConnectionCommandWriter
    Close-TCPNetworkStream -FTPServerConnection $FTPServerControlConnection -ConnectionType ControlConnection
    Close-TCPClientSocket -TCPClientSocket $TCPControlSocket -SocketType ControlSocket
    Write-Verbose "End Control Connection Clean Up Verbose Stream---------------"
    Write-Output $FTPServerTranscript
}
