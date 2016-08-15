[String]$FTPServerTranscript = ""

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

Function Test-ConnectionEncryption
{
<#
.SYNOPSIS
    This Cmdlet tests a Network Stream's Security context and will return
    True or False. 
.DESCRIPTION
    This Cmdlet tests a Network Stream's Security context and will return
    True or False. If an SSL Stream is provided as input this Cmdlet will
    check the .Net IsEncrypted property and return its True or False value, if
    the property is True it will supply details on the encryption used in its verbose
    output. If a standard Network Stream is provided as input True will be returned as
    no security was neccesary.
.PARAMETER FTPServerConnection
    This parameter is required and is the 1st positional parameter. It will
    accept a Network Stream as input.
.EXAMPLE
    Test-ConnectionEncryption -FTPServerConnection $FTPServerConnection

    This command will return a True or False value based on the type of
    Network Stream that is provided.
.NOTES
    Author: Michael J. Patterson
#>
    [CmdLetBinding()]
    Param([Parameter(Mandatory=$True, Position=0)]
          [ValidateNotNullorEmpty()]
          $FTPServerConnection)

    Write-Verbose "Testing Network Stream's Transmission Context"
    if ($FTPServerConnection -is [System.Net.Security.SslStream])
    {
        if ($FTPServerConnection.IsEncrypted -eq $True) 
        {
            Write-Verbose "Encryption Test Response: Test Passed, .Net SSLStream' IsEncrypted Property is True, details below"
            Write-Verbose "CipherAlgorithm: $($FTPServerConnection.CipherAlgorithm)"
            Write-Verbose "CipherStrength: $($FTPServerConnection.CipherStrength)"
            Write-Verbose "HashAlgorithm: $($FTPServerConnection.HashAlgorithm)"
            Write-Verbose "HashStrength: $($FTPServerConnection.HashStrength)"
            Return $True
        }
        else
        {
            Write-Verbose "Encryption Test Response: Test Failed, .Net SSLStream's IsEncrypted Property is False"
            Return $False
        }
    }
    else
    {
        Write-Verbose "Encryption Test Response: User defined default FTP which occurs over Plain Text no encryption test required"
        Return $True
    }
}

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
    
    $FTPServerConnection = Open-TCPNetworkStream -TCPClientSocket $TCPClientSocket -ServerIPAddress $ServerIPAddress -TransmissionContext $TransmissionContext -Verbose
    $TestStreamSecurity  = Test-ConnectionEncryption -FTPServerConnection $FTPServerConnection -Verbose

    if ($TestStreamSecurity)
    {
        Write-Output $FTPServerConnection
    }
    else
    {
        Throw "Error: Network Stream Security is compromised ending process."
    }
}

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

Function Close-FTPCommandDelegate
{
<#
.SYNOPSIS
    This Cmdlet closes the .Net Stream Writer that  used as a delegate to
    write FTP Commands to the Control Connection.
.DESCRIPTION
    This Cmdlet closes the .Net Stream Writer that  used as a delegate to
    write FTP Commands to the Control Connection. Cmdlet executes the close
    method of the .Net Stream Writer that is passed to it.
.PARAMETER CommandWritingDelegate
    This parameter is required and is the 1st positional parameter.It will
    accept a .Net Stream Writer as input.
.EXAMPLE
    Close-FTPCommandDelegate -CommandWritingDelegate $CommandWritingDelegate

    This command will execute the close method on the provided .Net Stream Writer.
.NOTES
    Author: Michael J. Patterson
#>
    [CmdletBinding()]
    Param([Parameter(Mandatory = $True, Position = 0)]
          [ValidateNotNullorEmpty()]
          $CommandWritingDelegate)

    Write-Verbose "Handling CommandWritingDelegate .Net Stream Writer Clean Up"
    Write-Verbose "Closing .Net Stream Writer"
    $CommandWritingDelegate.Close()
    Write-Verbose ".Net Stream Writer Closed"
}
Function Write-FTPCommand
{
<#
.SYNOPSIS
    This Cmdlet handles the back and forth communication required to pass
    commands to the FTP Server.
.DESCRIPTION
    This Cmdlet handles the back and forth communication required to pass
    commands to the FTP Server. Cmdlet uses a Command Writing Delegate to write
    commands to the FTP Server then logs and returns the Server's Responses either
    to a running FTPTranscript and or the pipeline.
.PARAMETER FTPCommand
    This parameter is required and is the 1st positional parameter. It will accept
    one or more FTP Command Strings as input.
.PARAMETER CommandWriter
    This parameter is required and is the 2nd positional parameter. It will accept
    a CommandWritingDelegate as input. This will be used to write the commands to the FTP
    Server Stream.
.PARAMETER FTPServerConnection
    This parameter is required and is the 3rd positional parameter. It will accept
    a Network Stream as input and will be used to read the FTP Server's Responses to the
    written commands.
.PARAMETER CommandDelay
    This parameter is not required and is the 4th positional parameter. It will accept
    input as type Int and will be used as the time to delay before reading the FTP Server's
    response to the written command.
.PARAMETER ReturnResponse
    This parameter is not required and is a switch parameter. By default the response of the Server
    is written to a running Transcript; however, if this is provided it will return the response to
    the pipeline.
.EXAMPLE
    Write-FTPCommand -FTPCommand "USER ExampleUserName" -CommandWriter $CommandWritingDelegate -FTPServerConnection $FTPServerConnection

    This command will write the FTP User Command to the FTP Server using the default time delay of 200 milliseconds
    and will write the server response to the running transcript.
.EXAMPLE
    Write-FTPCommand -FTPCommand "USER ExampleUserName" -CommandWriter $CommandWritingDelegate -CommandDelay 500 -FTPServerConnection $FTPServerConnection

    This command will write the FTP User Command to the FTP Server changing the default time delay of 200 milliseconds
    to 500 milliseconds and will write the server response to the running transcript.
.EXAMPLE
    Write-FTPCommand -FTPCommand "USER ExampleUserName" -CommandWriter $CommandWritingDelegate -FTPServerConnection $FTPServerConnection

    This command will write the FTP User Command to the FTP Server using the default time delay of 200 milliseconds,
    will write the server response to the running transcript, and will also return the response to the pipeline.
.NOTES
    Author: Michael J. Patterson
#>
    [CmdletBinding()]
    Param([Parameter(Mandatory=$True, Position=0)]
          [ValidateNotNullorEmpty()]
          [String[]]$FTPCommand,
          
          [Parameter(Mandatory=$True, Position=1)]
          [ValidateNotNullorEmpty()]
          $CommandWriter,

          [Parameter(Mandatory = $True, Position =2)]
          [ValidateNotNullOrEmpty()]
          $FTPServerConnection,

          [Parameter(Mandatory=$False, Position=3)]
          [ValidateNotNullorEmpty()]
          [Int]$CommandDelay = 200,
          
          [Parameter(Mandatory = $False)]
          [Switch]$ReturnResponse)

    Write-Verbose "Checking Network Stream for existing Server Response and logging to Transcript"
    $Script:FTPServerTranscript += Read-FTPServerResponse -FTPServerConnection $FTPServerConnection

    foreach ($Command in $FTPCommand)
    {
        Write-Verbose "Sending Following Command to Server: $Command"
        $CommandWriter.WriteLine($Command)
        $CommandWriter.Flush()
        Start-Sleep -Milliseconds $CommandDelay

        Write-Verbose "Logging Server Response to Transcript"
        $ServerResponse = Read-FTPServerResponse -FTPServerConnection $FTPServerConnection
        $Script:FTPServerTranscript += $ServerResponse
        if ($ReturnResponse)
        {
            Write-Output $ServerResponse
        }
    }
}

Function Send-FTPAuthCommands
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
    Send-FTPAuthCommands -CommandWriter $CommandWriter -FTPServerConnection $FTPServerConnection -UserName ExampleUsername -Password ExamplePassword

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

Function Send-FTPTransferSetUpCommands
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
    Send-FTPTransferSetUpCommands -CommandWriter $CommandWriter -FTPServerConnection $FTPServerConnection

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

Function Send-LocalFileBytes
{
<#
.SYNOPSIS
    This Cmdlet handles writing the actual file bytes of the local file
    to be transferred to the FTP Server.
.DESCRIPTION
    This Cmdlet handles writing the actual file bytes of the local file
    to be transferred to the FTP Server. This is accomplished by reading in the
    local file bytes and writing them to the Data Connection Stream.
.PARAMETER FTPServerConnection
    This parameter is required and is the 1st positional parameter. It will accept
    a Network Stream as input and will be used to read the FTP Server's Responses to the
    written commands.
.PARAMETER LocalFilePath
    This parameter is required and is the 2nd positional parameter. It will accept
    a String Type as input and should be the full path to the local file that is to be
    uploaded to the FTP Server.
.EXAMPLE
    Send-LocalFileBytes -FTPServerConnection $FTPServerConnection -LocalFilePath "C:\Example.txt"

    This command will send the bytes of the local file to the FTP Server through the FTP Server
    Connection.
.NOTES
    Author: Michael J. Patterson
#>
    [CmdletBinding()]
    Param([Parameter(Mandatory = $False, Position = 0)]
          [ValidateNotNullorEmpty()]
          $FTPServerConnection,
          
          [Parameter(Mandatory = $True, Position = 1)]
          [ValidateScript({Test-Path $_})]
          [String]$LocalFilePath)

    Write-Verbose "Retreiving Local File Bytes"
    $LocalFileBytes = Get-Content -Path $LocalFilePath -Encoding Byte
    $LocalFileLength = $LocalFileBytes.Length
    Write-Verbose "Sending bytes from local file"
    $FTPServerConnection.Write($LocalFileBytes, 0, $LocalFileLength)
    Write-Verbose "Local file bytes transferred"
}
Function Read-FTPServerResponse
{
<#
.SYNOPSIS
    This Cmdlet handles reading all responses from the FTP Server.
.DESCRIPTION
    This Cmdlet handles reading all responses from the FTP Server.
    This is accomplished by wrapping the Network Stream connecting the
    TCP Client and the FTP Server.
.PARAMETER FTPServerConnection
    This parameter is required and is the 1st positional parameter. It will accept
    a Network Stream as input and will be used to read the FTP Server's Responses to the
    written commands.
.EXAMPLE
    Read-FTPServerResponse -FTPServerConnection $FTPServerConnection

    This command will read the FTP Server Connection and return and response that the
    Server provided.
.NOTES
    Author: Michael J. Patterson
#>
    [CmdletBinding()]
    Param([Parameter(Mandatory = $True, Position = 0)]
          [ValidateNotNullorEmpty()]
          $FTPServerConnection)
    #Create Buffer for Server Response and Set Encoding
    $Buffer = New-Object -TypeName System.Byte[] 1024 
    $BufferEncoding = [System.Text.Encoding]::ASCII

    $ResponseBuffer = "" 
    $MoreData = $False

    #Read all data from stream and return the Server's Response
    do
    {
        ## Allow data to buffer for a bit 
        Start-Sleep -Milliseconds 1000

        ## Read what data is available 
        $MoreData = $false 
        $FTPServerConnection.ReadTimeout = 1000

        do
        {
            try
            {
                $ReadfromStream = $FTPServerConnection.Read($Buffer, 0, 1024)
                if($ReadfromStream -gt 0)
                {
                    $MoreData = $True
                    $ResponseBuffer += ($BufferEncoding.GetString($Buffer, 0, $ReadFromStream))
                }
            }
            catch
            {
                $MoreData = $False
                $ReadFromStream = 0
            }
        } while($ReadFromStream -gt 0) 
    } while($MoreData)

    Return $ResponseBuffer
}

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
    $TCPControlSocket = New-TCPClientSocket -ServerIPAddress $ServerIPAddress -ServerPortNumber $ControlPortNumber -Verbose
    if ($SelfSigned)
    {
        $FTPServerControlConnection = Connect-FTPServer -ServerIPAddress $ServerIPAddress -TCPClientSocket $TCPControlSocket -TransmissionContext SSLSelfSigned -Verbose
    }
    else
    {
        $FTPServerControlConnection = Connect-FTPServer -ServerIPAddress $ServerIPAddress -TCPClientSocket $TCPControlSocket -TransmissionContext StandardSSL -Verbose
    }
    $ControlConnectionCommandWriter = New-FTPCommandDelegate -FTPServerConnection $FTPServerControlConnection
    $SendAuthenicationCommands      = Send-FTPAuthCommands -CommandWriter $ControlConnectionCommandWriter -FTPServerConnection $FTPServerControlConnection -UserName $UserName -Password $Password
    $SendSetupTransferModes         = Send-FTPTransferSetUpCommands -CommandWriter $ControlConnectionCommandWriter -FTPServerConnection $FTPServerControlConnection
    $PassiveHandshakePortResponse   = Send-FTPPassiveCommand -CommandWriter $ControlConnectionCommandWriter -FTPServerConnection $FTPServerControlConnection
    $SendSTORFileCommand            = Send-FTPFileTransferCommand -CommandWriter $ControlConnectionCommandWriter -FTPServerConnection $FTPServerControlConnection -LocalFilePath $LocalFilePath -RemoteFilePathRoot $RemoteDirectory
    Write-Verbose "END Control Connection Verbose Stream---------------"

    Write-Verbose "BEGIN Data Connection Verbose Stream---------------"
    $TCPDataSocket = New-TCPClientSocket -ServerIPAddress $ServerIPAddress -ServerPortNumber $PassiveHandshakePortResponse -Verbose
    if ($SelfSigned)
    {
        $FTPServerDataConnection = Connect-FTPServer -ServerIPAddress $ServerIPAddress -TCPClientSocket $TCPDataSocket -TransmissionContext SSLSelfSigned -Verbose
    }
    else
    {
        $FTPServerDataConnection = Connect-FTPServer -ServerIPAddress $ServerIPAddress -TCPClientSocket $TCPDataSocket -TransmissionContext StandardSSL -Verbose
    }
    $SendLocalFileBytes          = Send-LocalFileBytes -FTPServerConnection $FTPServerDataConnection -LocalFilePath $LocalFilePath -Verbose
    $CleanUpServerDataConnection = Close-TCPNetworkStream -FTPServerConnection $FTPServerDataConnection -ConnectionType DataConnection -Verbose
    $CleanUpTCPDataSocket        = Close-TCPClientSocket -TCPClientSocket $TCPDataSocket -SocketType DataSocket -Verbose
    Write-Verbose "END Data Connection Verbose Stream---------------"
    
    Write-Verbose "BEGIN Control Connection Clean Up Verbose Stream---------------"
    $CleanUpCommandWritingDelegate  = Close-FTPCommandDelegate -CommandWritingDelegate $ControlConnectionCommandWriter -Verbose
    $CleanUpServerControlConnection = Close-TCPNetworkStream -FTPServerConnection $FTPServerControlConnection -ConnectionType ControlConnection -Verbose
    $CleanUpTCPControlSocket        = Close-TCPClientSocket -TCPClientSocket $TCPControlSocket -SocketType ControlSocket -Verbose
    Write-Verbose "End Control Connection Clean Up Verbose Stream---------------"
    Write-Output $FTPServerTranscript
}
Export-ModuleMember -Variable FTPServerTranscript
Export-ModuleMember -Function Start-ImplicitSSLFileUpload
