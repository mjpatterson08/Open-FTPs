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
    This parameter is required and must be supplied in the 1st position. It will only accept
    valid IP Addresses and is validated using the .Net IPAddress Type Accelerator and will be
    used as the IP Address to connect on.

.PARAMETER ServerPortNumber
    This parameter is required and must be supplied in the 2nd position. It will accept
    and Int type as input and will be used as the port number to connect on.

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
          [ValidateNotNullorEmpty()]
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
        Return $Error[0]
        Throw "Exiting Process, Failed to Create TCP Socket"
    }
    Write-Output $TCPClientSocket
}

Function Set-StreamTransmissionContext
{
<#
.SYNOPSIS
    This Cmdlet creates a Network Stream and sets the transmission context using
    the provided TCP Client Socket and returns it to the pipeline.

.DESCRIPTION
    This Cmdlet creates a Network Stream and sets the transmission context using
    the provided TCP Client Socket and returns it to the pipeline. Cmdlet can return
    a plain text Network Stream for standard FTP communication or an SSL Stream
    if Implicit or Explicit SSL is set for secure FTPS communication.

.PARAMETER TCPClientSocket
    This parameter is required and must be supplied in the 1st position. It will accept
    the TCP Client Socket the Network Stream will be built on.

.PARAMETER ServerIPAddress
    This parameter is required and must be supplied in the 2nd position. It will only accept
    valid IP Addresses and is validated using the .Net IPAddress Type Accelerator. It will be
    used as the Destination IP to authenticate an SSL Stream.

.PARAMETER TransmissionContext
    This parameter is required and must be supplied in the 3rd position. It will only
    accept 3 possible string inputs. StandardFTP, ExplicitSSL, ImplicitSSL are the acceptable
    inputs and will set the mode of the Network Stream used for FTP communication.

.EXAMPLE
    Set-StreamTransmissionContext -TCPClientSocket $TCPClient -ServerIPAddress 1.2.3.4 -TransmissionContext StandardFTP

    This will open a Network Stream as plain text to allow standard FTP communication and return it
    to the pipeline.

.EXAMPLE
    Set-StreamTransmissionContext -TCPClientSocket $TCPClient -ServerIPAddress 1.2.3.4 -TransmissionContext ExplicitSSL

    This will open a Network Stream and upgrade it to an SSL Stream to allow FTP communication and
    return it to the pipeline. This will use the Windows default SSL Cert Validation.

.EXAMPLE
    Set-StreamTransmissionContext -TCPClientSocket $TCPClient -ServerIPAddress 1.2.3.4 -TransmissionContext ImplicitSSL

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
          [ValidateSet("StandardFTP", "ExplicitSSL", "ImplicitSSL")]
          [String]$TransmissionContext)

    Try
    {
        Write-Verbose "Attempting to Open Network Stream to FTP Server over Client Socket"
        $NetworkStream = $TCPClientSocket.GetStream()
        Write-Verbose "Network Stream Established, Setting Transmission Context"

        Switch ($TransmissionContext)
        {
            "StandardFTP"
            {
                Write-Verbose "Transmition Context: $TransmissionContext, FTP will occur in Plain Text"
                Write-Output $NetworkStream
            }
            "ExplicitSSL"
            {
                Write-Verbose "Transmition Context: $TransmissionContext, FTP will occur using Explicit SSL\TLS"
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
            "ImplicitSSL"
            {
                Write-Verbose "Transmition Context: $TransmissionContext, FTP will occur using Implicit SSL\TLS"
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
    This parameter is required and must be supplied in the 1st position. It will
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
    before before returning the Network Stream and will fail if it is not secure.

.PARAMETER ServerIPAddress
    This parameter is required and must be supplied in the 1st position. It will only accept
    valid IP Addresses and is validated using the .Net IPAddress Type Accelerator. It will be
    used as the Destination IP to authenticate an SSL Stream.

.PARAMETER TCPClientSocket
    This parameter is required and must be supplied in the 2nd position. It will accept
    the TCP Client Socket the Network Stream will be built on.

.PARAMETER TransmissionContext
    This parameter is required and must be supplied in the 3rd position. It will only
    accept 3 possible string inputs. StandardFTP, ExplicitSSL, ImplicitSSL are the acceptable
    inputs and will set the mode of the Network Stream used for FTP communication.

.EXAMPLE
    Connect-FTPServer -ServerIPAddress 1.2.3.4 -TCPClientSocket $TCPClientSocket -TransmissionContext StandardFTP

    This will open a Network Stream as plain text to allow standard FTP communication and return it
    to the pipeline.

.EXAMPLE
    Connect-FTPServer -ServerIPAddress 1.2.3.4 -TCPClientSocket $TCPClientSocket -TransmissionContext ExplicitSSL

    This will open a Network Stream and upgrade it to an SSL Stream to allow FTP communication and
    return it to the pipeline. This will use the Windows default SSL Cert Validation.

.EXAMPLE
    Connect-FTPServer -ServerIPAddress 1.2.3.4 -TCPClientSocket $TCPClientSocket -TransmissionContext ImplicitSSL

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
          [ValidateSet("StandardFTP", "ExplicitSSL", "ImplicitSSL")]
          [String]$TransmissionContext)
    
    $NetworkStream      = Set-StreamTransmissionContext -TCPClientSocket $TCPClientSocket -ServerIPAddress $ServerIPAddress -TransmissionContext $TransmissionContext -Verbose
    $TestStreamSecurity = Test-ConnectionEncryption -FTPServerConnection $NetworkStream -Verbose

    if ($TestStreamSecurity)
    {
        Write-Output $NetworkStream
    }
    else
    {
        Throw "Error: Network Stream Security is compromised ending process."
    }
}

Function Disconnect-FTPServerStream
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
    This parameter is required and must be supplied in the 1st position. It will
    accept a Network Stream as input.

.PARAMETER ConnectionType
    This parameter is required and must be supplied in the 2nd position. It will only
    accept two possible string inputs, ControlConnection and DataConnection, and is used
    for clear verbose output.

.EXAMPLE
    Disconnect-FTPServerStream -FTPServerConnection $FTPServerConnection -ConnectionType ControlConnection

    This command will run the dispose and close methods of the Stream provided as input and will use
    ControlConnection in it's verbose output.

.EXAMPLE
    Disconnect-FTPServerStream -FTPServerConnection $FTPServerConnection -ConnectionType DataConnection

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
    Write-Verbose "$ConnectionType Disconnected"
}

Function Disconnect-TCPClientSocket
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
    This parameter is required and must be supplied in the 1st position. It will
    accept a TCP Client Socket as input.

.PARAMETER SocketType
    This parameter is required and must be supplied in the 2nd position. It will only
    accept two possible string inputs, ControlSocket and DataSocket, and is used
    for clear verbose output.

.EXAMPLE
    Disconnect-TCPClientSocket -TCPClientSocket $TCPClientSocket -SocketType ControlSocket

    This command will run the dispose and close methods of the Socket provided as input and will use
    ControlSocket in it's verbose output.

.EXAMPLE
    Disconnect-TCPClientSocket -TCPClientSocket $TCPClientSocket -SocketType DataSocket

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
    Write-Verbose "$SocketType Disconnected"
}

Function New-CommandWritingDelegate
{
<#
.SYNOPSIS
    This Cmdlet creates a .Net Stream Writer that can be used as a delegate to
    write FTP Commands to the Control Connection.

.DESCRIPTION
    This Cmdlet creates a .Net Stream Writer that can be used as a delegate to
    write FTP Commands to the Control Connection.

.PARAMETER FTPServerConnection
    This parameter is required and must be supplied in the 1st position.It will
    accept a Network Stream as input.

.EXAMPLE
    New-CommandWritingDelegate -FTPServerConnection $FTPServerConnection

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

Function Close-CommandWritingDelegate
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
    This parameter is required and must be supplied in the 1st position.It will
    accept a .Net Stream Writer as input.

.EXAMPLE
    Close-CommandWritingDelegate -CommandWritingDelegate $CommandWritingDelegate

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
    This parameter is required and must be supplied in the 1st position. It will accept
    one or more FTP Command Strings as input.

.PARAMETER CommandWriter
    This parameter is required and must be supplied in the 2nd position. It will accept
    a CommandWritingDelegate as input. This will be used to write the commands to the FTP
    Server Stream.

.PARAMETER FTPServerConnection
    This parameter is required and must be supplied in the 3rd position. It will accept
    a Network Stream as input and will be used to read the FTP Server's Responses to the
    written commands.

.PARAMETER CommandDelay
    This parameter is not required and must be supplied in the 4th position. It will accept
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
    $Script:FTPServerTranscript += Get-FTPServerResponse -NetworkStream $FTPServerConnection

    foreach ($Command in $FTPCommand)
    {
        Write-Verbose "Sending Following Command to Server: $Command"
        $CommandWriter.WriteLine($Command)
        $CommandWriter.Flush()
        Start-Sleep -Milliseconds $CommandDelay

        Write-Verbose "Logging Server Response to Transcript"
        $ServerResponse = Get-FTPServerResponse -NetworkStream $FTPServerConnection
        $Script:FTPServerTranscript += $ServerResponse
        if ($ReturnResponse)
        {
            Write-Output $ServerResponse
        }
    }
}

Function Send-FTPAuthenticationCommands
{
<#
.SYNOPSIS
    This Cmdlet handles FTP authentication with the FTP Server.

.DESCRIPTION
    This Cmdlet handles FTP authentication with the FTP Server.
    That is accomplished by wrapping a Command Writing Delegate and
    and FTP Server Connection.

.PARAMETER CommandWriter
    This parameter is required and must be supplied in the 1st position. It will accept
    a CommandWritingDelegate as input. This will be used to write the commands to the FTP
    Server Stream.

.PARAMETER FTPServerConnection
    This parameter is required and must be supplied in the 2nd position. It will accept
    a Network Stream as input and will be used to read the FTP Server's Responses to the
    written commands.

.PARAMETER UserName
    This parameter is required and must be supplied in the 3rd position. It will accept
    a string as input, that string is to be the UserName of the FTP Account.

.PARAMETER Password
    This parameter is required and must be supplied in the 4th position. It will accept
    a string as input, that string is to be the Password of the FTP Account.

.EXAMPLE
    Send-FTPAuthenticationCommands -CommandWriter $CommandWriter -FTPServerConnection $FTPServerConnection -UserName ExampleUsername -Password ExamplePassword

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
    This parameter is required and must be supplied in the 1st position. It will accept
    a CommandWritingDelegate as input. This will be used to write the commands to the FTP
    Server Stream.

.PARAMETER FTPServerConnection
    This parameter is required and must be supplied in the 2nd position. It will accept
    a Network Stream as input and will be used to read the FTP Server's Responses to the
    written commands.

.PARAMETER PassiveCommand
    This parameter is not required and must be supplied in the 3rd position. It will accept
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
    This parameter is required and must be supplied in the 1st position. It will accept
    a CommandWritingDelegate as input. This will be used to write the commands to the FTP
    Server Stream.

.PARAMETER FTPServerConnection
    This parameter is required and must be supplied in the 2nd position. It will accept
    a Network Stream as input and will be used to read the FTP Server's Responses to the
    written commands.

.PARAMETER TypeCommand
    This parameter is not required and must be supplied in the 3rd position. It will accept
    a string as input; however, the appropriate FTP Command is already the default value of this
    parameter.

.PARAMETER StruCommand
    This parameter is not required and must be supplied in the 3rd position. It will accept
    a string as input; however, the appropriate FTP Command is already the default value of this
    parameter.

.PARAMETER ModeCommand
    This parameter is not required and must be supplied in the 3rd position. It will accept
    a string as input; however, the appropriate FTP Command is already the default value of this
    parameter.

.PARAMETER ProtCommand
    This parameter is not required and must be supplied in the 3rd position. It will accept
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
    This parameter is required and must be supplied in the 1st position. It will accept
    a CommandWritingDelegate as input. This will be used to write the commands to the FTP
    Server Stream.

.PARAMETER FTPServerConnection
    This parameter is required and must be supplied in the 2nd position. It will accept
    a Network Stream as input and will be used to read the FTP Server's Responses to the
    written commands.

.PARAMETER LocalFilePath
    This parameter is required and must be supplied in the 3rd position. It will accept
    a String Type as input and should be the full path to the local file that is to be
    uploaded to the FTP Server.

.PARAMETER RemoteFilePathRoot
    This parameter is required and must be supplied in the 4th position. It will accept
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

Function Send-TransferFileBytes
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
    This parameter is required and must be supplied in the 1st position. It will accept
    a Network Stream as input and will be used to read the FTP Server's Responses to the
    written commands.

.PARAMETER LocalFilePath
    This parameter is required and must be supplied in the 2nd position. It will accept
    a String Type as input and should be the full path to the local file that is to be
    uploaded to the FTP Server.

.EXAMPLE
    Send-TransferFileBytes -FTPServerConnection $FTPServerConnection -LocalFilePath "C:\Example.txt"

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
    Write-Verbose "Begining Send of Local File Bytes"
    $FTPServerConnection.Write($LocalFileBytes, 0, $LocalFileLength)
    Write-Verbose "File Bytes have been Transferred"
}
Function Get-FTPServerResponse
{
<#
.SYNOPSIS
    This Cmdlet handles reading all responses from the FTP Server.

.DESCRIPTION
    This Cmdlet handles reading all responses from the FTP Server.
    This is accomplished by wrapping the Network Stream connecting the
    TCP Client and the FTP Server.

.PARAMETER NetworkStream
    This parameter is required and must be supplied in the 1st position. It will accept
    a Network Stream as input and will be used to read the FTP Server's Responses to the
    written commands.

.EXAMPLE
    Get-FTPServerResponse -NetworkStream $FTPServerConnection

    This command will read the FTP Server Connection and return and response that the
    Server provided.

.NOTES
    Author: Michael J. Patterson
#>
    [CmdletBinding()]
    Param([Parameter(Mandatory = $True, Position = 0)]
          [ValidateNotNullorEmpty()]
          $NetworkStream)
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
        $NetworkStream.ReadTimeout = 1000

        do
        {
            try
            {
                $ReadfromStream = $NetworkStream.Read($Buffer, 0, 1024)
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
    [CmdletBinding()]
    Param([Parameter(Mandatory = $True, Position = 0)]
          [ValidateNotNullorEmpty()]
          [IPAddress]$ServerIPAddress,
          
          [Parameter(Mandatory = $True, Position = 1)]
          [ValidateNotNullorEmpty()]
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
          [String]$Password)



    #Set Up Control Connection
    #-Create TCPClient Socket
    #-Connect to Server and set up transmission context (Default FTP is plain Text, Can use Implicit or Explicit SSL)
    #-Create Stream Writing Delegate to write FTP Commands to Server
    #   -Authenicate by sending User and Pass Commands
    #   -Send transfer mode and setup commands
    #   -Send Passive Command and Parse Response to get Port Number for Data Connection
    #   -Send Store Command with new Remote Path to let Server know a file is comming and where to put it
    $TCPControlSocket               = New-TCPClientSocket -ServerIPAddress $ServerIPAddress -ServerPortNumber $ControlPortNumber -Verbose
    $FTPServerControlConnection     = Connect-FTPServer -ServerIPAddress $ServerIPAddress -TCPClientSocket $TCPControlSocket -TransmissionContext ImplicitSSL -Verbose
    $ControlConnectionCommandWriter = New-CommandWritingDelegate -FTPServerConnection $FTPServerControlConnection
    $AuthenicationCommands          = Send-FTPAuthenticationCommands -CommandWriter $ControlConnectionCommandWriter -FTPServerConnection $FTPServerControlConnection -UserName $UserName -Password $Password
    $SetupTransferModes             = Send-FTPTransferSetUpCommands -CommandWriter $ControlConnectionCommandWriter -FTPServerConnection $FTPServerControlConnection
    $PassiveCommandDataPortNumber   = Send-FTPPassiveCommand -CommandWriter $ControlConnectionCommandWriter -FTPServerConnection $FTPServerControlConnection
    $FileUploadCommand              = Send-FTPFileTransferCommand -CommandWriter $ControlConnectionCommandWriter -FTPServerConnection $FTPServerControlConnection -LocalFilePath $LocalFilePath -RemoteFilePathRoot $RemoteDirectory
    
    #Set Up Data Connection
    #-Create TCP Client Socket
    #-Connect to Server and set up transmission context (Default FTP is plain Text, Can use Implicit or Explicit SSL)
    #-Read Local File Data and convert to Bytes
    #-Send local File Bytes to Server
    #-Close Data Connection Network Stream
    #-Close Data Connection TCP Client Socket
    $TCPDataSocket               = New-TCPClientSocket -ServerIPAddress $ServerIPAddress -ServerPortNumber $PassiveCommandDataPortNumber -Verbose
    $FTPServerDataConnection     = Connect-FTPServer -ServerIPAddress $ServerIPAddress -TCPClientSocket $TCPDataSocket -TransmissionContext ImplicitSSL -Verbose
    $FileBytesTransfer           = Send-TransferFileBytes -FTPServerConnection $FTPServerDataConnection -LocalFilePath $LocalFilePath -Verbose
    $CleanUpServerDataConnection = Disconnect-FTPServerStream -FTPServerConnection $FTPServerDataConnection -ConnectionType DataConnection -Verbose
    $CleanUpTCPDataSocket        = Disconnect-TCPClientSocket -TCPClientSocket $TCPDataSocket -SocketType DataSocket -Verbose
    
    #Clean up Control Connection
    #-Close Command Writing Delegate
    #-Close Control Connection Network Stream
    #-Close Control Connection TCP Client
    $CleanUpCommandWritingDelegate  = Close-CommandWritingDelegate -CommandWritingDelegate $ControlConnectionCommandWriter
    $CleanUpServerControlConnection = Disconnect-FTPServerStream -FTPServerConnection $FTPServerControlConnection -ConnectionType ControlConnection -Verbose
    $CleanUpTCPControlSocket        = Disconnect-TCPClientSocket -TCPClientSocket $TCPControlSocket -SocketType ControlSocket -Verbose
    Write-Output $FTPServerTranscript
}
Export-ModuleMember -Variable FTPServerTranscript
Export-ModuleMember -Function Start-ImplicitSSLFileUpload
