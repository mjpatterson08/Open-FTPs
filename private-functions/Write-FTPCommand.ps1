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
