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
