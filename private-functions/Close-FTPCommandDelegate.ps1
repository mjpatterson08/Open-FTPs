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
    [void]$CommandWritingDelegate.Close()
    Write-Verbose ".Net Stream Writer Closed"
}
