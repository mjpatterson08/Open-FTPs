# Open-FTPs
Powershell implementation that allows FTPS file transfers using Implicit SSL/TLS with no dependencies.

Underlying helper functions allow for FTP to be executing over a clear text connection or one using Implicit or Explicit SSL/TLS.

I focused on the Implicit SSL\TLS use case in particular because there is very little documentation out there on how to implement a tool that will allow you to complete file transfers using this set up despite there being hundreds of questions on a number of forums and programming question boards going back several years. Additionally to add to the frustration, it appears users of those sites spam the same answers adding to the confusion.

In order to upload a file to an FTPS server secured using Implicit SSL\TLS all you need to do is import this module and run the command called Start-ImplicitSSLFileUpload and pass in the required parameters.

This is an open source module that anyone is welcome to contribute too, hopefully this can serve as a community resource that can help others that need this information in the future. You're welome to read the code in the module to understand how this was implemented, it would not be difficult to implement in other programming languages, i chose powershell because of how easy it is to share with co-workers everyone in my work place uses a windows machine and all come with powershell by default. See a quick over view below:

In an Implicit SSL/TLS setup the port used for the control connection is typically Port 990, you would implement the below steps in order to complete and file transfer.

Handle Control Connection

  1.Establish a TCP Connection to the control port using the Server's IP Address and Control Port number./n
  2.Authenticate SSL/TLS handshake and upgrade to an SSL Stream./n
  3.Create a delegate that can write valid FTP Commands to the SSL Stream./n
  4.Send User and Pass commands along with the appropriate UserName and Password to authenticate with the FTP server./n
  5.Send the commands related to the File transfer, these include STRU, PROT, TYPE, and MODE to name a few, these tell the server the/n   type of stream to be used the file structure (Binary vs ASCII) etc./n
  6.Send the Passive Command to tell the server it needs to send you back a port number that you can use to setup the Data Connection,   and parse the Server's response./n
  7.Send the STOR Command to let the Server know that file data will be comming and where to store it./n

Handle Data Connection

  1.Establish a TCP Connection to the data port using the Server's IP Address and Data Port number we parsed from the Passive Command e   earlier.
  2.Authenticate SSL/TLS handshake and upgrade to an SSL Stream.
  3.Write the bytes of the local file to the SSL Stream.
  4.Close the Data Connection when finished the Server knows what to do with the data based on the commands already sent using the c     control connection.
  5.Then finally close the Control Connection.

All this is made simple with the below example of a file transfer using this module.

First Import the Module, this can be done by placing this module on the Path and having powershell handle it, or by passing the path to this module to Import-Module.

Then just copy and paste the below into the Command Prompt changing that parameter inputs to meet your needs:

Start-ImplicitSSLFileUpload -SeverIPAddress "1.2.3.4" -ControlPortNumber 990 -LocalFilePath "C:\ExampleFile.txt" -RemoteDirectory /FTPServerArchive/InboundFileDirectory" -UserName "ExampleUserName" -Password "ExamplePassword"

Or if using a Self Signed Cert the below:

Start-ImplicitSSLFileUpload -SeverIPAddress "1.2.3.4" -ControlPortNumber 990 -LocalFilePath "C:\ExampleFile.txt" -RemoteDirectory /FTPServerArchive/InboundFileDirectory" -UserName "ExampleUserName" -Password "ExamplePassword" -SelfSigned

Hope this was helpful, please consider contributing.

