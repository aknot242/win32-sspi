This project is a fork of the garysick win32-sspi project which is in turn 
a fork of djbergers win32-sspi project which
provided the beginnings of a an FFI implementation of SSPI
on Windows. This particular fork expands the buffer size to ensure that the Kerberos token will 
work in the case of a user with a very large number of AD groups.

The following is the verbatim documentation from the garysick version of the project:

This project adds support for Kerberos through the
SPNEGO/Negotiate protocol.

The examples directory has working examples to illustrate
usage. The sspi_negotiate_*.rb files are client/server
examples of using Kerberos through SPNEGO/Negotiate protocol.
In order to be used successfully across multiple systems
in your domain you must define a Service Principal Name (SPN)
associated with the user account under which the server is
running unless the server is running as a Windows Service
under the LocalSystem account. To establish a SPN use the
setspn command as follows from a elevated privilege command
window:

```
  setspn -S HTTP/fqdn-of-your-host USERDOMAIN\USERNAME
```
The SPN you establish must be passed to the Client constructor
with the spn option in order to succesfully connect and
authenticate with the server.

The negotiate client/server implementations are also capable
of supporting the NTLM protocol. To do so specify the auth_type
option as 'NTLM' on the construction of the client. The user name
and user domain will be taken from the environment and will use
the current logged in users security context to authenticate with
the server. Otherwise passing the options username, domain, password
to the client constructor will establish a different security
context for the given username to authenticate against.
