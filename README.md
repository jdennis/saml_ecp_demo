# Introduction

The SAML Enhanced Client or Proxy Profile (ECP) is a SAML
authentication method designed for non-browser non-interactive SAML
auththentication. It is commonly used by command line tools to
authenticate via SAML.

ECP is often misunderstood and example implementations are hard to
find. saml_ecp_demo is a Python3 implementation of ECP designed both to
educate implementors about ECP and perform a complete ECP
authentication flow with the ability to dump all protocol interactions
for the purpose of education and/or diagnosing ECP transactions.

All documenation can be found in saml_ecp_demo.py, it is extensive and
worth reading. The script also supports the --help command line
argument and will print out usage information.

```shell
% saml_ecp_demo --help
```

An example of the saml_ecp_demo output can be found in saml_ecp_demo.log

## Installing and Running:

You can run the script from a checkout of the Github repo

```shell
% cd saml_ecp_demo
% python3 saml_ecp_demo.py
# Or make it executable and run it directly
% chmod +x saml_ecp_demo.py
% ./saml_ecp_demo.py
```

-OR-

saml_ecp_demo is also available as a Python PI package and can be
installed via Python pip.

```shell
% pip3 install --user saml_ecp_demo
```

This will create an entry in the appropriate bin directory called
"saml_ecp_demo" which can then be run by typing that name on the
command line.

```shell
% saml_ecp_demo ...
```

> **Note:** The --user tells pip to install in the user's home directory not
> in the system directories which are often managed by the operating
> system package manager and would require root access for
> installation. It's also advisable to have pip avoid using the system
> locations because it can corrupt files maintained by the system
> package manager. When you use --user you'll find the installed files
> under ~/.local

> **Important:** saml_ecp_demo is written for Python3, it does not support
> Python2, make sure you're using the Python3 version of pip otherwise
> the generated console script will invoke the wrong Python interpreter.

> **Note:** This installs a Python package called saml_ecp_demo under
> $PY_INSTALL_LOCATION/site-packages/saml_ecp_demo. The actual source
> code is in
> $PY_INSTALL_LOCATION/site-packages/saml_ecp_demo/saml_ecp_demo.py. The
> Python pip installer creates a console script called saml_ecp_demo in
> the appropriate bin directory that simply loads the actual script from
> the package directory. Python uses this redirection for scripts
> because running scripts is operating system specific but Python code
> is portable.

## Usage:

Use the -h or --help command line option to display all command line
options and get basic usage info.

The script requires 4 pieces of information to run:

-s --sp-resource:

This is the URL of a resource at the SP protected by SAML authentication.
It is what the ECP client wants and will use ECP to obtain.

-i --idp-endpoint:

The ECP client selects the IdP. For the purposes of this script we
explicitly supply the IdP or more accurately the SingleSignOnService
endpoint URL as advertised by the IdP in it's metadata supporting the
SOAP binding. To find this URL search for a SingleSignOnService
element in the IdP metadata which also has a Binding attribute of
"urn:oasis:names:tc:SAML:2.0:bindings:SOAP". The Location attribute
will be the URL to be used as the --idp-endpoint.

-u --user:

The user name the IdP will authenticate.

-p' --password:

The user password used to authenticate with. If it's not supplied
on the command line the tool will prompt for it.

The tool will emit varying levels of diagnostic information as it
runs. See the --log-categories command line option to see how to
control the verbosity and/or type of information displayed.



John Dennis <jdennis@sharpeye.com>
