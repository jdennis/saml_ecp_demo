#!/usr/bin/python3

'''
Introduction:
=============

This Python3 script implements a SAML ECP client. It's design goals
are:

* An example to illustrate the ECP protocol
* A test to validate ECP
* A diagnostic tool to debug ECP protocol problems

It is recommended you study the SAML ECP specifications. All SAML
specifications can be found here:

https://wiki.oasis-open.org/security/FrontPage

The two specifications you should review are:

* Profiles for the OASIS Security Assertion Markup Language (SAML)
* SAML V2.0 Enhanced Client or Proxy Profile Version 2.0

This ECP client implements the common ECP features, it does not
implement some of the more esoteric ECP features such as:

* SP supplied IdP list
* Channel Bindings
* Holder of Key
* Delegation

ECP Flow:
=========

1. ECP issues HTTP Request to Service Provider

In step 1, the Principal, via an ECP, makes an HTTP request for a
secured resource at a service provider, where the service provider
does not have an established security context for the ECP and
Principal.

2. Service Provider issues <AuthnRequest> to ECP

In step 2, the service provider issues an <AuthnRequest> message to
the ECP, which is to be delivered by the ECP to the appropriate
identity provider. The Reverse SOAP (PAOS) binding [SAMLBind] is used
here.

3. ECP Determines Identity Provider

In step 3, the ECP obtains the location of an endpoint at an identity
provider for the authentication request protocol that supports its
preferred binding. The means by which this is accomplished is
implementation-dependent.

4. ECP conveys <AuthnRequest> to Identity Provider

In step 4, the ECP conveys the <AuthnRequest> to the identity provider
identified in step 3 using a modified form of the SAML SOAP binding
[SAMLBind] with the additional allowance that the identity provider
may exchange arbitrary HTTP messages with the ECP before responding to
the SAML request.

5. Identity Provider identifies Principal

In step 5, the Principal is identified by the identity provider by
some means outside the scope of this profile. However, typically this
means utilizing HTTP authentication when the <AuthnRequest> is sent to
the IdP in step 4. because unlike the interactive browser based SAML
profiles the IdP is unable to interact with the user to exchange
credentials HTTP servers at a minimum support Basic and Digest
authentication but probably support better authentication methods as
well. Basic and Digest authentication are not considered very secure
by today's standards but represent a lowest common denominator making
them a good choice for a demo like this. However, the Requests library
we use to perform HTTP request/response supports many other
authentication methods. Adding support for a new authentication method
to this demo simple, see the documentation for the
send_authn_request_to_idp() method for details.

6. Identity Provider issues <Response> to ECP, targeted at Service Provider

In step 6, the identity provider issues a <Response> message, using
the SAML SOAP binding, to be delivered by the ECP to the service
provider. The message may indicate an error, or will include (at
least) an authentication assertion.

7. ECP conveys <Response> message to Service Provider

In step 7, the ECP conveys the <Response> message to the service
provider using the PAOS binding.

8. Service Provider grants or denies access to Principal

In step 8, having received the <Response> message from the identity
provider, the service provider either establishes its own security
context for the principal and return the requested resource, or
responds to the principal's ECP with an error.

Usage:
======

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

Implementation Notes:
=====================

Python Requirements:

This tool is written for Python version 3, it will not run on Python 2.
The tool requires the following external Python libraries, you can
install these either via your OS package manager or via Python pip:

* requests (used for HTTP communication)
* lxml (used for XML processing)

A note on naming conventions. XML appears in two forms, as text and then
after parsing the XML text as a set of lxml (e.g. libxml2) objects which
can be operated on in a program. Both forms (text and object) represent
the same XML information. To distinguish between the two forms we use a
naming convention that appends '_text' to XML in text form and '_xml' to
XML in object form.

Contact and Maintenance Info:
=============================

John Dennis

<jdennis@redhat.com>   [employer affiliation]
<jdennis@sharpeye.com> [personal]
Git Repository: https://github.com/jdennis/saml_ecp_demo
'''

#-------------------------------------------------------------------------------

import argparse
from copy import deepcopy
import getpass
import logging
from io import StringIO
import sys
import textwrap
import traceback

import requests
from lxml import etree

#---------------------- Declarations & Global Variables ------------------------

NS_ECP = 'urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp'
NS_PAOS = 'urn:liberty:paos:2003-08'
NS_SOAP = 'http://schemas.xmlsoap.org/soap/envelope/'
NS_SAMLP = 'urn:oasis:names:tc:SAML:2.0:protocol'
NS_SAML = 'urn:oasis:names:tc:SAML:2.0:assertion'

namespaces = {
    'ecp': NS_ECP,
    'paos': NS_PAOS,
    'soap': NS_SOAP,
    'samlp': NS_SAMLP,
    'saml': NS_SAML,
}

SOAP_ACTOR = 'http://schemas.xmlsoap.org/soap/actor/next'
SOAP_MUST_UNDERSTAND = '1'

LOG = None

valid_log_categories = set(('sp-resource',
                            'message-info',
                            'saml-message',
                            'http-request-response',
                            'http-content',
                            'http-lowlevel'))

default_log_categories = set(('sp-resource',
                              'message-info',
                              'saml-message',
                              'http-request-response'))

#------------------------------ Utilities --------------------------------------

def setup_logging(options, log_categories):
    '''Set up the logging configuration. We don't make much use of the
    log level to control output because this is not a traditional
    application and we want to control the output granularity in
    messages that might be logged at the same level. As such we make
    heaver use of logging categories to control what is output.
    '''

    global LOG
    logging.basicConfig(format='%(message)s', filename=options.log_file,
                        filemode='w')

    LOG = logging.getLogger()
    LOG.setLevel(logging.INFO)

    if 'http-lowlevel' in log_categories:
        # Enabling debugging at http.client level
        # (requests->urllib3->http.client) you will see the REQUEST,
        # including HEADERS and DATA, and RESPONSE with HEADERS but
        # without DATA.  the only thing missing will be the response.body
        # which is not logged.

        from http.client import HTTPConnection
        HTTPConnection.debuglevel = 1
        LOG.setLevel(logging.DEBUG)
        requests_log = logging.getLogger("urllib3")
        requests_log.setLevel(logging.DEBUG)
        requests_log.propagate = True

def ns_name(ns, name):
    '''Return a XML element name as {namespace}name.

    lxml wants XML elements it creates to have the full namespace
    wrapped in braces as opposed to using a namespace prefix. lxml
    will generate the namespace prefix declarations automatically when
    it renders the XML into text.
    '''

    return '{%s}%s' % (namespaces[ns], name)


def get_xml_element(context_node, required, xpath_expr,
                    description=None):
    '''Return an XML element found by an xpath expression.

    If required is True and the xpath expression does not find the
    element an exception is raised. The optional description is used
    in the error message. This function assumes at most one instance
    will exist, it does not permit multiple instances.

    '''

    matches = context_node.xpath(xpath_expr, namespaces=namespaces)
    n_matches = 0 if not matches else len(matches)

    if n_matches == 0:
        if required:
            raise ValueError('not found "%s"' %
                             (description or xpath_expr))
        else:
            return None

    if n_matches > 1:
        raise ValueError('found %d multiple matches "%s"' %
                         (n_matches, description or xpath_expr))

    return matches[0]

def get_xml_element_text(context_node, required, xpath_expr,
                         description=None):

    '''Return the text of either an XML element or an attribute of an XML
    element depending on the xpath expression.

    If required is True and the xpath expression does not find the
    item an exception is raised. The optional description is used in
    the error message. This function assumes at most one instance
    will exist, it does not permit multiple instances.'''

    data = get_xml_element(context_node, required, xpath_expr,
                              description)
    if hasattr(data, 'text'):
        return data.text
    return data

def build_soap_fault(fault_code, fault_string, detail=None):
    'Build a SOAP Fault document and return it as a XML object.'

    envelope = etree.Element(ns_name('soap','Envelope'),
                             nsmap={'soap': NS_SOAP})

    body = etree.SubElement(envelope, ns_name('soap', 'Body'))
    fault = etree.SubElement(body, ns_name('soap', 'Fault'))

    fc = etree.SubElement(fault, 'faultcode')
    fc.text = 'soap:' + fault_code

    fs = etree.SubElement(fault, 'faultstring')
    fs.text = fault_string

    if detail:
        d = etree.SubElement(fault, 'detail')
        d.text = detail

    return envelope

def banner(string):
    'Make some strings stand out among the voluminous output'

    return '=== %s ===' % string

def format_xml_from_object(root):
    'Pretty print an XML object, returned as a string'

    return etree.tostring(root, encoding='unicode', pretty_print=True)

def format_xml_from_string(xml):
    '''Given an XML document as text, parse it and then pretty print it,
    return it as a string'''

    root = etree.fromstring(xml)
    return format_xml_from_object(root)

def _format_http_request_response(buf, response, log_categories):
    '''Python Requests encapsulates a HTTP request & response in their
    Response object. This function pretty prints the request/response
    information and returns it as a string.'''

    request = response.request

    buf.write('\nRequest:\n')
    buf.write('  url = %s\n' % request.url)
    buf.write('  method = %s\n' % request.method)
    buf.write('  Headers:\n')
    for hdr in sorted(request.headers.keys()):
        buf.write('    %s: %s\n' % (hdr, request.headers[hdr]))
    if request.body and 'http-content' in log_categories:
        buf.write('  Body:\n')
        buf.write('    %s' % (request.body))

    buf.write('\nResponse:\n')
    buf.write('  Status = %s\n' % response.status_code)
    buf.write('  Headers:\n')
    for hdr in sorted(response.headers.keys()):
        buf.write('    %s: %s\n' % (hdr, response.headers[hdr]))


    if 'http-content' in log_categories:
        content_type = response.headers.get('Content-Type')
        if content_type and response.content:
            if is_content_xml(content_type):
                formatted_content = format_xml_from_string(response.text)
                formatted_content = textwrap.indent(formatted_content, '    ')
            elif is_content_text(content_type):
                formatted_content = response.text
                formatted_content = textwrap.indent(formatted_content, '    ')
            else:
                formatted_content = response.text # FIXME
            buf.write('  Content:\n')
            buf.write(formatted_content)

def format_http_request_response(response, log_categories, msg=None):
    '''Python Requests encapsulates a HTTP request & response in their
    Response object. This function pretty prints the request/response
    information and returns it as a string.'''

    formatted = None
    request = response.request

    with StringIO() as buf:
        if msg:
            buf.write(msg)
            buf.write('\n')

        if 'http-request-response' in log_categories:
            for r in response.history:
                _format_http_request_response(buf, r, log_categories)
            _format_http_request_response(buf, response, log_categories)

        formatted = buf.getvalue()
    return formatted

def is_content_xml(content_type):
    'Based on the Content-Type return True if the content is XML text.'

    if 'text/xml' in content_type:
        return True

    if 'application/vnd.paos+xml' in content_type:
        return True

    return False

def is_content_text(content_type):
    'Based on the Content-Type return True if the content is plain text.'
    if content_type.startswith('text'):
        return True

    return False

#------------------------------ ECPFlow Class ----------------------------------

class ECPFlow:
    '''This class encapsulates all the data and functions necessary to to
    perform a single ECP transaction. Data which needs to preserved
    between ECP steps are preserved in this class for use in a
    subsequent step. The implementation is designed for demo and
    tutorial purposes, as such it is not necessarily the most
    efficient or minimal approach. For example we extract and preserve
    some data which is not essential for implementing ECP but helps
    illustrate the concepts and aids in diagnostics.'''

    def __init__(self, sp_resource, idp_endpoint,
                 user, password, idp_auth_method, log_categories):
        self.sp_resource = sp_resource
        self.idp_endpoint = idp_endpoint
        self.user = user
        self.password = password
        self.idp_auth_method = idp_auth_method
        self.log_categories = log_categories

        # HTTP session used to perform HTTP request/response
        self.session = requests.Session()

        #### Collected Data ####

        # SP Request
        self.paos_request_text = None
        self.paos_request_xml = None
        self.sp_response_consumer_url = None
        self.sp_message_id = None
        self.sp_is_passive = None
        self.sp_issuer = None
        self.sp_relay_state = None
        self.sp_authn_request_xml = None

        # IdP Response
        self.idp_response_text = None
        self.idp_response_xml = None
        self.idp_assertion_consumer_url = None
        self.idp_request_authenticated = None
        self.idp_saml_response_xml = None
        self.idp_saml_response_status_xml = None
        self.idp_saml_response_status_code = None
        self.idp_saml_response_status_code2 = None
        self.idp_saml_response_status_msg = None
        self.idp_saml_response_status_detail = None

        # SP Response
        self.sp_response_xml = None

    # ==== Utilities ====

    def format_paos_request_info(self, log_categories, msg=None):
        '''For illustration and diagnostic purposes we extract pertinent
        pieces of information from the PAOS request sent by the SP. This
        function pretty prints that information and returns it as a string.'''

        formatted = None

        with StringIO() as buf:
            if msg:
                buf.write(msg)
                buf.write('\n')

            if 'message-info' in log_categories:
                buf.write('SP PAOS Request Info:\n')

                buf.write('  response_consumer_url: %s\n' %
                          self.sp_response_consumer_url)
                buf.write('  message_id: %s\n' % self.sp_message_id)
                buf.write('  is_passive: %s\n' % self.sp_is_passive)
                buf.write('  issuer: %s\n' % self.sp_issuer)
                buf.write('  relaystate: %s\n' % self.sp_relay_state)
                if 'saml-message' in log_categories:
                    xml_text = format_xml_from_object(self.sp_authn_request_xml)
                    buf.write('  authn_request:\n%s\n' % textwrap.indent(xml_text, '    '))

            formatted = buf.getvalue()
        return formatted

    def format_idp_response_info(self, log_categories, msg=None):
        '''For illustration and diagnostic purposes we extract pertinent
        pieces of information from the ECP response sent by the IdP. This
        function pretty prints that information and returns it as a string.'''

        formatted = None

        with StringIO() as buf:
            if msg:
                buf.write(msg)
                buf.write('\n')

            if 'message-info' in log_categories:
                buf.write('IdP SOAP Response Info:\n')

                buf.write('  SAML Status Code: %s\n' %
                          self.idp_saml_response_status_code)
                buf.write('  SAML Status Code 2: %s\n' %
                          self.idp_saml_response_status_code2)
                buf.write('  SAML Status Message: %s\n' %
                          self.idp_saml_response_status_msg)
                buf.write('  SAML Status Detail: %s\n' %
                          self.idp_saml_response_status_detail)
                buf.write('  idp_assertion_consumer_url: %s\n' %
                          self.idp_assertion_consumer_url)
                buf.write('  idp_request_authenticated: %s\n' % self.idp_request_authenticated)
                if 'saml-message' in log_categories:
                    xml_text = format_xml_from_object(self.idp_saml_response_xml)
                    buf.write('  SAML Response:\n%s\n' % textwrap.indent(xml_text, '    '))

            formatted = buf.getvalue()
        return formatted


    def validate_soap_attrs(self, node, description):
        '''Many of the XML elements used within the SOAP envelope share a
        common set of mandatory attributes. This function verifies
        these requirements are satisfied.'''

        soap_actor = get_xml_element_text(node, False, './@soap:actor')
        if soap_actor is None:
            raise ValueError('%s is missing required soap:actor attribute' %
                             (description))
        if soap_actor != SOAP_ACTOR:
            raise ValueError('%s has invalid soap:actor value: %s, '
                             'expecting %s' %
                             (description, soap_actor, SOAP_ACTOR))

        soap_must_understand = get_xml_element_text(node, False, './@soap:mustUnderstand')

        if soap_must_understand is None:
            raise ValueError('%s is missing required soap:mustUnderstand attribute' %
                             (description))
        if soap_must_understand != SOAP_MUST_UNDERSTAND:
            raise ValueError('%s has invalid soap:actor value: %s, '
                             'expecting %s' %
                             (description, soap_must_understand, SOAP_MUST_UNDERSTAND))



    # ==== Flow Steps ====

    def run(self):
        'Execute an ECP flow as a sequence of logical steps.'

        self.ecp_issues_request_to_sp()
        self.process_paos_request()
        self.determine_idp_endpoint()
        self.build_authn_request_for_idp()
        self.send_authn_request_to_idp()
        self.process_idp_response()
        self.validate_idp_response()
        self.build_sp_response()
        self.send_sp_response()

    def ecp_issues_request_to_sp(self):
        '''This is the first step in the ECP process. The ECP client wants
        a resource from the SP server but must authenticate first. The ECP
        client indicates it's intent to participate in the ECP flow by
        sending two special HTTP headers (Accept & PAOS) in the HTTP
        header. If the SP decides the client must authenticate (because
        there is no existing session) it will recognize from the special
        HTTP headers the client wants to participate in ECP. The SP will
        then respond by returning a PAOS request to the client who will
        then forward it to the IdP.

        This function sends the request to the SP along with the special
        headers and stores the received PAOS request in the class instance.'''

        description = banner(' ECP Issues HTTP Request to Service Provider')

        # headers needed to indicate to the SP an ECP request
        headers = {
            'Accept' : 'text/html, application/vnd.paos+xml',
            'PAOS'   : 'ver="urn:liberty:paos:2003-08";"urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp"'
        }

        response = self.session.get(self.sp_resource, headers=headers)
        LOG.info(format_http_request_response(response, self.log_categories,
                                              msg=description))

        self.paos_request_text = response.text

    def process_paos_request(self):
        '''After receiving the PAOS request from the SP we parse the XML
         text and build a XML object in order to operate on the
         data. The primary purpose of this step is to extract the
         authnRequest from the PAOS request and encapsulate it in a new
         SOAP request that can be forwarded to the IdP.

         The PAOS request also contains additional information some of
         which must be preserved for the later step when we forward the
         IdP response back to the SP.

         1. The paos:Request responseConsumerURL is preserved because
            the ECP client MUST assure it matches the
            ecp:Response.AssertionConsumerServiceURL returned by the
            IdP to prevent man-in-the-middle attacks. It must also
            match the samlp:AuthnRequest.AssertionConsumerServiceURL.

         2. If the paos:Request contained a messageID it is preserved
            so it can be returned in the subsequent
            paos:Response.refToMessageID. This allows a provider to
            correlate messages.

         3. If a ecp:RelayState is present it is preserved because when
            the ECP client sends the response to the SP it MUST include
            RelayState provided in the request.

         In addition we extract some pertinent information for display
         and diagnostic purposes.'''

        description = banner('Process PAOS request from SP')

        self.paos_request_xml = etree.fromstring(self.paos_request_text)
        # PAOS Request Header Block
        self.sp_response_consumer_url = get_xml_element_text(
            self.paos_request_xml, True,
            '/soap:Envelope/soap:Header/paos:Request/@responseConsumerURL')

        self.sp_message_id = get_xml_element_text(
            self.paos_request_xml, False,
            '/soap:Envelope/soap:Header/paos:Request/@messageID')

        # ECP Request Header Block
        self.provider_name = get_xml_element_text(
            self.paos_request_xml, False,
            '/soap:Envelope/soap:Header/ecp:Request/@ProviderName')

        self.sp_is_passive = get_xml_element_text(
            self.paos_request_xml, False,
            '/soap:Envelope/soap:Header/ecp:Request/@IsPassive')

        self.sp_issuer = get_xml_element_text(
            self.paos_request_xml, True,
            '/soap:Envelope/soap:Header/ecp:Request/saml:Issuer')

        # ECP RelayState Header Block
        self.sp_relay_state = get_xml_element_text(
            self.paos_request_xml, False,
            '/soap:Envelope/soap:Header/ecp:RelayState')

        # The AuthnRequest as an XML object
        self.sp_authn_request_xml = get_xml_element(
            self.paos_request_xml, True,
            '/soap:Envelope/soap:Body/samlp:AuthnRequest')

        LOG.info(self.format_paos_request_info(self.log_categories,
                                               description))

    def determine_idp_endpoint(self):
        '''Stub method, can be expanded later. For now just use the
        value passed on the command line.'''

        description = banner('ECP Determines Identity Provider')

        LOG.info('%s\nUsing IdP endpoint: %s\n',
                 description, self.idp_endpoint)

    def build_authn_request_for_idp(self):
        '''The ECP client will forward the AuthnRequest message received in
        the PAOS request to the IdP in the body of a SOAP
        envelope. Any SOAP header blocks received from the SP in the
        PAOS request MUST be removed from the SOAP envelope before it
        is forwarded to the IdP. However, it is vital we preserve any
        XML namespace declarations which might located in the SOAP
        envelope element otherwise the XML will be malformed because
        the namespace prefixes will be undefined. It is common
        practice to place all namespace declarations on the top most
        XML element which is the SOAP Envelope element.

        To accomplish this we copy the original PAOS SOAP envelope,
        then we remove the envelope Header. What remains is just the
        envelope Body with all the original namespace
        declarations. Note, it is not necessary to copy the original
        request, we could modify it in place but because this a
        demonstration we preserve the original.'''

        self.idp_request_xml = deepcopy(self.paos_request_xml)
        xpath_expr = '/soap:Envelope/soap:Header'
        matches = self.idp_request_xml.xpath('/soap:Envelope/soap:Header',
                                             namespaces=namespaces)
        for element in matches:
            element.getparent().remove(element)

        self.idp_request_text = etree.tostring(self.idp_request_xml)


    def send_authn_request_to_idp(self):
        '''In the previous step we built the SOAP message containing the
        <AuthnRequest> to forward to the IdP. In this function we send
        it to the IdP. Unlike the interactive browser based SAML
        profiles where the IdP is able to interact with the user to
        exchange credentials the ECP profile is non-interactive and
        hence requires authentication to be performed when the
        <AuthnRequest> is sent to the IdP.  HTTP servers at a minimum
        support Basic and Digest authentication but most support
        better authentication methods. Basic and Digest authentication
        is not considered very secure by today's standards but
        represent a lowest common denominator making them a good
        choice for a demo like this. However, the Requests library we
        use to perform HTTP request/response supports numerous other
        authentication methods. Adding support for a new
        authentication method to this demo is simple. You just need to
        instantiate a new class instance derived from
        requests.auth.AuthBase and pass it as the auth parameter to
        the session.post call. Don't forget to update the
        --idp-auth-method command line option to accept the new
        method.'''

        description = banner('ECP sends <AuthnRequest> to IdP with authentication')

        if self.idp_auth_method == 'basic':
            auth=requests.auth.HTTPBasicAuth(self.user, self.password)
        elif self.idp_auth_method == 'digest':
            auth=requests.auth.HTTPDigestAuth(self.user, self.password)
        else:
            raise ValueError('unknown IdP authentication method: "%s"' %
                             self.idp_auth_method)

        headers = {
            'Content-Type': 'text/xml',
        }

        response = self.session.post(self.idp_endpoint, headers=headers,
                                     auth=auth, data=self.idp_request_text)

        self.idp_response_text = response.text

        LOG.info(format_http_request_response(response, self.log_categories,
                                              description))

        if 'saml-message' in self.log_categories:
            LOG.info('SOAP message from ECP to IdP\n%s' %
                     format_xml_from_object(self.idp_request_xml))

    def process_idp_response(self):
        '''We've received a response from the IdP and must process it by
        extracting pieces of data to be used in later steps (or for
        diagnostic/demo purposes) and validating the response conforms
        to the protocol requirements.

        Of the extracted data only the AssertionConsumerServiceURL is
        required by the profile because it will be compared to the
        responseConsumerURL attribute previously found in the
        <paos:Request> SOAP header block originally sent to the ECP
        client by the SP, see the documentation of the
        validate_idp_response() method for more information.'''

        description = banner('Processed response from IdP')

        self.idp_response_xml = etree.fromstring(self.idp_response_text)

        # ECP Response Header Block
        xpath_expr = '/soap:Envelope/soap:Header/ecp:Response'
        ecp_response = get_xml_element(self.idp_response_xml, True, xpath_expr)
        self.validate_soap_attrs(ecp_response, 'IdP to ECP messge, ecp:Response')

        xpath_expr = './@AssertionConsumerServiceURL'
        self.idp_assertion_consumer_url = get_xml_element_text(
            ecp_response, True, xpath_expr)

        # ECP RequestAuthenticated Header Block
        xpath_expr = '/soap:Envelope/soap:Header/ecp:RequestAuthenticated'
        self.idp_request_authenticated = get_xml_element(
            self.idp_response_xml, False, xpath_expr) is not None

        # Get SAML Response)
        self.idp_saml_response_xml = get_xml_element(self.idp_response_xml, True,
                                                 '/soap:Envelope/soap:Body/samlp:Response')

        self.idp_saml_response_status_code = get_xml_element_text(
            self.idp_saml_response_xml,
            True, './samlp:Status/samlp:StatusCode/@Value')

        self.idp_saml_response_status_code2 = get_xml_element_text(
            self.idp_saml_response_xml,
            False, './samlp:Status/samlp:StatusCode/samlp:StatusCode/@Value')

        self.idp_saml_response_status_msg = get_xml_element_text(
            self.idp_saml_response_xml,
            False, './samlp:Status/samlp:StatusMessage')

        self.idp_saml_response_status_detail = get_xml_element_text(
            self.idp_saml_response_xml,
            False, './samlp:Status/samlp:StatusDetail')

        LOG.info(self.format_idp_response_info(self.log_categories,
                                               description))

    def validate_idp_response(self):
        '''After receiving ECP response from the IdP the ECP client MUST
        compare the AssertionConsumerServiceURL attribute from the
        IdP's <ecp:Response> SOAP header block to the
        responseConsumerURL attribute previously found in the
        <paos:Request> SOAP header block originally sent to the ECP
        client by the SP. This is a security measure to assure the
        SAML Response is sent to the intended recipient. If this check
        fails the ECP client sends a SOAP Fault message to the SP
        instead of a PAOS response.        '''

        if (self.sp_response_consumer_url != self.idp_assertion_consumer_url):
            err_msg = (
                'SP responseConsumerURL MUST match IdP AssertionConsumerServiceURL '
                'but responseConsumerURL="%s" AssertionConsumerServiceURL="%s"' %
                (self.sp_response_consumer_url, self.idp_assertion_consumer_url))
            self.sp_response_xml = build_soap_fault('server',
                                                    'invalid response',
                                                    err_msg)
            return False
        return True

    def build_sp_response(self):
        '''Provided we are not sending a SOAP fault back to the SP (as
        determined in the prior operation) we need to build a PAOS
        response to deliver to the SP.

        The ECP client MUST remove any SOAP header blocks received
        from the IdP before forwarding the SAML response to the SP.

        We must be careful to preserve the XML namespace declarations
        which the IdP may have placed on the root SOAP Element because
        the namespace prefixes may be used in the XML contained in the
        envelope body we copy, otherwise the namespace prefixes would
        be undefined.

        The ECP client may need to add a <paos:Response> and
        <ecp:RelayState> SOAP header block to the SOAP Envelope
        before sending it to the SP.

        If the SP sent a RelayState in the original PAOS request the
        ECP client MUST return the RelayState it in the PAOS
        response. We check for the existence of a RelayState and if we
        have a saved copy of it add it to the SOAP Envelope Header.

        If the SP sent a messageID in it's <paos:Request> the ECP
        client MUST return the same value in a <paos:Response>
        refToMessageID attribute. This allows a provider to correlate
        messages (For what it's worth the SAML Request messageID and the SAML
        Response InResponseTo attributes is an alternative method to
        accomplish the same thing).'''

        # If there is an existing SOAP Fault use that instead
        if self.sp_response_xml is not None:
            return

        # Build ECP to SP Response
        #
        # Copy the XML namespace declarations from IdP response,
        # this helps preserve the original namespace prefixes, otherwise
        # lxml will generate anonymous indexed prefixes, e.g. ns0, ns1, ...
        nsmap = self.idp_response_xml.nsmap

        # Add the namespaces we might insert into the response so they have
        # a human readable name instead of anonymous indexed prefixes
        nsmap['paos'] = NS_PAOS
        nsmap['ecp'] = NS_ECP
        envelope = etree.Element(ns_name('soap','Envelope'),
                                    nsmap=nsmap)

        # Do we have to add SOAP header blocks to the response?
        if self.sp_message_id or self.sp_relay_state:
            header = etree.SubElement(envelope, ns_name('soap', 'Header'))

            # Add the <paos:Response> header block
            if self.sp_message_id:
                paos_response = etree.SubElement(header, ns_name('paos', 'Response'))
                paos_response.set(ns_name('soap', 'actor'),
                                 SOAP_ACTOR)
                paos_response.set(ns_name('soap', 'mustUnderstand'),
                                 SOAP_MUST_UNDERSTAND)
                paos_response.set(ns_name('paos', 'refToMessageID'),
                                 self.sp_message_id)

            # Add the <ecp:RelayState> header block
            if self.sp_relay_state:
                ecp_relay_state = etree.SubElement(header, ns_name('ecp', 'RelayState'))
                ecp_relay_state.set(ns_name('soap', 'actor'),
                                 SOAP_ACTOR)
                ecp_relay_state.set(ns_name('soap', 'mustUnderstand'),
                                 SOAP_MUST_UNDERSTAND)
                ecp_relay_state.text = self.sp_relay_state

        # Add the SOAP body received from the IdP to our response
        body = etree.SubElement(envelope, ns_name('soap', 'Body'))
        body.append(self.idp_saml_response_xml)

        self.sp_response_xml = envelope

    def send_sp_response(self):
        '''This is the last step in the ECP flow. The ECP client forwards the
        SAML Response received from the IdP wrapped in a PAOS response
        to the SP's appropriate assertion consumer service URL
        (i.e. the responseConsumerURL sent in the PAOS request). If
        the ECP client generated a SOAP Fault due to an error that is
        sent instead. Provided the SP accepts the SAML authentication
        and authorizes the request the original SP resource is
        returned.'''

        description = banner('Send PAOS response to SP, if successful SP resource is returned')

        LOG.info('%s\nSP Endpoint: %s\n' % (
            banner('PAOS response sent to SP'), self.sp_response_consumer_url))
        if 'saml-message' in self.log_categories:
            LOG.info('%s' % format_xml_from_object(self.sp_response_xml))

        sp_response_text = etree.tostring(self.sp_response_xml)

        headers = {
            'Content-Type': 'application/vnd.paos+xml',
        }

        response = self.session.post(self.sp_response_consumer_url,
                                     headers=headers,
                                     data=sp_response_text)

        LOG.info(format_http_request_response(response, self.log_categories,
                                              description))

        if 'sp-resource' in self.log_categories:
            LOG.info('%s\n%s', banner('SP Resource'), response.text)

#---------------------------- Script Main Function -----------------------------

# Usage text

usage_text = '''\
Usage:
======

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
'''

# Script argument parsing utilities

log_categories_help = '''\

You can enable or disable certain categories of logging to increase or
decrease the output verbosity or to limit the output to specific areas
of interest. The available log categories are %s. This option takes a
comma (,) separated list of categories which adds or removes a
category from the default category set, which are %s.  If the category
is prefixed with an exclamation point (!) the category is removed from
the set, otherwise it is added.  For example to remove the sp-resource
category and add the http-content category to the default set use
--log-categories "!sp-resource,http-content"''' % (valid_log_categories,
                                                   default_log_categories)


class LogCategoryAction(argparse.Action):
    def __init__(self, option_strings, dest, nargs=None, **kwargs):
        if nargs is not None:
            raise ValueError("nargs not allowed")
        super(LogCategoryAction, self).__init__(option_strings, dest, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        log_categories = getattr(namespace, self.dest)
        for category in values.split(','):
            if not category:
                continue

            adding = True
            if category.startswith('!'):
                adding = False
                category = category[1:]

            if category not in valid_log_categories:
                msg = ('invalid log category "%s", valid categores are %s' %
                       (values, sorted(valid_log_categories)))
                raise argparse.ArgumentTypeError(msg)

            if adding:
                log_categories.add(category)
            else:
                log_categories.discard(category)

        setattr(namespace, self.dest, log_categories)

#### Main Function ####

def main():
    result = 0

    parser = argparse.ArgumentParser(description='SAML ECP Demo',
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     epilog=usage_text)

    parser.add_argument('-s', '--sp-resource', required=True,
                        help='SP resource URL')

    parser.add_argument('-i', '--idp-endpoint', required=True,
                        help='IdP SOAP binding URL')

    parser.add_argument('-u', '--user', required=True,
                        help='user id for IdP login')

    parser.add_argument('-p', '--password',
                        help='user password for IdP login, '
                        'if not supplied will prompt on terminal')

    parser.add_argument('--idp-auth-method',
                        choices=['basic', 'digest'], default='basic',
                        help='Authentication method used when forwarding '
                        'authnRequest to IdP')

    parser.add_argument('-l', '--log-categories',
                        action=LogCategoryAction, dest='log_categories',
                        default=default_log_categories,
                        help=log_categories_help)

    parser.add_argument('--log-file',
                        help='log to file pathname instead of the console')

    parser.add_argument('--show-traceback', action='store_true',
                        help='If an exception is raised print the stack '
                        'trace. This is helpful when diagnosing errors')

    options = parser.parse_args()

    if options.password is None:
        options.password = getpass.getpass('Enter password for "%s": '
                                           % (options.user))

    setup_logging(options, options.log_categories)

    try:
        ecp = ECPFlow(options.sp_resource,
                      options.idp_endpoint,
                      options.user,
                      options.password,
                      options.idp_auth_method,
                      options.log_categories)

        ecp.run()
    except Exception as e:
        if options.show_traceback:
            LOG.exception('jrd Error')
        LOG.error('%s' % (e))
        result = 1

    return result
#-------------------------------------------------------------------------------

if __name__ == '__main__':
    sys.exit(main())
