/* ========================================================================
 * Copyright (c) 2005-2010 The OPC Foundation, Inc. All rights reserved.
 *
 * OPC Foundation MIT License 1.00
 * 
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * The complete license agreement can be found here:
 * http://opcfoundation.org/License/MIT/1.00/
 * ======================================================================*/

#include "StdAfx.h"
#include "Application.h"
#include "Utils.h"
#include "Channel.h"
#include "CustomDataType.h"

#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/err.h>

using namespace AnsiCStackQuickstart;

#define CLIENT_SERIALIZER_MAXALLOC                   16777216
#define CLIENT_ENCODER_MAXSTRINGLENGTH               ((OpcUa_UInt32)16777216)
#define CLIENT_ENCODER_MAXARRAYLENGTH                ((OpcUa_UInt32)65536)
#define CLIENT_ENCODER_MAXBYTESTRINGLENGTH           ((OpcUa_UInt32)16777216)
#define CLIENT_ENCODER_MAXMESSAGELENGTH              ((OpcUa_UInt32)16777216)
#define CLIENT_SECURELISTENER_THREADPOOL_MINTHREADS  5
#define CLIENT_SECURELISTENER_THREADPOOL_MAXTHREADS  5
#define CLIENT_SECURELISTENER_THREADPOOL_MAXJOBS     20
#define CLIENT_SECURITYTOKEN_LIFETIME_MAX            3600000
#define CLIENT_SECURITYTOKEN_LIFETIME_MIN            60000
#define CLIENT_TCPLISTENER_DEFAULTCHUNKSIZE          ((OpcUa_UInt32)65536)
#define CLIENT_TCPCONNECTION_DEFAULTCHUNKSIZE        ((OpcUa_UInt32)65536)

/*============================================================================
 * g_Custom_EncodeableTypes
 *===========================================================================*/
static OpcUa_EncodeableType* g_Custom_EncodeableTypes[] = 
{
    &CustomDataType_EncodeableType,
    OpcUa_Null
};

/*============================================================================
 * a_Custom_NamespaceUris
 *===========================================================================*/
static OpcUa_StringA a_Custom_NamespaceUris[] =
{
    "http://opcfoundation.org/UA/", // standard UA namespace must be first.
	"",                             // application uri is the second namespace (does not need to be filled in).
	NamespaceURI_CustomDataType,    // add custom namespaces.
    OpcUa_Null
};

//============================================================================
// Application::Constructor
//============================================================================
Application::Application(void)
{
	m_hPlatformLayer = 0;

	memset(&m_hPlatformLayer, 0, sizeof(OpcUa_ProxyStubConfiguration));
	memset(&m_tPkiConfig, 0, sizeof(OpcUa_P_OpenSSL_CertificateStore_Config));
	memset(&m_tPkiProvider, 0, sizeof(OpcUa_PKIProvider));
	memset(&m_tCertificate, 0, sizeof(OpcUa_ByteString));
	memset(&m_tPrivateKey, 0, sizeof(OpcUa_Key));
}

//============================================================================
// Application::Destructor
//============================================================================
Application::~Application(void)
{
	Cleanup();
}

//============================================================================
// Application::Cleanup
//============================================================================
void Application::Cleanup(void)
{
    OpcUa_PKIProvider_Delete(&m_tPkiProvider);
	memset(&m_hPlatformLayer, 0, sizeof(OpcUa_ProxyStubConfiguration));

	OpcUa_Free(m_tPkiConfig.IssuerCertificateStorePath);
	OpcUa_Free(m_tPkiConfig.TrustedCertificateStorePath);
	memset(&m_tPkiConfig, 0, sizeof(OpcUa_P_OpenSSL_CertificateStore_Config));

    OpcUa_ByteString_Clear(&m_tCertificate);
    OpcUa_Key_Clear(&m_tPrivateKey);

	if (m_hPlatformLayer != 0)
	{
		OpcUa_ProxyStub_Clear();
		OpcUa_P_Clean(&m_hPlatformLayer);
		m_hPlatformLayer = 0;
	}
}

//============================================================================
// Application::Uninitialize
//============================================================================
void Application::Uninitialize(void)
{
	Cleanup();
}

//============================================================================
// Application::Initialize
//============================================================================
void Application::Initialize(void)
{
    OpcUa_StatusCode uStatus = OpcUa_Good;

    try
    {
	    // initialize the WIN32 platform layer. 
	    m_hPlatformLayer = 0;
	    uStatus = OpcUa_P_Initialize(&m_hPlatformLayer);
	    ThrowIfBad(uStatus, "Could not initialize platform layer.");

	    // these parameters control tracing.
	    m_tConfiguration.bProxyStub_Trace_Enabled              = OpcUa_True;
	    m_tConfiguration.uProxyStub_Trace_Level                = OPCUA_TRACE_OUTPUT_LEVEL_SYSTEM;

	    // these parameters are used to protect against buffer overflows caused by bad data.
	    // they may need to be adjusted depending on the needs of the application.
	    // the server also sets these limits which means errors could occur even if these limits are raised. 
	    m_tConfiguration.iSerializer_MaxAlloc                  = CLIENT_SERIALIZER_MAXALLOC;
	    m_tConfiguration.iSerializer_MaxStringLength           = CLIENT_ENCODER_MAXSTRINGLENGTH;
	    m_tConfiguration.iSerializer_MaxByteStringLength       = CLIENT_ENCODER_MAXARRAYLENGTH;
	    m_tConfiguration.iSerializer_MaxArrayLength            = CLIENT_ENCODER_MAXBYTESTRINGLENGTH;
	    m_tConfiguration.iSerializer_MaxMessageSize            = CLIENT_ENCODER_MAXMESSAGELENGTH;

	    // the thread pool is only used in a server to dispatch incoming requests.
	    m_tConfiguration.bSecureListener_ThreadPool_Enabled    = OpcUa_False;
	    m_tConfiguration.iSecureListener_ThreadPool_MinThreads = CLIENT_SECURELISTENER_THREADPOOL_MINTHREADS;
	    m_tConfiguration.iSecureListener_ThreadPool_MaxThreads = CLIENT_SECURELISTENER_THREADPOOL_MAXTHREADS;
	    m_tConfiguration.iSecureListener_ThreadPool_MaxJobs    = CLIENT_SECURELISTENER_THREADPOOL_MAXJOBS;
	    m_tConfiguration.bSecureListener_ThreadPool_BlockOnAdd = OpcUa_True;
	    m_tConfiguration.uSecureListener_ThreadPool_Timeout    = OPCUA_INFINITE;

	    // these parameters are used to tune performance. larger chunks == more memory, slower performance.
	    m_tConfiguration.iTcpListener_DefaultChunkSize         = CLIENT_TCPLISTENER_DEFAULTCHUNKSIZE;
	    m_tConfiguration.iTcpConnection_DefaultChunkSize       = CLIENT_TCPCONNECTION_DEFAULTCHUNKSIZE;
	    m_tConfiguration.iTcpTransport_MaxMessageLength        = CLIENT_ENCODER_MAXMESSAGELENGTH;
	    m_tConfiguration.iTcpTransport_MaxChunkCount           = -1;
	    m_tConfiguration.bTcpListener_ClientThreadsEnabled     = OpcUa_False;
	    m_tConfiguration.bTcpStream_ExpectWriteToBlock         = OpcUa_True;

	    // initialize the stack.
	    uStatus = OpcUa_ProxyStub_Initialize(m_hPlatformLayer, &m_tConfiguration);
	    ThrowIfBad(uStatus, "Could not initialize proxy/stubs.");

		// initialize table with custom types.
		uStatus = OpcUa_ProxyStub_AddTypes(g_Custom_EncodeableTypes);
		ThrowIfBad(uStatus, "Could not add custom types to type table.");	

		// update the namespace table.
		uStatus = OpcUa_ProxyStub_SetNamespaceUris(a_Custom_NamespaceUris);
		ThrowIfBad(uStatus, "Could not update the namespace table.");	
    }
    catch (...)
    {
        throw;
    }
}

//============================================================================
// Application::InitializeSecurity
//============================================================================
void Application::InitializeSecurity(std::string certificateStorePath)
{	
    OpcUa_StatusCode uStatus = OpcUa_Good;
    OpcUa_ByteString tCertificate;
    OpcUa_Key tPrivateKey;
    OpcUa_Handle pContext = NULL;
    OpcUa_StringA sThumbprint = NULL;
    OpcUa_StringA sApplicationUri = NULL;

    try
    {
        // find the first certificate in the store with application name and a private key.
        // this example uses the same store for the private keys and trusted certificates.
        // they can be in seperate locations.
        do
        {
            uStatus = OpcUa_Certificate_FindCertificateInStore(
                &pContext,
                (OpcUa_StringA)certificateStorePath.c_str(),
                OpcUa_True,
                NULL,
                (OpcUa_StringA)m_applicationName.c_str(),
                NULL,
                &tCertificate,
                &tPrivateKey);
            
            ThrowIfBad(uStatus, "Could access certificate store.");

            if (tCertificate.Length > 0 && tPrivateKey.Key.Length > 0)
            {
                break;
            }

            OpcUa_ByteString_Clear(&tCertificate);
            OpcUa_Key_Clear(&tPrivateKey);
        }
        while (pContext != NULL);

        // create a new self-signed certificate if none found.
        if (tCertificate.Length <= 0)
        {
            uStatus = OpcUa_Certificate_Create(
                (OpcUa_StringA)certificateStorePath.c_str(),
                (OpcUa_StringA)m_applicationName.c_str(),
				NULL,
				NULL,
				NULL,
                0,
                NULL,
                0,
                1024,
                600,
				OpcUa_False,
				OpcUa_False,
                OpcUa_Crypto_Encoding_PKCS12,
                NULL,
                NULL,
                NULL,
                &tCertificate,
                NULL,
                &tPrivateKey,
                NULL);

            ThrowIfBad(uStatus, "Could not create self signed certificate.");
        }

        // extract the information from the certificate.
        uStatus = OpcUa_Certificate_GetInfo(
            &tCertificate,
            NULL,
            NULL,
            NULL,
            &sThumbprint,
            &sApplicationUri,
            NULL,
            NULL);
        
        ThrowIfBad(uStatus, "Could not extract information from application certificate.");

        // the stack requires a reference to the subdirectory.
        m_certificateStorePath = certificateStorePath;

	    // specify the trust list to used by the stack to validate certificates. 
        m_tPkiConfig.PkiType						   = OpcUa_OpenSSL_PKI;    
        m_tPkiConfig.Flags							   = 0;
	    m_tPkiConfig.IssuerCertificateStorePath		   = NULL;
		m_tPkiConfig.TrustedCertificateStorePath	   = Utils::StrDup(certificateStorePath.c_str());

        uStatus = OpcUa_PKIProvider_Create(&m_tPkiConfig, &m_tPkiProvider);
        ThrowIfBad(uStatus, "Could not initialize PKI provider.");

        // save information for later use.
        m_thumbprint = sThumbprint;
        m_applicationUri = sApplicationUri;
        m_tCertificate = tCertificate;
        m_tPrivateKey = tPrivateKey;

        OpcUa_Free(sThumbprint);
        OpcUa_Free(sApplicationUri);
    }
    catch (...)
    {
        OpcUa_ByteString_Clear(&tCertificate);
        OpcUa_Key_Clear(&tPrivateKey);
        OpcUa_Free(sThumbprint);
        OpcUa_Free(sApplicationUri);
        throw;
    }
}

//============================================================================
// Application::DiscoverEndpoints
//============================================================================
std::vector<EndpointDescription> Application::DiscoverEndpoints(std::string discoveryUrl)
{
    OpcUa_StatusCode uStatus = OpcUa_Good;
    OpcUa_RequestHeader tRequestHeader;
	OpcUa_String sDiscoveryUrl;
    OpcUa_String sLocaleIds;
    OpcUa_String sProfileUris;
    OpcUa_ResponseHeader tResponseHeader;
    OpcUa_Int32 nNoOfEndpoints = 0;
    OpcUa_EndpointDescription* pEndpoints = OpcUa_Null;
    
	Channel channel(this);
	std::vector<EndpointDescription> endpoints;

    try
    {
        OpcUa_RequestHeader_Initialize(&tRequestHeader);
        OpcUa_String_Initialize(&sDiscoveryUrl);
        OpcUa_String_Initialize(&sLocaleIds);
        OpcUa_String_Initialize(&sProfileUris);
        OpcUa_ResponseHeader_Initialize(&tResponseHeader);

	    // connect to the server.
	    channel.Connect(discoveryUrl);

	    // get the endpoints.
	    tRequestHeader.TimeoutHint = UTILS_DEFAULT_TIMEOUT;
	    tRequestHeader.Timestamp   = OpcUa_DateTime_UtcNow();

	    // need to wrap the DiscoveryUrl with a OpcUa_String structure.
        uStatus = OpcUa_String_AttachReadOnly(&sDiscoveryUrl, (OpcUa_StringA)discoveryUrl.c_str());
        ThrowIfCallFailed(uStatus, OpcUa_String_AttachReadOnly);

	    uStatus = OpcUa_ClientApi_GetEndpoints(  
		    channel.GetHandle(), 
		    &tRequestHeader,
		    &sDiscoveryUrl,
		    0,
		    &sLocaleIds, 
		    0,
		    &sProfileUris, 
		    &tResponseHeader,
		    &nNoOfEndpoints,
		    &pEndpoints);

        ThrowIfBad(uStatus, "Could not get endpoints from server.");

	    // copy enpoints to a vector.
	    if (pEndpoints != OpcUa_Null)
	    {
		    for (OpcUa_Int32 ii = 0; ii < nNoOfEndpoints; ii++)
		    { 
			    endpoints.push_back(&(pEndpoints[ii]));
		    } 
	    }

	    // clean up.
        OpcUa_RequestHeader_Clear(&tRequestHeader);
        OpcUa_String_Clear(&sDiscoveryUrl);
        OpcUa_String_Clear(&sLocaleIds);
        OpcUa_String_Clear(&sProfileUris);
        OpcUa_ResponseHeader_Clear(&tResponseHeader);
	    Utils_ClearArray(pEndpoints, nNoOfEndpoints, OpcUa_EndpointDescription);

	    // disconnect.
	    channel.Disconnect();

	    return endpoints;
    }
    catch (...)
    {
	    // disconnect.
	    channel.Disconnect();

	    // clean up.
        OpcUa_RequestHeader_Clear(&tRequestHeader);
        OpcUa_String_Clear(&sDiscoveryUrl);
        OpcUa_String_Clear(&sLocaleIds);
        OpcUa_String_Clear(&sProfileUris);
        OpcUa_ResponseHeader_Clear(&tResponseHeader);
	    Utils_ClearArray(pEndpoints, nNoOfEndpoints, OpcUa_EndpointDescription);

	    throw;
    }
}

//============================================================================
// Application::TrustCertificate
//============================================================================
void Application::TrustCertificate(std::vector<unsigned char> certificate)
{
    OpcUa_StatusCode uStatus = OpcUa_Good;
    OpcUa_ByteString tCertificate;

    try
    {
        tCertificate = Utils::Copy(certificate);

        uStatus = OpcUa_Certificate_SavePublicKeyInStore(
            (OpcUa_StringA)m_certificateStorePath.c_str(),
            &tCertificate,
            NULL);

        ThrowIfBad(uStatus, "Could not add certificate to the application's trusted store.");

        OpcUa_ByteString_Clear(&tCertificate);
    }
    catch (...)
    {
        OpcUa_ByteString_Clear(&tCertificate);
        throw;
    }
}
