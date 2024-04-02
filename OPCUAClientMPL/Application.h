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

#pragma once

#include "EndpointDescription.h"

namespace AnsiCStackQuickstart {

// Stores information associated with a UA application instance.
class Application
{
public:
	Application(void);
	~Application(void);

	// Initializes the stack and application.
	virtual void Initialize(void);

	// Frees all resources used by the stack and application.
	virtual void Uninitialize(void);

	// Initializes security and loads the application instance certificate from an OpenSSL certificate store.
    virtual void InitializeSecurity(std::string certificateStorePath);

    // Adds the certificate to the trusted peer store for the application.
    void TrustCertificate(std::vector<unsigned char> certificate);

	// Returns the application name.
	std::string GetApplicationName()
	{
		return m_applicationName;
	}

	// Sets the application name.
	void SetApplicationName(std::string applicationName)
	{
		m_applicationName = applicationName;
	}

	// Returns the application instance URI.
	std::string GetApplicationUri()
	{
		return m_applicationUri;
	}

	// Sets the application instance URI.
	void SetApplicationUri(std::string applicationUri)
	{
		m_applicationUri = applicationUri;
	}

	// Returns the application product URI.
	std::string GetProductUri()
	{
		return m_productUri;
	}

	// Sets the application product URI.
	void SetProductUri(std::string productUri)
	{
		m_productUri = productUri;
	}

	// Returns the certificate store path.
	std::string GetCertificateStorePath()
	{
		return m_certificateStorePath;
	}

	// Sets the certificate store path.
	void SetCertificateStorePath(std::string certificateStorePath)
	{
		m_certificateStorePath = certificateStorePath;
        ::CreateDirectoryA(m_certificateStorePath.c_str(), NULL);
	}

    // Creates a self-signed certificate for the application.
    void CreateCertificate(
        std::string applicationName,
        std::vector<std::string> hostNames,
        unsigned int keySize,
        unsigned int lifetimeInMonths);

	// Returns the application instance certificate.
	OpcUa_ByteString* GetCertificate()
	{
		return &m_tCertificate;
	}
	
	// Returns the application instance certificate's private key.
	OpcUa_Key* GetPrivateKey()
	{
		return &m_tPrivateKey;
	}
	
	// Returns the configuration for the PKI provider used by the application.
	OpcUa_P_OpenSSL_CertificateStore_Config* GetPkiConfig()
	{
		return &m_tPkiConfig;
	}
	
	// Returns the PKI provider used by the application.
	OpcUa_PKIProvider* GetPkiProvider()
	{
		return &m_tPkiProvider;
	}

	// Fetches the endpoint descriptions from a discovery endpoint.
	std::vector<EndpointDescription> DiscoverEndpoints(std::string discoveryUrl);

private:

	// Frees memory allocated by the object.
	void Cleanup(void);
	OpcUa_ByteString m_tCertificate;
	OpcUa_Key m_tPrivateKey;

	std::string m_applicationName;
	std::string m_applicationUri;
	std::string m_productUri;
	std::string m_certificateStorePath;
	std::string m_thumbprint;
	OpcUa_Handle m_hPlatformLayer;
	OpcUa_ProxyStubConfiguration m_tConfiguration;
	OpcUa_PKIProvider m_tPkiProvider;
	OpcUa_P_OpenSSL_CertificateStore_Config m_tPkiConfig;
};

} // namespace AnsiCStackQuickstart
