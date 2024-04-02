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

namespace AnsiCStackQuickstart {

class UserTokenPolicy;

// Stores the information required to connect to a UA server.
class EndpointDescription
{
public:

	// Creates an empty description.
	EndpointDescription(void);

	// Initializes the object from a OpcUa_EndpointDescription.
	EndpointDescription(OpcUa_EndpointDescription* pDescription);

	// Releases all resources used by the object.
	~EndpointDescription(void);

	// Returns the globally unique identifier for the server application.
	std::string GetServerUri()
	{
		return m_serverUri;
	}

	// Returns the URL of the server endpoint.
	std::string GetEndpointUrl()
	{
		return m_endpointUrl;
	}

	// Returns the security mode used by the endpoint.
	OpcUa_MessageSecurityMode GetSecurityMode()
	{
		return m_eSecurityMode;
	}

	// Returns the security policy used by the endpoint.
	std::string GetSecurityPolicyUri()
	{
		return m_securityPolicyUri;
	}

	// Returns the server's instance certificate.
	std::vector<unsigned char> GetServerCertificate()
	{
		return m_serverCertificate;
	}

	// Returns the server's supported user tokens.
	std::vector<UserTokenPolicy> GetUserTokenPolicies()
	{
		return m_userTokenPolicies;
	}

private:

	std::string m_serverUri;
	std::string m_endpointUrl;
	std::string m_securityPolicyUri;
	OpcUa_MessageSecurityMode m_eSecurityMode;
	std::vector<unsigned char> m_serverCertificate;
	std::vector<UserTokenPolicy> m_userTokenPolicies;
};

// Stores the information about a user identity token.
class UserTokenPolicy
{
public:

	// Creates an empty policy.
	UserTokenPolicy(void);

	// Initializes the object from a OpcUa_UserTokenPolicy.
	UserTokenPolicy(OpcUa_UserTokenPolicy* pPolicy);

	// Releases all resources used by the object.
	~UserTokenPolicy(void);

	// Returns the id assigned by the server.
	std::string GetPolicyId()
	{
		return m_policyId;
	}

	// Returns the token type.
	OpcUa_UserTokenType GetTokenType()
	{
		return m_eTokenType;
	}

	// Returns the security policy used by the token.
	std::string GetSecurityPolicyUri()
	{
		return m_securityPolicyUri;
	}

private:

	std::string m_policyId;
	OpcUa_UserTokenType m_eTokenType;
	std::string m_securityPolicyUri;
};

} // namespace AnsiCStackQuickstart
