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
#include "EndpointDescription.h"
#include "Utils.h"

using namespace AnsiCStackQuickstart;

//============================================================================
// EndpointDescription::Constructor
//============================================================================
EndpointDescription::EndpointDescription(void)
{
}

//============================================================================
// EndpointDescription::Constructor(OpcUa_EndpointDescription)
//============================================================================
EndpointDescription::EndpointDescription(OpcUa_EndpointDescription* pDescription)
{
	m_eSecurityMode = OpcUa_MessageSecurityMode_Invalid;

	if (pDescription != 0)
	{
		m_serverUri = OpcUa_String_GetRawString(&pDescription->Server.ApplicationUri);
		m_endpointUrl = OpcUa_String_GetRawString(&pDescription->EndpointUrl);
		m_eSecurityMode = pDescription->SecurityMode;
		m_securityPolicyUri = Utils::Copy(&pDescription->SecurityPolicyUri);
		m_serverCertificate = Utils::Copy(&pDescription->ServerCertificate);

		for (int ii = 0; ii < pDescription->NoOfUserIdentityTokens; ii++)
		{
			m_userTokenPolicies.push_back(UserTokenPolicy(&(pDescription->UserIdentityTokens[ii])));
		}
	}
}

//============================================================================
// EndpointDescription::Destructor
//============================================================================
EndpointDescription::~EndpointDescription(void)
{
}

//============================================================================
// UserTokenPolicy::Constructor
//============================================================================
UserTokenPolicy::UserTokenPolicy(void)
{
}

//============================================================================
// UserTokenPolicy::Constructor(OpcUa_UserTokenPolicy)
//============================================================================
UserTokenPolicy::UserTokenPolicy(OpcUa_UserTokenPolicy* pPolicy)
{
	m_eTokenType = OpcUa_UserTokenType_Anonymous;

	if (pPolicy != 0)
	{
		m_policyId = OpcUa_String_GetRawString(&pPolicy->PolicyId);
		m_eTokenType = pPolicy->TokenType;
		m_securityPolicyUri = Utils::Copy(&pPolicy->SecurityPolicyUri);
	}
}

//============================================================================
// UserTokenPolicy::Destructor
//============================================================================
UserTokenPolicy::~UserTokenPolicy(void)
{
}
