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
#include "Channel.h"
#include "Application.h"
#include "Utils.h"

using namespace AnsiCStackQuickstart;

//============================================================================
// Channel::Constructor
//============================================================================
Channel::Channel(Application* pApplication)
{
	m_pApplication = pApplication;
	m_hChannel = 0;
	m_pSecurityToken = 0;
	m_eSecurityMode = OpcUa_MessageSecurityMode_None;

    OpcUa_String_Initialize(&m_sSecurityPolicy);
    OpcUa_ByteString_Initialize(&m_tServerCertificate);	
}

//============================================================================
// Channel::Destructor
//============================================================================
Channel::~Channel(void)
{
	Disconnect();
}

//============================================================================
// Channel::Connect(endpointUrl)
//============================================================================
void Channel::Connect(std::string endpointUrl)
{
	m_endpointUrl = endpointUrl;
	m_eSecurityMode = OpcUa_MessageSecurityMode_None;
	
	OpcUa_String_AttachToString( 
		OpcUa_SecurityPolicy_None, 
		OPCUA_STRINGLENZEROTERMINATED, 
		0,
		OpcUa_False, 
		OpcUa_False, 
		&m_sSecurityPolicy);

    OpcUa_ByteString_Initialize(&m_tServerCertificate);

	InternalConnect();
}

//============================================================================
// Channel::Connect(endpoint)
//============================================================================
void Channel::Connect(EndpointDescription endpoint)
{
	m_endpointUrl = endpoint.GetEndpointUrl();
	m_sSecurityPolicy = Utils::Copy(endpoint.GetSecurityPolicyUri());
	m_tServerCertificate = Utils::Copy(endpoint.GetServerCertificate());
	m_eSecurityMode = endpoint.GetSecurityMode();

	InternalConnect();
}

//============================================================================
// Channel::InternalConnect
//============================================================================
void Channel::InternalConnect()
{
    OpcUa_StatusCode uStatus = OpcUa_Good;

    try
    {
	    // create the channel. only binary encoding supported at this time.
	    uStatus = OpcUa_Channel_Create(&m_hChannel, OpcUa_Channel_SerializerType_Binary);
	    ThrowIfBad(uStatus, "Could not create new channel");
    	
	    // connect to the server.
	    uStatus = OpcUa_Channel_Connect(   
		    m_hChannel,
		    (OpcUa_StringA)m_endpointUrl.c_str(),
		    OpcUa_Null,
		    OpcUa_Null,
		    m_pApplication->GetCertificate(),
		    &m_pApplication->GetPrivateKey()->Key,
		    &m_tServerCertificate,
		    m_pApplication->GetPkiConfig(),
		    &m_sSecurityPolicy,
		    OPCUA_SECURITYTOKEN_LIFETIME_MAX,
		    m_eSecurityMode,
		    &m_pSecurityToken,
		    UTILS_DEFAULT_TIMEOUT); 

	    ThrowIfBad(uStatus, "Could not connect to server.");
    }
    catch (...)
    {
	    Disconnect();
	    throw;
    }
}

//============================================================================
// Channel::Disconnect
//============================================================================
void Channel::Disconnect()
{
	if (m_hChannel != 0)
	{
		OpcUa_Channel_Disconnect(m_hChannel);
	    OpcUa_Channel_Delete(&m_hChannel);
	}
	
	OpcUa_String_Clear(&m_sSecurityPolicy);
    OpcUa_ByteString_Clear(&m_tServerCertificate);	

	if (m_pSecurityToken != 0)
	{
		OpcUa_ChannelSecurityToken_Clear(m_pSecurityToken);
		OpcUa_Free(m_pSecurityToken);
		m_pSecurityToken = 0;
	}
}
