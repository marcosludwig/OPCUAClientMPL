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

class Application;

// Manages a communiction channel with a server.
class Channel
{
public:

	// Constructs a channel that can be used by the specified application.
	Channel(Application* pApplication);

	// Releases all resources used by the channel.
	~Channel(void);

	// Connects to the endpoint with no security.
	void Connect(std::string endpointUrl);

	// Connects to the endpoint with the security specified in the EndpointDescription.
	void Connect(EndpointDescription endpoint);

	// Disconnects from the server.
	void Disconnect(void);

	// Returns the stack assigned handled for the channel.
	OpcUa_Channel GetHandle()
	{
		return m_hChannel;
	}
	
private:

	// Connects to the server.
	void InternalConnect();

	Application* m_pApplication;
	std::string m_endpointUrl;
	OpcUa_Channel m_hChannel;
	OpcUa_String m_sSecurityPolicy;
	OpcUa_MessageSecurityMode m_eSecurityMode;
	OpcUa_ByteString m_tServerCertificate;
	OpcUa_ChannelSecurityToken* m_pSecurityToken;
};

} // namespace AnsiCStackQuickstart
