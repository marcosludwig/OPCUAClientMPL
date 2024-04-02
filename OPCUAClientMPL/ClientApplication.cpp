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
#include "ClientApplication.h"
#include "StatusCodeException.h"
#include "Utils.h"
#include "Channel.h"

using namespace AnsiCStackQuickstart;


ClientApplication::ClientApplication(void)
{
}

ClientApplication::~ClientApplication(void)
{
}

std::vector<ServerDescription> ClientApplication::FindServers(std::string hostName)
{
	Channel channel(this);
	std::vector<ServerDescription> servers;

	std::string discoveryUrl;
    OpcUa_RequestHeader tRequestHeader;
	OpcUa_String sDiscoveryUrl;
    OpcUa_String sLocaleIds;
    OpcUa_String sServerUris;
    OpcUa_ResponseHeader tResponseHeader;
    OpcUa_Int32 nNoOfServers = 0;
    OpcUa_ApplicationDescription* pServers = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_Client, "ClientApplication::FindServers");

    OpcUa_RequestHeader_Initialize(&tRequestHeader);
    OpcUa_String_Initialize(&sDiscoveryUrl);
    OpcUa_String_Initialize(&sLocaleIds);
    OpcUa_String_Initialize(&sServerUris);
    OpcUa_ResponseHeader_Initialize(&tResponseHeader);

	// construct the discovery url from the host name.	
	discoveryUrl.append("opc.tcp://");

	if (!hostName.empty())
	{
		discoveryUrl.append(hostName);
	}
	else
	{
		discoveryUrl.append("localhost");
	}

	discoveryUrl.append(":4840");

	channel.Connect(discoveryUrl);

	// find the servers.
	tRequestHeader.TimeoutHint = UTILS_DEFAULT_TIMEOUT;
	tRequestHeader.Timestamp   = OpcUa_DateTime_UtcNow();

	// need to wrap the dicovery url with a OpcUa_String structure.
    uStatus = OpcUa_String_AttachReadOnly(&sDiscoveryUrl, (OpcUa_StringA)discoveryUrl.c_str());
    OpcUa_GotoErrorIfBad(uStatus);

	// find the servers.
	uStatus = OpcUa_ClientApi_FindServers(  
		channel.GetHandle(), 
		&tRequestHeader,
		&sDiscoveryUrl,
		0,
		&sLocaleIds, 
		0,
		&sServerUris, 
		&tResponseHeader,
		&nNoOfServers,
		&pServers);

    OpcUa_GotoErrorIfBad(uStatus);
	
	// copy the available servers into a vector.
	if (pServers != OpcUa_Null)
	{
		for (OpcUa_Int32 ii = 0; ii < nNoOfServers; ii++)
		{ 
            // ignore discovery servers.
            if (pServers[ii].ApplicationType == OpcUa_ApplicationType_DiscoveryServer)
            {
                continue;
            }

			servers.push_back(&(pServers[ii]));
		}
	}

	// clean up.
    OpcUa_RequestHeader_Clear(&tRequestHeader);
    OpcUa_String_Clear(&sDiscoveryUrl);
    OpcUa_String_Clear(&sLocaleIds);
    OpcUa_String_Clear(&sServerUris);
    OpcUa_ResponseHeader_Clear(&tResponseHeader);
	Utils_ClearArray(pServers, nNoOfServers, OpcUa_ApplicationDescription);

	// disconnect.
	channel.Disconnect();

	return servers;

OpcUa_BeginErrorHandling;

	// disconnect.
	channel.Disconnect();

	// clean up.
    OpcUa_RequestHeader_Clear(&tRequestHeader);
    OpcUa_String_Clear(&sDiscoveryUrl);
    OpcUa_String_Clear(&sLocaleIds);
    OpcUa_String_Clear(&sServerUris);
    OpcUa_ResponseHeader_Clear(&tResponseHeader);
	Utils_ClearArray(pServers, nNoOfServers, OpcUa_ApplicationDescription);

	throw StatusCodeException(uStatus, "Could not find servers available on host.");
}
