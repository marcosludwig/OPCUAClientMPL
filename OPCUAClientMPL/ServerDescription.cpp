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
#include "ServerDescription.h"

using namespace AnsiCStackQuickstart;

ServerDescription::ServerDescription(void)
{
}

ServerDescription::ServerDescription(OpcUa_ApplicationDescription* pDescription)
{
	if (pDescription != 0)
	{
		// save the server name.
		OpcUa_StringA sText = OpcUa_String_GetRawString(&pDescription->ApplicationName.Text);

		if (sText != 0)
		{
			m_serverName = sText;
		}

		// only keep the UA TCP discovery url.
		if (pDescription->DiscoveryUrls != 0)
		{
			for (int ii = 0; ii < pDescription->NoOfDiscoveryUrls; ii++)
			{
				OpcUa_StringA sText = OpcUa_String_GetRawString(&pDescription->DiscoveryUrls[ii]);

				if (sText != 0)
				{
					m_discoveryUrl = sText;

					std::string::size_type index = m_discoveryUrl.find("opc.tcp");

					if (index != std::string::npos)
					{
						break;
					}
				}
			}
		}
	}
}

ServerDescription::~ServerDescription(void)
{
}
