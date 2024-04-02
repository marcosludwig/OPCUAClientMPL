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

#include "ClientApplication.h"
#include "Channel.h"

namespace AnsiCStackQuickstart {

class ClientSession;

class BrowseResult
{
  OpcUa_NodeId m_nodeId;
  OpcUa_NodeClass m_nodeClass;
  std::string m_displayName;

public:
  BrowseResult()
  {
  }

  BrowseResult(const BrowseResult& cbr)
  {
    m_nodeId = cbr.m_nodeId;
    m_displayName = cbr.m_displayName;
    m_nodeClass = cbr.m_nodeClass;
  }
  
  BrowseResult(OpcUa_NodeId nodeId, OpcUa_NodeClass nodeClass, const std::string& displayName)
  {
    m_nodeId = nodeId;
    m_nodeClass = nodeClass;
    m_displayName = displayName;
  }

  ~BrowseResult()
  {
  }

  /*BrowseResult operator= (const BrowseResult& cbr)
  {
    return BrowseResult(cbr.m_nodeId, cbr.m_displayName);
  }*/

  const OpcUa_NodeId& GetNodeId() const
  {
    return m_nodeId;
  }

  const OpcUa_NodeClass& GetNodeClass() const
  {
    return m_nodeClass;
  }

  std::string GetDisplayname() const
  {
    return m_displayName;
  }

};
// A function used to received notifications when an asynchronous read completes.
typedef OpcUa_StatusCode (PfnClientSession_OnReadValue)(  
    ClientSession*   pSession,
  OpcUa_Void*      pCallbackData,
  OpcUa_StatusCode uStatus,
  OpcUa_Variant*   pValue);

// Manages a session with a UA server for a client.
class ClientSession
{
public:

  // Creates a new session for the specified client.
  ClientSession(ClientApplication* pApplication);

  // Releases all resources owned by the object.
  ~ClientSession(void);

  // Creates the session.
  void Create(EndpointDescription endpoint, std::string sessionName);

  // Activates the session.
  void Activate();

  // Closes the session.
  void Close();

  // Begins an asynchronous read the value of the specified Node.
  void BeginReadValue(OpcUa_NodeId nodeId, PfnClientSession_OnReadValue* pCallback, OpcUa_Void* pCallbackData);

  OpcUa_StatusCode ReadValue(OpcUa_NodeId, std::vector<OpcUa_DataValue>&);
  std::vector<BrowseResult> Browse(OpcUa_NodeId& nodeId);

  BOOL IsActive()
  {
    return m_channel.GetHandle() != 0;
  }

private:

  // Deletes the session.
  void Delete();

  ClientApplication* m_pApplication;
  EndpointDescription m_endpoint;
    OpcUa_NodeId m_tSessionId;
    OpcUa_NodeId m_tAuthenticationToken;
    OpcUa_Double m_nSessionTimeout;
    OpcUa_ByteString m_tServerNonce;
    OpcUa_ByteString m_tServerCertificate;
  OpcUa_CryptoProvider m_tCryptoProvider;
  Channel m_channel;
};

} // namespace AnsiCStackQuickstart
