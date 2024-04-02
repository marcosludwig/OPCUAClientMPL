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
#include "ClientSession.h"
#include "Utils.h"

using namespace AnsiCStackQuickstart;

ClientSession::ClientSession(ClientApplication* pApplication) : m_channel(pApplication)
{
	m_pApplication = pApplication;
	m_nSessionTimeout = 0;
	
	OpcUa_NodeId_Initialize(&m_tSessionId);
	OpcUa_NodeId_Initialize(&m_tAuthenticationToken);
	OpcUa_ByteString_Initialize(&m_tServerNonce);
	OpcUa_ByteString_Initialize(&m_tServerCertificate);
	OpcUa_MemSet(&m_tCryptoProvider, 0, sizeof(OpcUa_CryptoProvider));
}

ClientSession::~ClientSession(void)
{
	Delete();
}

void ClientSession::Delete()
{
	m_channel.Disconnect();

	OpcUa_NodeId_Clear(&m_tSessionId);
	OpcUa_NodeId_Clear(&m_tAuthenticationToken);
	OpcUa_ByteString_Clear(&m_tServerNonce);
	OpcUa_ByteString_Clear(&m_tServerCertificate);

	if (m_tCryptoProvider.Handle != 0)
	{
		OpcUa_CryptoProvider_Delete(&m_tCryptoProvider);
	}
}

void ClientSession::Create(EndpointDescription endpoint, std::string ClientSessionName)
{
	StatusCodeException e;

    OpcUa_RequestHeader                tRequestHeader;
    OpcUa_ApplicationDescription       tClientDescription;
    OpcUa_String                       sServerUri;
    OpcUa_String                       sEndpointUrl;
    OpcUa_String                       sClientSessionName;
    OpcUa_Key				           tClientNonce;
    OpcUa_Double                       nRequestedClientSessionTimeout = 0;
    OpcUa_UInt32                       nMaxResponseMessageSize = 0;
    OpcUa_ResponseHeader               tResponseHeader;
    OpcUa_NodeId                       tClientSessionId;
    OpcUa_NodeId                       tAuthenticationToken;
    OpcUa_Double                       nRevisedSessionTimeout;
    OpcUa_ByteString                   tServerNonce;
    OpcUa_ByteString                   tServerCertificate;
    OpcUa_Int32                        nNoOfServerEndpoints = 0;
    OpcUa_EndpointDescription*         pServerEndpoints = 0;
    OpcUa_Int32                        nNoOfServerSoftwareCertificates = 0;
    OpcUa_SignedSoftwareCertificate*   pServerSoftwareCertificates = 0;
    OpcUa_SignatureData                tServerSignature;
    OpcUa_UInt32                       nMaxRequestMessageSize = 0;

OpcUa_InitializeStatus(OpcUa_Module_Client, "ClientSession::Create");

    OpcUa_RequestHeader_Initialize(&tRequestHeader);
    OpcUa_ApplicationDescription_Initialize(&tClientDescription);
    OpcUa_String_Initialize(&sServerUri);
    OpcUa_String_Initialize(&sEndpointUrl);
    OpcUa_String_Initialize(&sClientSessionName);
    OpcUa_Key_Initialize(&tClientNonce);
    OpcUa_ResponseHeader_Initialize(&tResponseHeader);
    OpcUa_NodeId_Initialize(&tClientSessionId);
    OpcUa_NodeId_Initialize(&tAuthenticationToken);
    OpcUa_ByteString_Initialize(&tServerNonce);
    OpcUa_ByteString_Initialize(&tServerCertificate);
    OpcUa_SignatureData_Initialize(&tServerSignature);

	// connect to the server.
	m_channel.Connect(endpoint);

	// fill in request header.
	tRequestHeader.TimeoutHint = UTILS_DEFAULT_TIMEOUT;
	tRequestHeader.Timestamp   = OpcUa_DateTime_UtcNow();

	// fill in application description.
	tClientDescription.ApplicationName.Text = Utils::Copy(m_pApplication->GetApplicationName());
	tClientDescription.ApplicationType      = OpcUa_ApplicationType_Client;
	tClientDescription.ApplicationUri       = Utils::Copy(m_pApplication->GetApplicationUri());

	sServerUri = Utils::Copy(endpoint.GetServerUri());
	sEndpointUrl = Utils::Copy(endpoint.GetEndpointUrl());
	sClientSessionName = Utils::Copy(ClientSessionName);

	if (endpoint.GetSecurityMode() != OpcUa_MessageSecurityMode_None)
	{
		// create crypto provider.
		uStatus = OpcUa_CryptoProvider_Create((OpcUa_StringA)endpoint.GetSecurityPolicyUri().c_str(), &m_tCryptoProvider);

		if (OpcUa_IsBad(uStatus))
		{
			e = StatusCodeException(uStatus, "Could not create crypto provider.");
			OpcUa_GotoError;
		}

		// generate a nonce.
		tClientNonce.Key.Length = 32;
		tClientNonce.Key.Data = (OpcUa_Byte*)OpcUa_Alloc(tClientNonce.Key.Length);

		uStatus = OpcUa_Crypto_GenerateKey(&m_tCryptoProvider, tClientNonce.Key.Length, &tClientNonce);

		if (OpcUa_IsBad(uStatus))
		{
			e = StatusCodeException(uStatus, "Could not create client nonce.");
			OpcUa_GotoError;
		}
	}

	// request a 10 minute timeout.
	nRequestedClientSessionTimeout = 600000;

	// create the ClientSession.
	uStatus = OpcUa_ClientApi_CreateSession(  
		m_channel.GetHandle(), 
		&tRequestHeader,
		&tClientDescription,
		&sServerUri,
		&sEndpointUrl, 
		&sClientSessionName,
		&tClientNonce.Key, 
		m_pApplication->GetCertificate(),
		nRequestedClientSessionTimeout,
		nMaxResponseMessageSize,
		&tResponseHeader,
		&tClientSessionId,
		&tAuthenticationToken,
		&nRevisedSessionTimeout,
		&tServerNonce,
		&tServerCertificate,
		&nNoOfServerEndpoints,
		&pServerEndpoints,
		&nNoOfServerSoftwareCertificates,
		&pServerSoftwareCertificates,
		&tServerSignature,
		&nMaxRequestMessageSize);

	if (OpcUa_IsBad(uStatus) || OpcUa_IsBad(tResponseHeader.ServiceResult))
    {
		e = StatusCodeException(uStatus, "Could not create a new session.");
		OpcUa_GotoError;
    }

	// verify server signature.
	if (endpoint.GetSecurityMode() != OpcUa_MessageSecurityMode_None)
	{	
		std::vector<unsigned char> expectedBytes = endpoint.GetServerCertificate();

		bool match = (int)expectedBytes.size() == tServerCertificate.Length;

		if (match)
		{
			for (int ii = 0; ii < (int)expectedBytes.size(); ii++)
			{
				if (tServerCertificate.Data[ii] != expectedBytes[ii])
				{
					match = false;
					break;
				}
			}
		}

		if (!match)
		{
			e = StatusCodeException(uStatus, "Server returned a certificate does not match the expected certificate.");
			OpcUa_GotoError;
		}

        try
        {
		    Utils::VerifySignature(&m_tCryptoProvider, m_pApplication->GetCertificate(), &tClientNonce.Key, &tServerCertificate, &tServerSignature);
        }
		catch (...)
		{
			e = StatusCodeException(uStatus, "Could not verify signature provided by server.");
			OpcUa_GotoErrorIfBad(uStatus);
		}
	}
	
	// save session information.
	m_tSessionId = tClientSessionId;
	m_tAuthenticationToken = tAuthenticationToken;
	m_nSessionTimeout = nRevisedSessionTimeout;
	m_tServerCertificate = tServerCertificate;
	m_tServerNonce = tServerNonce;
    m_endpoint = endpoint;

	// clean up.
    OpcUa_RequestHeader_Clear(&tRequestHeader);
    OpcUa_ApplicationDescription_Clear(&tClientDescription);
    OpcUa_String_Clear(&sServerUri);
    OpcUa_String_Clear(&sEndpointUrl);
    OpcUa_String_Clear(&sClientSessionName);
    OpcUa_Key_Clear(&tClientNonce);
    OpcUa_ResponseHeader_Clear(&tResponseHeader);

	Utils_ClearArray(pServerEndpoints, nNoOfServerEndpoints, OpcUa_EndpointDescription);
	Utils_ClearArray(pServerSoftwareCertificates, nNoOfServerSoftwareCertificates, OpcUa_SignedSoftwareCertificate);

	return;

OpcUa_BeginErrorHandling;

	// delete the ClientSession.
	Delete();

	// clean up.
    OpcUa_RequestHeader_Clear(&tRequestHeader);
    OpcUa_ApplicationDescription_Clear(&tClientDescription);
    OpcUa_String_Clear(&sServerUri);
    OpcUa_String_Clear(&sEndpointUrl);
    OpcUa_String_Clear(&sClientSessionName);
    OpcUa_Key_Clear(&tClientNonce);
    OpcUa_ResponseHeader_Clear(&tResponseHeader);
    OpcUa_NodeId_Clear(&tClientSessionId);
    OpcUa_NodeId_Clear(&tAuthenticationToken);
    OpcUa_ByteString_Clear(&tServerNonce);
    OpcUa_ByteString_Clear(&tServerCertificate);
    OpcUa_SignatureData_Clear(&tServerSignature);

	Utils_ClearArray(pServerEndpoints, nNoOfServerEndpoints, OpcUa_EndpointDescription);
	Utils_ClearArray(pServerSoftwareCertificates, nNoOfServerSoftwareCertificates, OpcUa_SignedSoftwareCertificate);

	if (e.GetCode() != (int)uStatus)
	{
		e = StatusCodeException(uStatus, "Could create a new session with the server.");
	}

	throw e;
}

void ClientSession::Activate()
{
	StatusCodeException e;

    OpcUa_RequestHeader                tRequestHeader;
    OpcUa_SignatureData                tClientSignature;
    OpcUa_Int32                        nNoOfClientSoftwareCertificates = 0;
    OpcUa_SignedSoftwareCertificate    tClientSoftwareCertificates;
    OpcUa_Int32                        nNoOfLocaleIds = 0;
    OpcUa_String                       sLocaleIds;
    OpcUa_ExtensionObject              tUserIdentityToken;
    OpcUa_SignatureData                tUserTokenSignature;
    OpcUa_ResponseHeader               tResponseHeader;
    OpcUa_ByteString                   tServerNonce;
    OpcUa_Int32                        nNoOfResults = 0;
    OpcUa_StatusCode*                  pResults = 0;
    OpcUa_Int32                        nNoOfDiagnosticInfos = 0;
    OpcUa_DiagnosticInfo*              pDiagnosticInfos = 0;
	OpcUa_UserNameIdentityToken*       pToken = OpcUa_Null;

OpcUa_InitializeStatus(OpcUa_Module_Client, "ClientSession::Activate");

    OpcUa_RequestHeader_Initialize(&tRequestHeader);
    OpcUa_SignatureData_Initialize(&tClientSignature);
    OpcUa_SignedSoftwareCertificate_Initialize(&tClientSoftwareCertificates);
    OpcUa_String_Initialize(&sLocaleIds);
    OpcUa_ExtensionObject_Initialize(&tUserIdentityToken);
    OpcUa_SignatureData_Initialize(&tUserTokenSignature);
    OpcUa_ResponseHeader_Initialize(&tResponseHeader);
    OpcUa_ByteString_Initialize(&tServerNonce);

	// fill in request header.
	tRequestHeader.TimeoutHint         = UTILS_DEFAULT_TIMEOUT;
	tRequestHeader.Timestamp           = OpcUa_DateTime_UtcNow();
	tRequestHeader.AuthenticationToken = Utils::Copy(&m_tAuthenticationToken);

	if (m_endpoint.GetSecurityMode() != OpcUa_MessageSecurityMode_None)
	{
        try
        {
		    Utils::CreateSignature(
			    &m_tCryptoProvider, 
			    &m_tServerCertificate, 
			    &m_tServerNonce,
			    m_pApplication->GetCertificate(), 
			    m_pApplication->GetPrivateKey(), 
			    &tClientSignature);
        }
        catch (...)
		{
			e = StatusCodeException(uStatus, "Could not create client signature.");
			OpcUa_GotoError;
		}

    (void)pToken; // To avoid not used warnings.
    // by MPL
    // COMENTADO POIS ENTRARÁ SEMPRE COMO USUÁRIO ANÔNIMO!
    // by MPL

		// check if a user name policy is specified.
		/*UserTokenPolicy* pPolicy = 0;
		std::vector<UserTokenPolicy> policies = m_endpoint.GetUserTokenPolicies();

		for (unsigned int ii = 0; policies.size(); ii++)
		{
			if (policies[ii].GetTokenType() == OpcUa_UserTokenType_UserName)
			{
				pPolicy = &policies[ii];
				break;
			}
		}

		// set the username/password.
		if (pPolicy != 0)
		{
			// allocate the token.
			pToken = (OpcUa_UserNameIdentityToken*)OpcUa_Alloc(sizeof(OpcUa_UserNameIdentityToken));

			if (pToken == 0)
			{
				e = StatusCodeException(OpcUa_BadOutOfMemory, "OpcUa_BadOutOfMemory");
				OpcUa_GotoError;
			}

			try
			{
				OpcUa_UserNameIdentityToken_Initialize(pToken);

				// set the policy id provided by the server.
				pToken->PolicyId = Utils::Copy(pPolicy->GetPolicyId());

				// set a dummy user name.
				pToken->UserName = Utils::Copy("user1");

				// must encrypt the password if required by the server.
				Utils::Encrypt(
					pPolicy->GetSecurityPolicyUri(), 
					pToken,
					&m_tServerCertificate,
					(OpcUa_StringA)"user1",
					&m_tServerNonce);

				// the UserIndentityToken is an extension object which supports many types of tokens.

				// the type of the Token is specified by the TypeId.
				tUserIdentityToken.TypeId.NodeId.Identifier.Numeric = OpcUaId_UserNameIdentityToken;
				tUserIdentityToken.TypeId.NodeId.IdentifierType = OpcUa_IdentifierType_Numeric;

				// The encoding specifies a pointer to the object.
				tUserIdentityToken.Encoding = OpcUa_ExtensionObjectEncoding_EncodeableObject;

				// This is a table of functions for handling the type.
				tUserIdentityToken.Body.EncodeableObject.Type = &OpcUa_UserNameIdentityToken_EncodeableType;

				// Save the token itself (freed when OpcUa_ExtensionObject_Clear is called).
				tUserIdentityToken.Body.EncodeableObject.Object = pToken;
				pToken = 0;
			}
			catch (...)
			{
				if (pToken != 0)
				{
					OpcUa_UserNameIdentityToken_Clear(pToken);
					OpcUa_Free(pToken);
					pToken = 0;
				}

				e = StatusCodeException(uStatus, "Could not create user identity token.");
				OpcUa_GotoError;
			}
		}*/
	}

	// create the ClientSession.
	uStatus = OpcUa_ClientApi_ActivateSession(
		m_channel.GetHandle(), 
		&tRequestHeader,
		&tClientSignature,
		nNoOfClientSoftwareCertificates,
		&tClientSoftwareCertificates,
		nNoOfLocaleIds,
		&sLocaleIds,
		&tUserIdentityToken,
		&tUserTokenSignature,
		&tResponseHeader,
		&tServerNonce,
		&nNoOfResults,
		&pResults,
		&nNoOfDiagnosticInfos,
		&pDiagnosticInfos);

	if (OpcUa_IsBad(uStatus) || OpcUa_IsBad(tResponseHeader.ServiceResult))
  {
    e = StatusCodeException(uStatus, "Could not activate session.");
    OpcUa_GotoError;
  }
	
	// save ClientSession information.
	m_tServerNonce = tServerNonce;

	// clean up.
    OpcUa_RequestHeader_Clear(&tRequestHeader);
    OpcUa_SignatureData_Clear(&tClientSignature);
    OpcUa_SignedSoftwareCertificate_Clear(&tClientSoftwareCertificates);
    OpcUa_String_Clear(&sLocaleIds);
    OpcUa_ExtensionObject_Clear(&tUserIdentityToken);
    OpcUa_SignatureData_Clear(&tUserTokenSignature);
    OpcUa_ResponseHeader_Clear(&tResponseHeader);

	Utils_ClearArray(pResults, nNoOfResults, OpcUa_StatusCode);
	Utils_ClearArray(pDiagnosticInfos, nNoOfDiagnosticInfos, OpcUa_DiagnosticInfo);

	return;

OpcUa_BeginErrorHandling;

	// clean up.
    OpcUa_RequestHeader_Clear(&tRequestHeader);
    OpcUa_SignatureData_Clear(&tClientSignature);
    OpcUa_SignedSoftwareCertificate_Clear(&tClientSoftwareCertificates);
    OpcUa_String_Clear(&sLocaleIds);
    OpcUa_ExtensionObject_Clear(&tUserIdentityToken);


    OpcUa_SignatureData_Clear(&tUserTokenSignature);
    OpcUa_ResponseHeader_Clear(&tResponseHeader);
    OpcUa_ByteString_Clear(&tServerNonce);

	Utils_ClearArray(pResults, nNoOfResults, OpcUa_StatusCode);
	Utils_ClearArray(pDiagnosticInfos, nNoOfDiagnosticInfos, OpcUa_DiagnosticInfo);

	if (e.GetCode() != (int)uStatus)
	{
		e = StatusCodeException(uStatus, "Could create a activate session with the server.");
	}

	throw e;
}

void ClientSession::Close()
{
    OpcUa_RequestHeader  tRequestHeader;
    OpcUa_ResponseHeader tResponseHeader;

OpcUa_InitializeStatus(OpcUa_Module_Client, "ClientSession::Close");

    OpcUa_RequestHeader_Initialize(&tRequestHeader);
    OpcUa_ResponseHeader_Initialize(&tResponseHeader);

	// fill in request header.
	tRequestHeader.TimeoutHint         = UTILS_DEFAULT_TIMEOUT;
	tRequestHeader.Timestamp           = OpcUa_DateTime_UtcNow();
	tRequestHeader.AuthenticationToken = Utils::Copy(&m_tAuthenticationToken);

	// close the ClientSession.
	uStatus = OpcUa_ClientApi_CloseSession(
		m_channel.GetHandle(), 
		&tRequestHeader,
		OpcUa_False,
		&tResponseHeader);

    OpcUa_GotoErrorIfBad(uStatus);
	
	// clean up.
    OpcUa_RequestHeader_Clear(&tRequestHeader);
    OpcUa_ResponseHeader_Clear(&tResponseHeader);

	Delete();
	return;

OpcUa_BeginErrorHandling;

	// clean up.
    OpcUa_RequestHeader_Clear(&tRequestHeader);
    OpcUa_ResponseHeader_Clear(&tResponseHeader);

	throw StatusCodeException(uStatus, "Could not close the session.");
}


struct ReadAsyncCallbackData
{
	ClientSession* pClientSession;
	PfnClientSession_OnReadValue* pCallback;
	OpcUa_Void* pCallbackData;
};

static OpcUa_StatusCode ReadAsyncCallback(
	OpcUa_Channel           a_hChannel,
	OpcUa_Void*             a_pResponse,
	OpcUa_EncodeableType*   a_pResponseType,
	OpcUa_Void*             a_pCallbackData,
	OpcUa_StatusCode        a_uStatus)
{
    OpcUa_ReadResponse* pResponse = (OpcUa_ReadResponse*)a_pResponse;
    ReadAsyncCallbackData* pData = (ReadAsyncCallbackData*)a_pCallbackData;

OpcUa_InitializeStatus(OpcUa_Module_Client, "ReadAsyncCallback");

    OpcUa_ReferenceParameter(a_hChannel);

    if (OpcUa_IsBad(a_uStatus))
    {
        uStatus = a_uStatus;
        OpcUa_GotoError;
    }

	if (OpcUa_IsBad(pResponse->ResponseHeader.ServiceResult))
	{
        uStatus = pResponse->ResponseHeader.ServiceResult;
        OpcUa_GotoError;
	}
	
	if (pResponse->NoOfResults != 1)
	{
        uStatus = OpcUa_BadUnknownResponse;
        OpcUa_GotoError;
	}

	if (OpcUa_IsBad(pResponse->Results[0].StatusCode))
	{
        uStatus = pResponse->Results[0].StatusCode;
        OpcUa_GotoError;
	}

	if (pData != 0)
	{
		pData->pCallback(
			pData->pClientSession,
			pData->pCallbackData,
			OpcUa_Good,
			&pResponse->Results[0].Value);

		delete pData;
	}

    OpcUa_EncodeableObject_Delete(a_pResponseType, &a_pResponse);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

	if (pData != 0)
	{
		pData->pCallback(
			pData->pClientSession,
			pData->pCallbackData,
			uStatus,
			0);

		delete pData;
	}

    OpcUa_EncodeableObject_Delete(a_pResponseType, &a_pResponse);

OpcUa_FinishErrorHandling;
}

void ClientSession::BeginReadValue(OpcUa_NodeId nodeId, PfnClientSession_OnReadValue* pCallback, OpcUa_Void* pCallbackData)
{
    OpcUa_RequestHeader tRequestHeader;
    OpcUa_ReadValueId   tNodesToRead;

OpcUa_InitializeStatus(OpcUa_Module_Client, "ClientSession::ReadValue");

    OpcUa_RequestHeader_Initialize(&tRequestHeader);
    OpcUa_ReadValueId_Initialize(&tNodesToRead);

	// select attribute.
	tNodesToRead.NodeId = nodeId;
	tNodesToRead.AttributeId = OpcUa_Attributes_Value;

	// fill in request header.
	tRequestHeader.TimeoutHint         = UTILS_DEFAULT_TIMEOUT;
	tRequestHeader.Timestamp           = OpcUa_DateTime_UtcNow();
	tRequestHeader.AuthenticationToken = Utils::Copy(&m_tAuthenticationToken);

	ReadAsyncCallbackData* pData = new ReadAsyncCallbackData();

	pData->pClientSession = this;
	pData->pCallback = pCallback;
	pData->pCallbackData = pCallbackData;

	// create the ClientSession.
	uStatus = OpcUa_ClientApi_BeginRead(
		m_channel.GetHandle(), 
		&tRequestHeader,
		0,
		OpcUa_TimestampsToReturn_Both,
		1,
		&tNodesToRead,
		ReadAsyncCallback,
		pData);

    OpcUa_GotoErrorIfBad(uStatus);
	
	// clean up.
    OpcUa_RequestHeader_Clear(&tRequestHeader);
    OpcUa_ReadValueId_Clear(&tNodesToRead);

	return;

OpcUa_BeginErrorHandling;

	// clean up.
    OpcUa_RequestHeader_Clear(&tRequestHeader);
    OpcUa_ReadValueId_Clear(&tNodesToRead);

	throw StatusCodeException(uStatus, "Could read value from server.");
}

OpcUa_StatusCode ClientSession::ReadValue(OpcUa_NodeId nodeId, std::vector<OpcUa_DataValue>& rvValues)
{
  ASSERT(rvValues.empty());

  OpcUa_RequestHeader tRequestHeader;
  OpcUa_RequestHeader_Initialize(&tRequestHeader);
	// fill in request header.
	tRequestHeader.TimeoutHint         = UTILS_DEFAULT_TIMEOUT;
	tRequestHeader.Timestamp           = OpcUa_DateTime_UtcNow();
	tRequestHeader.AuthenticationToken = Utils::Copy(&m_tAuthenticationToken);
  
  // select attribute.
  OpcUa_ReadValueId tNodesToRead;
  OpcUa_ReadValueId_Initialize(&tNodesToRead);
	tNodesToRead.NodeId = nodeId;
	tNodesToRead.AttributeId = OpcUa_Attributes_Value;

  OpcUa_Double nMaxAge = 0;
  OpcUa_Int32 nNodesToRead = 1;

	// create the ClientSession.
  OpcUa_ReadResponse tReadResponse;
  OpcUa_ReadResponse_Initialize(&tReadResponse);

  OpcUa_InitializeStatus(OpcUa_Module_Client, "ClientSession::ReadValue");

  uStatus = OpcUa_ClientApi_Read(
		m_channel.GetHandle(), 
		&tRequestHeader,
    nMaxAge,
    OpcUa_TimestampsToReturn_Both,
    nNodesToRead,
    &tNodesToRead,
    &tReadResponse.ResponseHeader,
    &tReadResponse.NoOfResults,
    &tReadResponse.Results,
    &tReadResponse.NoOfDiagnosticInfos,
    &tReadResponse.DiagnosticInfos);

  if (OpcUa_IsBad(uStatus)) 
  { 
    OpcUa_GotoError; 
  } 

  if (OpcUa_IsBad(tReadResponse.ResponseHeader.ServiceResult)) 
  { 
    uStatus = tReadResponse.ResponseHeader.ServiceResult; 
    OpcUa_GotoError; 
  } 
    
  if (tReadResponse.NoOfResults != nNodesToRead) 
  { 
    uStatus = OpcUa_BadUnknownResponse; 
    OpcUa_GotoError; 
  } 

  for (size_t n = 0; n < (size_t)tReadResponse.NoOfResults; n++)
    rvValues.push_back(tReadResponse.Results[n]);

  // clean up.
//  OpcUa_ReadValueId_Clear(&tNodesToRead);
  OpcUa_RequestHeader_Clear(&tRequestHeader);
  //OpcUa_ReadResponse_Clear(&tReadResponse);

	return uStatus;

OpcUa_BeginErrorHandling;

	// clean up.
//  OpcUa_ReadValueId_Clear(&tNodesToRead);
  OpcUa_RequestHeader_Clear(&tRequestHeader);
  //OpcUa_ReadResponse_Clear(&tReadResponse);

	throw StatusCodeException(uStatus, "Could not read value from server.");
}

std::vector<BrowseResult> ClientSession::Browse(OpcUa_NodeId& nodeId)
{
  std::vector<BrowseResult> ret;

  OpcUa_RequestHeader tRequestHeader;
  OpcUa_RequestHeader_Initialize(&tRequestHeader);
  // fill in request header.
  tRequestHeader.TimeoutHint         = UTILS_DEFAULT_TIMEOUT;
  tRequestHeader.Timestamp           = OpcUa_DateTime_UtcNow();
  tRequestHeader.AuthenticationToken = Utils::Copy(&m_tAuthenticationToken);

  OpcUa_ViewDescription viewDescription;
  OpcUa_ViewDescription_Initialize(&viewDescription);

  OpcUa_BrowseDescription browseDescription;
  OpcUa_BrowseDescription_Initialize(&browseDescription);
  browseDescription.BrowseDirection = OpcUa_BrowseDirection_Forward;
  browseDescription.IncludeSubtypes = OpcUa_True;
  browseDescription.NodeClassMask = OpcUa_NodeClass_Object | OpcUa_NodeClass_Variable;
  browseDescription.NodeId = nodeId;

  OpcUa_NodeId referenceId;
  referenceId.IdentifierType = OpcUa_IdentifierType_Numeric;
  referenceId.Identifier.Numeric = OpcUaId_HierarchicalReferences;
  referenceId.NamespaceIndex = 0;
  
  browseDescription.ReferenceTypeId = referenceId;
  browseDescription.ResultMask = OpcUa_BrowseResultMask_DisplayName | OpcUa_BrowseResultMask_NodeClass;

  OpcUa_ResponseHeader              tResponseHeader;
  OpcUa_ResponseHeader_Initialize(&tResponseHeader);

  OpcUa_Int32 numberOfResults;
  OpcUa_BrowseResult* pResults = nullptr;
  OpcUa_Int32 numberOfDiagInfos;

  OpcUa_DiagnosticInfo* pDiagInfos = nullptr;

  OpcUa_InitializeStatus(OpcUa_Module_Client, "ClientSession::Browse");

  uStatus = OpcUa_ClientApi_Browse(m_channel.GetHandle(),
                                   &tRequestHeader,
                                   &viewDescription,
                                   0,
                                   1,
                                   &browseDescription,
                                   &tResponseHeader,
                                   &numberOfResults,
                                   &pResults,
                                   &numberOfDiagInfos,
                                   &pDiagInfos);

  if (OpcUa_IsBad(uStatus)) 
  { 
    OpcUa_GotoError; 
  } 

  if (OpcUa_IsBad(tResponseHeader.ServiceResult)) 
  { 
    uStatus = tResponseHeader.ServiceResult; 
    OpcUa_GotoError; 
  } 
    
  if (numberOfResults != 1) 
  { 
    uStatus = OpcUa_BadUnknownResponse; 
    OpcUa_GotoError; 
  } 

  int numberOfReferences = pResults[0].NoOfReferences;
  for (int i = 0; i < numberOfReferences; i++)
  {
    std::string displayName(Utils::Copy(&pResults[0].References[i].DisplayName.Text));
    
    ret.push_back(BrowseResult(Utils::Copy(&pResults[0].References[i].NodeId.NodeId),
                  pResults[0].References[i].NodeClass,
                  displayName));
  }

	// clean up.
  OpcUa_RequestHeader_Clear(&tRequestHeader);
  OpcUa_ViewDescription_Clear(&viewDescription);
  //OpcUa_BrowseDescription_Clear(&browseDescription);
  OpcUa_ResponseHeader_Clear(&tResponseHeader);
  
  return ret;
	
OpcUa_BeginErrorHandling;
  // clean up.
  OpcUa_RequestHeader_Clear(&tRequestHeader);
  OpcUa_ViewDescription_Clear(&viewDescription);
  OpcUa_BrowseDescription_Clear(&browseDescription);
  OpcUa_ResponseHeader_Clear(&tResponseHeader);

	throw StatusCodeException(uStatus, "Could read value from server.");
}
