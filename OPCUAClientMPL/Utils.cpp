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
#include "Utils.h"

using namespace AnsiCStackQuickstart;

//============================================================================
// Utils::StrDup(std::string)
//============================================================================
char* Utils::StrDup(std::string src)
{
	char* pDst = 0;

	if (src.empty())
	{
		return pDst;
	}

	pDst = (char*)OpcUa_Alloc(src.length()+1);
	memcpy(pDst, src.c_str(), src.length()+1);
	return pDst;
}

//============================================================================
// Utils::StrDup(OpcUa_ByteString)
//============================================================================
OpcUa_ByteString Utils::StrDup(const OpcUa_ByteString* pSrc)
{
	OpcUa_ByteString tDst;

	if (pSrc == 0)
	{
		OpcUa_ByteString_Initialize(&tDst);
		return tDst;
	}

	tDst.Length = pSrc->Length;
	tDst.Data = (OpcUa_Byte*)OpcUa_Alloc(tDst.Length);
	OpcUa_MemCpy(tDst.Data, tDst.Length, pSrc->Data, pSrc->Length);
	return tDst;
}

//============================================================================
// Utils::Copy(OpcUa_NodeId)
//============================================================================
OpcUa_NodeId Utils::Copy(const OpcUa_NodeId* pSrc)
{
	if (pSrc == 0)
	{
		OpcUa_NodeId null;
		OpcUa_NodeId_Initialize(&null);
		return null;
	}

	OpcUa_NodeId copy = *pSrc;

	// return the numeric value.
	if (pSrc->IdentifierType == OpcUa_IdentifierType_Numeric)
	{
		return copy;
	}

	// copy the string value.
	if (pSrc->IdentifierType == OpcUa_IdentifierType_String)
	{
		OpcUa_String_Initialize(&copy.Identifier.String);
		OpcUa_String_StrnCpy(&copy.Identifier.String, (OpcUa_String*)&pSrc->Identifier.String, OPCUA_STRING_LENDONTCARE);
		return copy;
	}

	// copy the guid value.
	if (pSrc->IdentifierType == OpcUa_IdentifierType_Guid)
	{
		copy.Identifier.Guid = (OpcUa_Guid*)OpcUa_Alloc(sizeof(OpcUa_Guid));
		OpcUa_MemCpy(copy.Identifier.Guid, sizeof(OpcUa_Guid), pSrc->Identifier.Guid, sizeof(OpcUa_Guid));
		return copy;
	}

	// copy the opaque value.
	if (pSrc->IdentifierType == OpcUa_IdentifierType_Opaque)
	{
		OpcUa_ByteString_Initialize(&copy.Identifier.ByteString);
		copy.Identifier.ByteString.Length = pSrc->Identifier.ByteString.Length;
		copy.Identifier.ByteString.Data = (OpcUa_Byte*)OpcUa_Alloc(copy.Identifier.ByteString.Length);
		OpcUa_MemCpy(copy.Identifier.ByteString.Data, copy.Identifier.ByteString.Length, pSrc->Identifier.ByteString.Data, pSrc->Identifier.ByteString.Length);
		return copy;
	}

	// other id types not supported yet.
	return copy;
}

//============================================================================
// Utils::IsEqual
//============================================================================
bool Utils::IsEqual(const OpcUa_NodeId* pOne, const OpcUa_NodeId* pTwo)
{
	if (pOne == pTwo)
	{
		return true;
	}

	if (pOne->IdentifierType != pTwo->IdentifierType)
	{
		return false;
	}
	
	if (pOne->NamespaceIndex != pTwo->NamespaceIndex)
	{
		return false;
	}

	// check the numeric value.
	if (pOne->IdentifierType == OpcUa_IdentifierType_Numeric)
	{
		return pOne->Identifier.Numeric == pTwo->Identifier.Numeric;
	}

	// check the string value.
	if (pOne->IdentifierType == OpcUa_IdentifierType_String)
	{
		return  OpcUa_String_StrnCmp((OpcUa_String*)&pOne->Identifier.String, (OpcUa_String*)&pTwo->Identifier.String, OPCUA_STRING_LENDONTCARE, OpcUa_False) == 0;
	}

	// check the guid value.
	if (pOne->IdentifierType == OpcUa_IdentifierType_Guid)
	{
		return OpcUa_MemCmp(pOne->Identifier.Guid, pTwo->Identifier.Guid, sizeof(OpcUa_Guid)) == 0;
	}

	// check the opaque value.
	if (pOne->IdentifierType == OpcUa_IdentifierType_Opaque)
	{
		if (pOne->Identifier.ByteString.Length != pTwo->Identifier.ByteString.Length)
		{
			return false;
		}

		return OpcUa_MemCmp(pOne->Identifier.ByteString.Data, pTwo->Identifier.ByteString.Data, pOne->Identifier.ByteString.Length) == 0;
	}
		
	return false;
}

//============================================================================
// Utils::Copy
//============================================================================
OpcUa_String Utils::Copy(std::string src)
{
	OpcUa_String sDst;
	OpcUa_String_Initialize(&sDst);

	if (src.empty())
	{
		return sDst;
	}

    OpcUa_StatusCode uStatus = OpcUa_String_AttachToString( 
		(OpcUa_StringA)src.c_str(), 
		OPCUA_STRINGLENZEROTERMINATED, 
		0,
		OpcUa_True, 
		OpcUa_True, 
		&sDst);

	if (OpcUa_IsBad(uStatus))
	{
		OpcUa_String_Initialize(&sDst);
		return sDst;
	}

	return sDst;
}

//============================================================================
// Utils::Copy(std::vector<unsigned char>)
//============================================================================
OpcUa_ByteString Utils::Copy(std::vector<unsigned char> src)
{
	OpcUa_ByteString tDst;
	OpcUa_ByteString_Initialize(&tDst);

	if (src.empty())
	{
		return tDst;
	}

	tDst.Length = src.size();
	tDst.Data = (OpcUa_Byte*)OpcUa_Alloc(tDst.Length);

	if (tDst.Data == 0)
	{
		OpcUa_ByteString_Initialize(&tDst);
		return tDst;
	}

	for (int ii = 0; ii < tDst.Length; ii++)
	{
		tDst.Data[ii] = src[ii];
	}

	return tDst;
}

//============================================================================
// Utils::Copy(OpcUa_String)
//============================================================================
std::string Utils::Copy(const OpcUa_String* pSrc)
{
	std::string dst;

	if (pSrc == 0)
	{
		return dst;
	}

	OpcUa_StringA pData = OpcUa_String_GetRawString((OpcUa_String*)pSrc);
	OpcUa_UInt32 nLength = OpcUa_String_StrLen((OpcUa_String*)pSrc);

	dst.assign(pData, nLength);

	return dst;
}

//============================================================================
// Utils::Copy(OpcUa_ByteString)
//============================================================================
std::vector<unsigned char> Utils::Copy(const OpcUa_ByteString* pSrc)
{
	std::vector<unsigned char> dst;

	if (pSrc == 0 || pSrc->Length <= 0)
	{
		return dst;
	}

	dst.reserve(pSrc->Length);

	for (int ii = 0; ii < pSrc->Length; ii++)
	{
		dst.push_back(pSrc->Data[ii]);
	}

	return dst;
}

//============================================================================
// Utils::StatusToString
//============================================================================
std::string Utils::StatusToString(OpcUa_StatusCode uStatus)
{
	std::string sError;

    switch(uStatus)
    {
		case OpcUa_BadTimeout:
		{
			sError = "OpcUa_BadTimeout";
			break;
		}

		case OpcUa_BadCommunicationError:
		{
			sError = "OpcUa_BadCommunicationError";
			break;
		}

		case OpcUa_BadConnectionClosed:
		{
			sError = "OpcUa_BadConnectionClosed";
			break;
		}

		case OpcUa_BadCertificateInvalid:
		{
			sError = "OpcUa_BadCertificateInvalid";
			break;
		}

		case OpcUa_BadCertificateTimeInvalid:
		{
			sError = "OpcUa_BadCertificateTimeInvalid";
			break;
		}

		case OpcUa_BadCertificateRevoked:
		{
			sError = "OpcUa_BadCertificateRevoked";
			break;
		}

		case OpcUa_BadCertificateUntrusted:
		{
			sError = "OpcUa_BadCertificateUntrusted";
			break;
		}

		case OpcUa_BadCertificateIssuerRevocationUnknown:
		{
			sError = "OpcUa_BadCertificateIssuerRevocationUnknown";
			break;
		}

		case OpcUa_BadConnectionRejected:
		{
			sError = "OpcUa_BadConnectionRejected";
			break;
		}

		default:
		{
			sError = "Unknown Error";
		}
    }

	return sError;
}

//============================================================================
// Utils::VerifySignature
//============================================================================
void Utils::VerifySignature(
	OpcUa_CryptoProvider* pProvider, 
	const OpcUa_ByteString* pReceiverCertificate, 
	const OpcUa_ByteString* pNonce, 
	const OpcUa_ByteString* pSigningCertificate, 
	const OpcUa_SignatureData* pSignature)
{
    OpcUa_StatusCode uStatus = OpcUa_Good;
	OpcUa_Key tKey;
	OpcUa_ByteString tData;
	std::vector<unsigned char> data;

    try
    {
	    OpcUa_Key_Initialize(&tKey);
	    OpcUa_ByteString_Initialize(&tData);

	    // determine the length of the public key.
	    uStatus = OpcUa_Crypto_GetPublicKeyFromCert(
		    pProvider,
		    (OpcUa_ByteString*)pSigningCertificate,
		    0,
		    &tKey);

        ThrowIfBad(uStatus, "Could not get the size of the public key from the certificate.");

	    tKey.Key.Data = (OpcUa_Byte*)OpcUa_Alloc(tKey.Key.Length);
	    OpcUa_MemSet(tKey.Key.Data, 0, tKey.Key.Length);

	    // extract the public key from the certificate.
	    uStatus = OpcUa_Crypto_GetPublicKeyFromCert(
		    pProvider,
		    (OpcUa_ByteString*)pSigningCertificate,
		    0,
		    &tKey);

        ThrowIfBad(uStatus, "Could not get the public key from the certificate.");

	    // append the nonce to the certificate data.
	    data.reserve(pReceiverCertificate->Length + pNonce->Length);

	    for (int ii = 0; ii < pReceiverCertificate->Length; ii++)
	    {
		    data.push_back(pReceiverCertificate->Data[ii]);
	    }
    	
	    for (int ii = 0; ii < pNonce->Length; ii++)
	    {
		    data.push_back(pNonce->Data[ii]);
	    }

	    tData = Utils::Copy(data);

	    // verify signature.
	    uStatus = OpcUa_Crypto_AsymmetricVerify(
		    pProvider,
		    tData,
		    &tKey,
		    (OpcUa_ByteString*)&pSignature->Signature);
    	
        ThrowIfBad(uStatus, "Could not verify digital signature.");

	    OpcUa_Key_Clear(&tKey);
	    OpcUa_ByteString_Clear(&tData);
    }
    catch (...)
    {
	    OpcUa_Key_Clear(&tKey);
	    OpcUa_ByteString_Clear(&tData);
        throw;
    }
}

//============================================================================
// Utils::CreateSignature
//============================================================================
void Utils::CreateSignature(
	OpcUa_CryptoProvider* pProvider, 
	const OpcUa_ByteString* pReceiverCertificate, 
	const OpcUa_ByteString* pNonce, 
	const OpcUa_ByteString* pSigningCertificate, 
	const OpcUa_Key* pSigningPrivateKey, 
	OpcUa_SignatureData* pSignature)
{
    OpcUa_StatusCode uStatus = OpcUa_Good;
	OpcUa_Key tKey;
	OpcUa_ByteString tData;
	std::vector<unsigned char> data;
	OpcUa_UInt32 uKeySize = 0;

    try
    {
	    OpcUa_Key_Initialize(&tKey);
	    OpcUa_ByteString_Initialize(&tData);
	    OpcUa_SignatureData_Initialize(pSignature);

	    // determine the length of the public key.
	    uStatus = OpcUa_Crypto_GetPublicKeyFromCert(
		    pProvider,
		    (OpcUa_ByteString*)pSigningCertificate,
		    0,
		    &tKey);

        ThrowIfBad(uStatus, "Could not get the size of the public key from the certificate.");

	    tKey.Key.Data = (OpcUa_Byte*)OpcUa_Alloc(tKey.Key.Length);
	    OpcUa_MemSet(tKey.Key.Data, 0, tKey.Key.Length);

	    // extract the public key from the certificate.
	    uStatus = OpcUa_Crypto_GetPublicKeyFromCert(
		    pProvider,
		    (OpcUa_ByteString*)pSigningCertificate,
		    0,
		    &tKey);

        ThrowIfBad(uStatus, "Could not get the public key from the certificate.");

	    uStatus = OpcUa_Crypto_GetAsymmetricKeyLength(pProvider, tKey, &uKeySize);
        ThrowIfBad(uStatus, "Could not get length of the key in the certificate.");

	    OpcUa_Key_Clear(&tKey);

	    // append the nonce to the certificate data.
	    data.reserve(pReceiverCertificate->Length + pNonce->Length);

	    for (int ii = 0; ii < pReceiverCertificate->Length; ii++)
	    {
		    data.push_back(pReceiverCertificate->Data[ii]);
	    }
    	
	    for (int ii = 0; ii < pNonce->Length; ii++)
	    {
		    data.push_back(pNonce->Data[ii]);
	    }

	    tData = Utils::Copy(data);

	    // fill in signature information.
	    uStatus = OpcUa_String_AttachToString(
		    OpcUa_AlgorithmUri_Signature_RsaSha1,
		    OPCUA_STRINGLENZEROTERMINATED, 
		    0,
		    OpcUa_False, 
		    OpcUa_False, 
		    &pSignature->Algorithm);

        ThrowIfCallFailed(uStatus, OpcUa_String_AttachToString);

	    // create signature.
	    pSignature->Signature.Length = uKeySize/8;
	    pSignature->Signature.Data = (OpcUa_Byte*)OpcUa_Alloc(pSignature->Signature.Length);
	    OpcUa_MemSet(pSignature->Signature.Data, 0, pSignature->Signature.Length);

	    uStatus = OpcUa_Crypto_AsymmetricSign(
		    pProvider,
		    tData,
		    (OpcUa_Key*)pSigningPrivateKey,
		    &pSignature->Signature);
    	
        ThrowIfBad(uStatus, "Could not create digital signature.");

	    OpcUa_Key_Clear(&tKey);
	    OpcUa_ByteString_Clear(&tData);
    }
    catch (...)
    {
	    OpcUa_Key_Clear(&tKey);
	    OpcUa_ByteString_Clear(&tData);
        throw;
    }
}



//============================================================================
// Utils::Encrypt
//============================================================================
void Utils::Encrypt(
	std::string securityPolicyUri,
	OpcUa_UserNameIdentityToken* pToken, 
	const OpcUa_ByteString* pReceiverCertificate, 
	const OpcUa_StringA pPassword,
	const OpcUa_ByteString* pNonce)
{
    OpcUa_StatusCode uStatus = OpcUa_Good;
	OpcUa_Key tKey;
	OpcUa_ByteString tData;
	std::vector<unsigned char> data;
	OpcUa_UInt32 uKeySize = 0;
	OpcUa_CryptoProvider tCryptoProvider;

    try
    {
	    OpcUa_Key_Initialize(&tKey);
	    OpcUa_ByteString_Initialize(&tData);
		OpcUa_MemSet(&tCryptoProvider, 0, sizeof(OpcUa_CryptoProvider));

	    // create crypto provider.
	    uStatus = OpcUa_CryptoProvider_Create((OpcUa_StringA)securityPolicyUri.c_str(), &tCryptoProvider);
        ThrowIfBad(uStatus,  "Could not create crypto provider.");

	    // determine the length of the public key.
	    uStatus = OpcUa_Crypto_GetPublicKeyFromCert(
		    &tCryptoProvider,
		    (OpcUa_ByteString*)pReceiverCertificate,
		    0,
		    &tKey);

        ThrowIfBad(uStatus, "Could not get the size of the public key from the certificate.");

	    tKey.Key.Data = (OpcUa_Byte*)OpcUa_Alloc(tKey.Key.Length);
	    OpcUa_MemSet(tKey.Key.Data, 0, tKey.Key.Length);

	    // extract the public key from the certificate.
	    uStatus = OpcUa_Crypto_GetPublicKeyFromCert(
		    &tCryptoProvider,
		    (OpcUa_ByteString*)pReceiverCertificate,
		    0,
		    &tKey);

        ThrowIfBad(uStatus, "Could not get the public key from the certificate.");

	    uStatus = OpcUa_Crypto_GetAsymmetricKeyLength(&tCryptoProvider, tKey, &uKeySize);
        ThrowIfBad(uStatus, "Could not get length of the key in the certificate.");

	    // append the nonce to the certificate data.
		int iLength = strlen(pPassword) + pNonce->Length;
	    data.reserve(iLength + 4);
		
	    data.push_back((unsigned char)((iLength & 0x000000FF)));
	    data.push_back((unsigned char)((iLength & 0x0000FF00)>>8));
	    data.push_back((unsigned char)((iLength & 0x00FF0000)>>16));
	    data.push_back((unsigned char)((iLength & 0xFF000000)>>24));

		iLength -= pNonce->Length;

	    for (int ii = 0; ii < iLength; ii++)
	    {
		    data.push_back(pPassword[ii]);
	    }
    	
	    for (int ii = 0; ii < pNonce->Length; ii++)
	    {
		    data.push_back(pNonce->Data[ii]);
	    }

	    tData = Utils::Copy(data);

	    // fill in signature information.
	    uStatus = OpcUa_String_AttachToString(
		    OpcUa_AlgorithmUri_Encryption_Rsa15,
		    OPCUA_STRINGLENZEROTERMINATED, 
		    0,
		    OpcUa_False, 
		    OpcUa_False, 
		    &pToken->EncryptionAlgorithm);

        ThrowIfCallFailed(uStatus, OpcUa_String_AttachToString);

	    // create signature.
	    pToken->Password.Length = uKeySize/8;
	    pToken->Password.Data = (OpcUa_Byte*)OpcUa_Alloc(pToken->Password.Length);
	    OpcUa_MemSet(pToken->Password.Data, 0, pToken->Password.Length);

	    uStatus = OpcUa_Crypto_AsymmetricEncrypt(
		    &tCryptoProvider,
			tData.Data,
			tData.Length,
			&tKey,
			pToken->Password.Data,
			(OpcUa_UInt32*)&pToken->Password.Length);
    	
        ThrowIfBad(uStatus, "Could not encrypt password");

	    OpcUa_Key_Clear(&tKey);
	    OpcUa_ByteString_Clear(&tData);
		OpcUa_CryptoProvider_Delete(&tCryptoProvider);
    }
    catch (...)
    {
	    OpcUa_Key_Clear(&tKey);
	    OpcUa_ByteString_Clear(&tData);
	    OpcUa_ByteString_Clear(&pToken->Password);

		if (tCryptoProvider.Handle != 0)
		{
			OpcUa_CryptoProvider_Delete(&tCryptoProvider);
		}

        throw;
    }
}
