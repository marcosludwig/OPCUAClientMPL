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

#include "StatusCodeException.h"

namespace AnsiCStackQuickstart {

// Defines utility functions. 
class Utils
{
public:
	Utils(void);
	~Utils(void);

	// Converts a std::string to OpcUa_StringA. Returned value must freed with OpcUa_Free.
	static OpcUa_StringA StrDup(std::string src);

	// Duplicates a OpcUa_ByteString.
	static OpcUa_ByteString StrDup(const OpcUa_ByteString* pSrc);

	// Copies a NodeId
	static OpcUa_NodeId Copy(const OpcUa_NodeId* pSrc);

	//  Compares two NodeIds.
	static bool IsEqual(const OpcUa_NodeId* pOne, const OpcUa_NodeId* pTwo);

	// Converts a std::string to OpcUa_String. Returned value must freed with OpcUa_String_Clear.
	static OpcUa_String Copy(std::string src);

	// Converts a std::vector to OpcUa_ByteString. Returned value must freed with OpcUa_ByteString_Clear.
	static OpcUa_ByteString Copy(std::vector<unsigned char> src);

	// Converts a OpcUa_String to a std::string.
	static std::string Copy(const OpcUa_String* pSrc);

	// Converts a OpcUa_ByteString to a std::vector.
	static std::vector<unsigned char> Copy(const OpcUa_ByteString* pSrc);
	
	// Converts a OpcUa_StatusCode to a std::string.
	static std::string StatusToString(OpcUa_StatusCode uStatus);
	
	// Appends the pNonce to the pReceiverCertificate and calculates the signature with the pSigningCertificate.
	static void CreateSignature(
		OpcUa_CryptoProvider* pProvider, 
		const OpcUa_ByteString* pReceiverCertificate, 
		const OpcUa_ByteString* pNonce,
		const OpcUa_ByteString* pSigningCertificate, 
		const OpcUa_Key* pSigningPrivateKey, 
		OpcUa_SignatureData* pSignature);

	// Appends the pNonce to the pReceiverCertificate and verifies the signature with the pSigningCertificate.
	static void VerifySignature(
		OpcUa_CryptoProvider* pProvider, 
		const OpcUa_ByteString* pReceiverCertificate, 
		const OpcUa_ByteString* pNonce, 
		const OpcUa_ByteString* pSigningCertificate, 
		const OpcUa_SignatureData* pSignature);

	// Encrypts the password.
	static void Encrypt(
		std::string securityPolicyUri,
		OpcUa_UserNameIdentityToken* pToken, 
		const OpcUa_ByteString* pReceiverCertificate, 
		const OpcUa_StringA pPassword,
		const OpcUa_ByteString* pNonce);
};

// Clears an array of any type with xType_Clear function defined.
#define Utils_ClearArray(xArray,xCount,xType) \
if (xArray != OpcUa_Null) \
{ \
	for (OpcUa_Int32 ii = 0; ii < xCount; ii++) \
	{ \
		xType##_Clear(&(xArray[ii])); \
	} \
 \
	OpcUa_Free(xArray); \
	xArray = 0; \
}

//#define UTILS_DEFAULT_TIMEOUT 300000
#define UTILS_DEFAULT_TIMEOUT 10000

} // namespace AnsiCStackQuickstart
