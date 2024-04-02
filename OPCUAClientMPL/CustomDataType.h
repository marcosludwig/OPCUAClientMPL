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

extern "C" 
{

// A simple custom data type.
typedef struct _CustomDataType
{
    OpcUa_Int32 Low;
    OpcUa_Int32 High;
}
CustomDataType;

OpcUa_Void CustomDataType_Initialize(CustomDataType* pValue);

OpcUa_Void CustomDataType_Clear(CustomDataType* pValue);

OpcUa_StatusCode CustomDataType_GetSize(CustomDataType* pValue, struct _OpcUa_Encoder* pEncoder, OpcUa_Int32* pSize);

OpcUa_StatusCode CustomDataType_Encode(CustomDataType* pValue, struct _OpcUa_Encoder* pEncoder);

OpcUa_StatusCode CustomDataType_Decode(CustomDataType* pValue, struct _OpcUa_Decoder* pDecoder);

extern struct _OpcUa_EncodeableType CustomDataType_EncodeableType;

#define NamespaceURI_CustomDataType "urn:MyCustomDataTypes:CustomDataType"
#define OpcUaId_CustomDataType 1234
#define OpcUaId_CustomDataType_DefaultBinary 1235

} // extern "C"
