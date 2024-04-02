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
#include "CustomDataType.h"

#include <opcua_encoder.h>
#include <opcua_decoder.h>

using namespace AnsiCStackQuickstart;

/*============================================================================
 * CustomDataType_Initialize
 *===========================================================================*/
OpcUa_Void CustomDataType_Initialize(CustomDataType* a_pValue)
{
    if (a_pValue != OpcUa_Null)
    {
        OpcUa_Field_Initialize(Int32, Low);
        OpcUa_Field_Initialize(Int32, High);
    }
}

/*============================================================================
 * CustomDataType_Clear
 *===========================================================================*/
OpcUa_Void CustomDataType_Clear(CustomDataType* a_pValue)
{
    if (a_pValue != OpcUa_Null)
    {
        OpcUa_Field_Clear(Int32, Low);
        OpcUa_Field_Clear(Int32, High);
    }
}

/*============================================================================
 * CustomDataType_GetSize
 *===========================================================================*/
OpcUa_StatusCode CustomDataType_GetSize(CustomDataType* a_pValue, OpcUa_Encoder* a_pEncoder, OpcUa_Int32* a_pSize)
{
    OpcUa_Int32 iSize = 0;

    OpcUa_InitializeStatus(OpcUa_Module_Serializer, "CustomDataType_GetSize");

    OpcUa_ReturnErrorIfArgumentNull(a_pValue);
    OpcUa_ReturnErrorIfArgumentNull(a_pEncoder);
    OpcUa_ReturnErrorIfArgumentNull(a_pSize);

    *a_pSize = -1;

    OpcUa_Field_GetSize(Int32, Low);
    OpcUa_Field_GetSize(Int32, High);

    *a_pSize = iSize;

    OpcUa_ReturnStatusCode;
    OpcUa_BeginErrorHandling;

    *a_pSize = -1;

    OpcUa_FinishErrorHandling;
}

/*============================================================================
 * CustomDataType_Encode
 *===========================================================================*/
OpcUa_StatusCode CustomDataType_Encode(CustomDataType* a_pValue, OpcUa_Encoder* a_pEncoder)
{    
    OpcUa_InitializeStatus(OpcUa_Module_Serializer, "CustomDataType_Encode");

    OpcUa_ReturnErrorIfArgumentNull(a_pValue);
    OpcUa_ReturnErrorIfArgumentNull(a_pEncoder);

    OpcUa_Field_Write(Int32, Low);
    OpcUa_Field_Write(Int32, High);

    OpcUa_ReturnStatusCode;
    OpcUa_BeginErrorHandling;

    /* nothing to do */

    OpcUa_FinishErrorHandling;
}

/*============================================================================
 * CustomDataType_Decode
 *===========================================================================*/
OpcUa_StatusCode CustomDataType_Decode(CustomDataType* a_pValue, OpcUa_Decoder* a_pDecoder)
{    
    OpcUa_InitializeStatus(OpcUa_Module_Serializer, "CustomDataType_Decode");

    OpcUa_ReturnErrorIfArgumentNull(a_pValue);
    OpcUa_ReturnErrorIfArgumentNull(a_pDecoder);

    CustomDataType_Initialize(a_pValue);

    OpcUa_Field_Read(Int32, Low);
    OpcUa_Field_Read(Int32, High);

    OpcUa_ReturnStatusCode;
    OpcUa_BeginErrorHandling;

    CustomDataType_Clear(a_pValue);

    OpcUa_FinishErrorHandling;
}

/*============================================================================
 * CustomDataType_EncodeableType
 *===========================================================================*/
struct _OpcUa_EncodeableType CustomDataType_EncodeableType =
{
    "CustomDataType",
    OpcUaId_CustomDataType, 
    OpcUaId_CustomDataType_DefaultBinary,
    0, 
	NamespaceURI_CustomDataType,
    sizeof(CustomDataType),
    (OpcUa_EncodeableObject_PfnInitialize*)CustomDataType_Initialize,
    (OpcUa_EncodeableObject_PfnClear*)CustomDataType_Clear,
    (OpcUa_EncodeableObject_PfnGetSize*)CustomDataType_GetSize,
    (OpcUa_EncodeableObject_PfnEncode*)CustomDataType_Encode,
    (OpcUa_EncodeableObject_PfnDecode*)CustomDataType_Decode
};
