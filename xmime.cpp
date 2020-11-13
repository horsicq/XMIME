// Copyright (c) 2020 hors<horsicq@gmail.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//
#include "xmime.h"

XMIME::XMIME(QObject *pParent) : QObject(pParent)
{

}

QList<QString> XMIME::getTypes(QIODevice *pDevice)
{
    QList<QString> listResult;

    SpecAbstract::SCAN_OPTIONS options={};
    SpecAbstract::SCAN_RESULT scanResult=StaticScan::processDevice(pDevice,&options);

    if( SpecAbstract::isScanStructPresent(&scanResult.listRecords,XBinary::FT_PE32)||
        SpecAbstract::isScanStructPresent(&scanResult.listRecords,XBinary::FT_PE64))
    {
        listResult.append("application/vnd.microsoft.portable-executable");
        listResult.append("application/x-dosexec");
    }

    if(SpecAbstract::isScanStructPresent(&scanResult.listRecords,XBinary::FT_UNKNOWN,SpecAbstract::RECORD_TYPE_SOURCECODE,SpecAbstract::RECORD_NAME_PYTHON))
    {
        listResult.append("text/x-python");
    }

    if( SpecAbstract::isScanStructPresent(&scanResult.listRecords,XBinary::FT_UNKNOWN,SpecAbstract::RECORD_TYPE_SOURCECODE,SpecAbstract::RECORD_NAME_C)||
        SpecAbstract::isScanStructPresent(&scanResult.listRecords,XBinary::FT_UNKNOWN,SpecAbstract::RECORD_TYPE_SOURCECODE,SpecAbstract::RECORD_NAME_CCPP))
    {
        listResult.append("text/x-c");
    }

    if( SpecAbstract::isScanStructPresent(&scanResult.listRecords,XBinary::FT_TEXT)||
        SpecAbstract::isScanStructPresent(&scanResult.listRecords,XBinary::FT_PLAINTEXT)||
        SpecAbstract::isScanStructPresent(&scanResult.listRecords,XBinary::FT_UTF8) ||
        SpecAbstract::isScanStructPresent(&scanResult.listRecords,XBinary::FT_UNICODE))
    {
        listResult.append("text/plain");
    }

    return listResult;
}

QList<QString> XMIME::getTypes(QString sFileName)
{
    QList<QString> listResult;

    QFile file;

    file.setFileName(sFileName);

    if(file.open(QIODevice::ReadOnly))
    {
        listResult=getTypes(&file);

        file.close();
    }

    return listResult;
}

