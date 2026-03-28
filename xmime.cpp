/* Copyright (c) 2020-2026 hors<horsicq@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include "xmime.h"

XMIME::XMIME(QObject *pParent) : QObject(pParent)
{
}

QList<QString> XMIME::getTypes(QIODevice *pDevice, bool bIsAll)
{
    QList<QString> listResult;

    XScanEngine::SCAN_OPTIONS scanOptions = {};
    scanOptions.bShowType = true;
    scanOptions.bShowVersion = true;
    scanOptions.bShowInfo = true;

    XScanEngine::SCAN_RESULT scanResult = SpecAbstract().scanDevice(pDevice, &scanOptions);

    bool bBinary = false;
    // Executables
    {
        if (SpecAbstract::isScanStructPresent(&scanResult.listRecords, XBinary::FT_PE32) ||
            SpecAbstract::isScanStructPresent(&scanResult.listRecords, XBinary::FT_PE64)) {
            listResult.append("application/vnd.microsoft.portable-executable");
            bBinary = true;
        } else if (SpecAbstract::isScanStructPresent(&scanResult.listRecords, XBinary::FT_ELF32) ||
                   SpecAbstract::isScanStructPresent(&scanResult.listRecords, XBinary::FT_ELF64)) {
            listResult.append("application/x-executable");
            bBinary = true;
            // TODO
        } else if (SpecAbstract::isScanStructPresent(&scanResult.listRecords, XBinary::FT_MACHO32) ||
                   SpecAbstract::isScanStructPresent(&scanResult.listRecords, XBinary::FT_MACHO64)) {
            listResult.append("application/x-mach-binary");
            bBinary = true;
            // TODO
        }

        if (SpecAbstract::isScanStructPresent(&scanResult.listRecords, XBinary::FT_MSDOS)) {
            listResult.append("application/x-dosexec");
            bBinary = true;
        }
    }

    // Documents
    if (!bBinary) {
        if (SpecAbstract::isScanStructPresent(&scanResult.listRecords, XBinary::FT_UNKNOWN, SpecAbstract::RECORD_TYPE_UNKNOWN, SpecAbstract::RECORD_NAME_PYTHON)) {
            listResult.append("text/x-python");
        }

        if (SpecAbstract::isScanStructPresent(&scanResult.listRecords, XBinary::FT_UNKNOWN, SpecAbstract::RECORD_TYPE_UNKNOWN, SpecAbstract::RECORD_NAME_PERL)) {
            listResult.append("text/x-perl");
        }

        if (SpecAbstract::isScanStructPresent(&scanResult.listRecords, XBinary::FT_UNKNOWN, SpecAbstract::RECORD_TYPE_UNKNOWN, SpecAbstract::RECORD_NAME_RUBY)) {
            listResult.append("text/x-ruby");
        }

        if (SpecAbstract::isScanStructPresent(&scanResult.listRecords, XBinary::FT_UNKNOWN, SpecAbstract::RECORD_TYPE_UNKNOWN, SpecAbstract::RECORD_NAME_HTML)) {
            listResult.append("text/html");
        }

        if (SpecAbstract::isScanStructPresent(&scanResult.listRecords, XBinary::FT_UNKNOWN, SpecAbstract::RECORD_TYPE_UNKNOWN, SpecAbstract::RECORD_NAME_XML)) {
            listResult.append("text/xml");
        }

        if (SpecAbstract::isScanStructPresent(&scanResult.listRecords, XBinary::FT_UNKNOWN, SpecAbstract::RECORD_TYPE_UNKNOWN, SpecAbstract::RECORD_NAME_PDF)) {
            listResult.append("application/pdf");
        }

        if (SpecAbstract::isScanStructPresent(&scanResult.listRecords, XBinary::FT_UNKNOWN, SpecAbstract::RECORD_TYPE_UNKNOWN, SpecAbstract::RECORD_NAME_SHELL)) {
            listResult.append("text/x-shellscript");
        }

        if (SpecAbstract::isScanStructPresent(&scanResult.listRecords, XBinary::FT_UNKNOWN, SpecAbstract::RECORD_TYPE_UNKNOWN, SpecAbstract::RECORD_NAME_C) ||
            SpecAbstract::isScanStructPresent(&scanResult.listRecords, XBinary::FT_UNKNOWN, SpecAbstract::RECORD_TYPE_UNKNOWN, SpecAbstract::RECORD_NAME_CCPP)) {
            listResult.append("text/x-c");
        }
    }

    // Media
    {
        if (SpecAbstract::isScanStructPresent(&scanResult.listRecords, XBinary::FT_UNKNOWN, SpecAbstract::RECORD_TYPE_UNKNOWN, SpecAbstract::RECORD_NAME_MP3)) {
            listResult.append("audio/mpeg");
        }

        if (SpecAbstract::isScanStructPresent(&scanResult.listRecords, XBinary::FT_UNKNOWN, SpecAbstract::RECORD_TYPE_UNKNOWN, SpecAbstract::RECORD_NAME_PNG)) {
            listResult.append("image/png");
        }

        if (SpecAbstract::isScanStructPresent(&scanResult.listRecords, XBinary::FT_UNKNOWN, SpecAbstract::RECORD_TYPE_UNKNOWN, SpecAbstract::RECORD_NAME_WEBP)) {
            listResult.append("image/webp");
        }

        if (SpecAbstract::isScanStructPresent(&scanResult.listRecords, XBinary::FT_UNKNOWN, SpecAbstract::RECORD_TYPE_UNKNOWN, SpecAbstract::RECORD_NAME_JPEG)) {
            listResult.append("image/jpg");
            listResult.append("image/jpeg");
        }

        if (SpecAbstract::isScanStructPresent(&scanResult.listRecords, XBinary::FT_UNKNOWN, SpecAbstract::RECORD_TYPE_UNKNOWN, SpecAbstract::RECORD_NAME_GIF)) {
            listResult.append("image/gif");
        }
    }

    if (SpecAbstract::isScanStructPresent(&scanResult.listRecords, XBinary::FT_TEXT) ||
        SpecAbstract::isScanStructPresent(&scanResult.listRecords, XBinary::FT_PLAINTEXT) ||
        SpecAbstract::isScanStructPresent(&scanResult.listRecords, XBinary::FT_UTF8) || SpecAbstract::isScanStructPresent(&scanResult.listRecords, XBinary::FT_UNICODE)) {
        if ((listResult.count() == 0) || (bIsAll)) {
            listResult.append("text/plain");
        }
    } else {
        if ((listResult.count() == 0) || (bIsAll)) {
            listResult.append("application/octet-stream");
        }
    }
    {
        if (SpecAbstract::isScanStructPresent(&scanResult.listRecords, XBinary::FT_UNKNOWN, SpecAbstract::RECORD_TYPE_UNKNOWN, SpecAbstract::RECORD_NAME_GZIP)) {
            listResult.append("application/x-gzip");
        }
    
    }
    {
        if (SpecAbstract::isScanStructPresent(&scanResult.listRecords, XBinary::FT_UNKNOWN, SpecAbstract::RECORD_TYPE_UNKNOWN, SpecAbstract::RECORD_NAME_BZIP2)) {
            listResult.append("application/x-bzip2");
        }
    
    }
    {
        if (SpecAbstract::isScanStructPresent(&scanResult.listRecords, XBinary::FT_UNKNOWN, SpecAbstract::RECORD_TYPE_UNKNOWN, SpecAbstract::RECORD_NAME_BZIP)) {
            listResult.append("application/x-bzip");
        }
    
    }
    {
        if (SpecAbstract::isScanStructPresent(&scanResult.listRecords, XBinary::FT_UNKNOWN, SpecAbstract::RECORD_TYPE_UNKNOWN, SpecAbstract::RECORD_NAME_LZIP)) {
            listResult.append("application/x-lzip");
        }
    
    }
    {
        if (SpecAbstract::isScanStructPresent(&scanResult.listRecords, XBinary::FT_UNKNOWN, SpecAbstract::RECORD_TYPE_UNKNOWN, SpecAbstract::RECORD_NAME_7ZCOMPRESSED)) {
            listResult.append("application/x-7z-compressed");
        }
    
    }
    {
        if (SpecAbstract::isScanStructPresent(&scanResult.listRecords, XBinary::FT_UNKNOWN, SpecAbstract::RECORD_TYPE_UNKNOWN, SpecAbstract::RECORD_NAME_LZMA)) {
            listResult.append("application/x-lzma");
        }
    
    }
    {
        if (SpecAbstract::isScanStructPresent(&scanResult.listRecords, XBinary::FT_UNKNOWN, SpecAbstract::RECORD_TYPE_UNKNOWN, SpecAbstract::RECORD_NAME_XZ)) {
            listResult.append("application/x-xz");
        }
    
    }
    {
        if (SpecAbstract::isScanStructPresent(&scanResult.listRecords, XBinary::FT_UNKNOWN, SpecAbstract::RECORD_TYPE_UNKNOWN, SpecAbstract::RECORD_NAME_LRZIP)) {
            listResult.append("application/x-lrzip");
        }
    
    }
    {
        if (SpecAbstract::isScanStructPresent(&scanResult.listRecords, XBinary::FT_UNKNOWN, SpecAbstract::RECORD_TYPE_UNKNOWN, SpecAbstract::RECORD_NAME_LZ4)) {
            listResult.append("application/x-lz4");
        }
    
    }
    {
        if (SpecAbstract::isScanStructPresent(&scanResult.listRecords, XBinary::FT_UNKNOWN, SpecAbstract::RECORD_TYPE_UNKNOWN, SpecAbstract::RECORD_NAME_ZSTD)) {
            listResult.append("application/x-zstd");
        }
    
    }
    {
        if (SpecAbstract::isScanStructPresent(&scanResult.listRecords, XBinary::FT_UNKNOWN, SpecAbstract::RECORD_TYPE_UNKNOWN, SpecAbstract::RECORD_NAME_ZLIB)) {
            listResult.append("application/x-zlib");
        }
    
    }
    {
        if (SpecAbstract::isScanStructPresent(&scanResult.listRecords, XBinary::FT_UNKNOWN, SpecAbstract::RECORD_TYPE_UNKNOWN, SpecAbstract::RECORD_NAME_JAVASCRIPT)) {
            listResult.append("application/x-javascript");
        }
    
    }
    {
        if (SpecAbstract::isScanStructPresent(&scanResult.listRecords, XBinary::FT_UNKNOWN, SpecAbstract::RECORD_TYPE_UNKNOWN, SpecAbstract::RECORD_NAME_ARCHIVE)) {
            listResult.append("application/x-archive");
        }
    
    }
    {
        if (SpecAbstract::isScanStructPresent(&scanResult.listRecords, XBinary::FT_UNKNOWN, SpecAbstract::RECORD_TYPE_UNKNOWN, SpecAbstract::RECORD_NAME_WMV)) {
            listResult.append("video/x-ms-wmv");
        }
    
    }
    {
        if (SpecAbstract::isScanStructPresent(&scanResult.listRecords, XBinary::FT_UNKNOWN, SpecAbstract::RECORD_TYPE_UNKNOWN, SpecAbstract::RECORD_NAME_WMA)) {
            listResult.append("audio/x-ms-wma");
        }
    
    }
    {
        if (SpecAbstract::isScanStructPresent(&scanResult.listRecords, XBinary::FT_UNKNOWN, SpecAbstract::RECORD_TYPE_UNKNOWN, SpecAbstract::RECORD_NAME_ANDROIDPACKAGE)) {
            listResult.append("application/vnd.android.package-archive");
        }
    
    }

    return listResult;
}

QList<QString> XMIME::getTypes(const QString &sFileName, bool bIsAll)
{
    QList<QString> listResult;

    QFile file;

    file.setFileName(sFileName);

    if (file.open(QIODevice::ReadOnly)) {
        listResult = getTypes(&file, bIsAll);

        file.close();
    }

    return listResult;
}
