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

#include <QPointer>

#include "xformats.h"
#include "xelf.h"

// XMIME maps a detected file to its MIME type(s).
//
// Primary pass: the concrete file-type set from XFormats::getFileTypes() (the same, tested
// mechanism the scan engine itself uses) drives the container/binary/media/image MIME strings,
// with most-specific-wins precedence (a PE suppresses its MZ stub, an APK/JAR suppresses the
// generic ZIP, a WEBP/AVI/WAV suppresses the generic RIFF, and pure umbrella types
// FT_ARCHIVE/FT_IMAGE/FT_RIFF are never emitted directly).
//
// Refinement pass: a DIE scan supplies RECORD_NAME markers that no file type captures - source
// languages inside FT_TEXT (python/perl/ruby/php/shell/js/c/...), formats with no dedicated FT
// (deb, wmv/wma, flv, swf, au, lrzip, comic-book), and CFBF/OLE2 office sub-types (doc/xls/...).
//
// The generic text/plain vs application/octet-stream fallback is emitted LAST, after every
// specific append, so a recognized format never gets a spurious octet-stream prepended.
//
// MIME strings follow the IANA / freedesktop shared-mime-info conventions (e.g. application/gzip
// not application/x-gzip, image/jpeg never image/jpg, text/javascript not application/x-javascript).

struct XMIME_NAME_MIME {
    XScanEngine::RECORD_NAME name;
    const char *pszMime;
};

// RECORD_NAME -> MIME, ONLY for things the file-type pass cannot express. Formats that already
// surface as a concrete FT (png, gzip, zip, pdf, dex, androidpackage, ...) are intentionally
// absent here to avoid double emission.
static const XMIME_NAME_MIME g_nameMimeTable[] = {
    // Source languages (live inside FT_TEXT; no distinct file type)
    {XScanEngine::RECORD_NAME_PYTHON, "text/x-python"},
    {XScanEngine::RECORD_NAME_PERL, "text/x-perl"},
    {XScanEngine::RECORD_NAME_RUBY, "text/x-ruby"},
    {XScanEngine::RECORD_NAME_PHP, "application/x-php"},
    {XScanEngine::RECORD_NAME_SHELL, "application/x-shellscript"},
    {XScanEngine::RECORD_NAME_JAVASCRIPT, "text/javascript"},
    {XScanEngine::RECORD_NAME_ECMASCRIPT, "text/javascript"},
    {XScanEngine::RECORD_NAME_JSCRIPT, "text/javascript"},
    {XScanEngine::RECORD_NAME_C, "text/x-csrc"},
    {XScanEngine::RECORD_NAME_CPP, "text/x-c++src"},
    {XScanEngine::RECORD_NAME_CCPP, "text/x-csrc"},
    {XScanEngine::RECORD_NAME_JAVA, "text/x-java"},
    {XScanEngine::RECORD_NAME_KOTLIN, "text/x-kotlin"},
    {XScanEngine::RECORD_NAME_GO, "text/x-go"},
    {XScanEngine::RECORD_NAME_RUST, "text/x-rust"},
    {XScanEngine::RECORD_NAME_SWIFT, "text/x-swift"},
    {XScanEngine::RECORD_NAME_CSHARP, "text/x-csharp"},
    {XScanEngine::RECORD_NAME_OBJECTIVEC, "text/x-objcsrc"},
    {XScanEngine::RECORD_NAME_D, "text/x-dsrc"},
    {XScanEngine::RECORD_NAME_FORTRAN, "text/x-fortran"},
    {XScanEngine::RECORD_NAME_QML, "text/x-qml"},
    {XScanEngine::RECORD_NAME_VBNET, "text/x-vbnet"},
    {XScanEngine::RECORD_NAME_VISUALBASIC, "text/x-vb"},
    {XScanEngine::RECORD_NAME_NIM, "text/x-nim"},
    {XScanEngine::RECORD_NAME_ZIG, "text/x-zig"},
    {XScanEngine::RECORD_NAME_HTML, "text/html"},
    {XScanEngine::RECORD_NAME_RTF, "application/rtf"},
    {XScanEngine::RECORD_NAME_LUACOMPILED, "application/x-lua-bytecode"},
    // Audio / video with no dedicated file type (ASF / FLV / SWF / AU wrappers)
    {XScanEngine::RECORD_NAME_WMV, "video/x-ms-wmv"},
    {XScanEngine::RECORD_NAME_WMA, "audio/x-ms-wma"},
    {XScanEngine::RECORD_NAME_WINDOWSMEDIA, "video/x-ms-asf"},
    {XScanEngine::RECORD_NAME_FLASHVIDEO, "video/x-flv"},
    {XScanEngine::RECORD_NAME_SWF, "application/x-shockwave-flash"},
    {XScanEngine::RECORD_NAME_AU, "audio/basic"},
    // Compressors with no dedicated file type
    {XScanEngine::RECORD_NAME_LRZIP, "application/x-lrzip"},
    {XScanEngine::RECORD_NAME_BZIP, "application/x-bzip"},
    {XScanEngine::RECORD_NAME_LZFSE, "application/x-lzfse"},
    // Packages / images with no dedicated file type
    {XScanEngine::RECORD_NAME_DEB, "application/vnd.debian.binary-package"},
    {XScanEngine::RECORD_NAME_COMICBOOKARCHIVE, "application/vnd.comicbook+zip"},
    {XScanEngine::RECORD_NAME_APPIMAGE, "application/vnd.appimage"},
    // CFBF / OLE2 office sub-types (refine the generic FT_CFBF container)
    {XScanEngine::RECORD_NAME_MICROSOFTOFFICEWORD, "application/msword"},
    {XScanEngine::RECORD_NAME_MICROSOFTEXCEL, "application/vnd.ms-excel"},
    {XScanEngine::RECORD_NAME_MICROSOFTVISIO, "application/vnd.visio"},
    {XScanEngine::RECORD_NAME_MICROSOFTACCESS, "application/x-msaccess"},
    {XScanEngine::RECORD_NAME_MICROSOFTCOMPILEDHTMLHELP, "application/vnd.ms-htmlhelp"},
    {XScanEngine::RECORD_NAME_MICROSOFTWINHELP, "application/winhlp"},
};

static void _appendUnique(QList<QString> *pListResult, const QString &sMime)
{
    if (!sMime.isEmpty()) {
        if (!pListResult->contains(sMime)) {
            pListResult->append(sMime);
        }
    }
}

static bool _isRecordPresent(QList<XScanEngine::SCANSTRUCT> *pListRecords, XScanEngine::RECORD_NAME name)
{
    return XScanEngine::isScanStructPresent(pListRecords, XBinary::FT_UNKNOWN, XScanEngine::RECORD_TYPE_UNKNOWN, name);
}

// True when a specific CFBF/OLE2 office document was recognized (so the generic OLE storage MIME
// is suppressed in favour of the precise application/msword, application/vnd.ms-excel, ...).
static bool _hasCfbfSubtype(QList<XScanEngine::SCANSTRUCT> *pListRecords)
{
    bool bResult = false;

    if (_isRecordPresent(pListRecords, XScanEngine::RECORD_NAME_MICROSOFTOFFICEWORD)) {
        bResult = true;
    } else if (_isRecordPresent(pListRecords, XScanEngine::RECORD_NAME_MICROSOFTEXCEL)) {
        bResult = true;
    } else if (_isRecordPresent(pListRecords, XScanEngine::RECORD_NAME_MICROSOFTVISIO)) {
        bResult = true;
    } else if (_isRecordPresent(pListRecords, XScanEngine::RECORD_NAME_MICROSOFTACCESS)) {
        bResult = true;
    } else if (_isRecordPresent(pListRecords, XScanEngine::RECORD_NAME_MICROSOFTCOMPILEDHTMLHELP)) {
        bResult = true;
    } else if (_isRecordPresent(pListRecords, XScanEngine::RECORD_NAME_MICROSOFTWINHELP)) {
        bResult = true;
    }

    return bResult;
}

// ELF sub-type by e_type (ET_EXEC/ET_DYN/ET_REL/ET_CORE) rather than a flat x-executable.
static QString _elfMimeForType(QIODevice *pDevice)
{
    XELF elf(pDevice);

    qint32 nType = elf.getType();

    if (nType == XELF::TYPE_DYN) {
        // Shared object (also PIE executables); the freedesktop type for ET_DYN.
        return QString("application/x-sharedlib");
    } else if (nType == XELF::TYPE_REL) {
        return QString("application/x-object");
    } else if (nType == XELF::TYPE_CORE) {
        return QString("application/x-coredump");
    }

    return QString("application/x-executable");
}

// Primary pass: append MIME strings for the concrete file types in stFT (most-specific-wins).
static void _appendMimeForFileTypes(QList<QString> *pListResult, const QSet<XBinary::FT> &stFT, QList<XScanEngine::SCANSTRUCT> *pListRecords, QIODevice *pDevice)
{
    // ---- Executables (mutually exclusive; a richer type suppresses the plain MZ/DOS stub) ----
    if (stFT.contains(XBinary::FT_PE32) || stFT.contains(XBinary::FT_PE64) || stFT.contains(XBinary::FT_PE)) {
        _appendUnique(pListResult, "application/vnd.microsoft.portable-executable");
        _appendUnique(pListResult, "application/x-dosexec");
    } else if (stFT.contains(XBinary::FT_CLI_ASSEMBLY)) {
        _appendUnique(pListResult, "application/vnd.microsoft.portable-executable");
    } else if (stFT.contains(XBinary::FT_NE) || stFT.contains(XBinary::FT_LE) || stFT.contains(XBinary::FT_LX) || stFT.contains(XBinary::FT_DOS16M) ||
               stFT.contains(XBinary::FT_DOS4G) || stFT.contains(XBinary::FT_BWDOS16M) || stFT.contains(XBinary::FT_MSDOS) || stFT.contains(XBinary::FT_COM)) {
        _appendUnique(pListResult, "application/x-dosexec");
    } else if (stFT.contains(XBinary::FT_ELF32) || stFT.contains(XBinary::FT_ELF64) || stFT.contains(XBinary::FT_ELF)) {
        _appendUnique(pListResult, _elfMimeForType(pDevice));
    } else if (stFT.contains(XBinary::FT_MACHO32) || stFT.contains(XBinary::FT_MACHO64) || stFT.contains(XBinary::FT_MACHO) ||
               stFT.contains(XBinary::FT_MACHOFAT)) {
        _appendUnique(pListResult, "application/x-mach-binary");
    }

    // ---- Byte-code / class containers (independent of the exec chain) ----
    if (stFT.contains(XBinary::FT_DEX)) {
        _appendUnique(pListResult, "application/x-dex");
    }
    if (stFT.contains(XBinary::FT_JAVACLASS)) {
        _appendUnique(pListResult, "application/java-vm");
        _appendUnique(pListResult, "application/x-java");
    }
    if (stFT.contains(XBinary::FT_PYC)) {
        _appendUnique(pListResult, "application/x-python-code");
    }

    // ---- ZIP family (a specific package suppresses the generic zip) ----
    if (stFT.contains(XBinary::FT_APK)) {
        _appendUnique(pListResult, "application/vnd.android.package-archive");
    } else if (stFT.contains(XBinary::FT_JAR)) {
        _appendUnique(pListResult, "application/java-archive");
    } else if (stFT.contains(XBinary::FT_ZIP)) {
        // An .ipa reaches here (it is a plain zip with no registered MIME of its own).
        _appendUnique(pListResult, "application/zip");
    }

    // ---- Other archives (each is a distinct format) ----
    if (stFT.contains(XBinary::FT_7Z)) {
        _appendUnique(pListResult, "application/x-7z-compressed");
    }
    if (stFT.contains(XBinary::FT_RAR)) {
        _appendUnique(pListResult, "application/vnd.rar");
        _appendUnique(pListResult, "application/x-rar-compressed");
    }
    if (stFT.contains(XBinary::FT_TAR)) {
        _appendUnique(pListResult, "application/x-tar");
    }
    if (stFT.contains(XBinary::FT_CAB)) {
        _appendUnique(pListResult, "application/vnd.ms-cab-compressed");
    }
    if (stFT.contains(XBinary::FT_ARJ)) {
        _appendUnique(pListResult, "application/x-arj");
    }
    if (stFT.contains(XBinary::FT_ACE)) {
        _appendUnique(pListResult, "application/x-ace-compressed");
    }
    if (stFT.contains(XBinary::FT_WIM)) {
        _appendUnique(pListResult, "application/x-ms-wim");
    }
    if (stFT.contains(XBinary::FT_ZOO)) {
        _appendUnique(pListResult, "application/x-zoo");
    }
    if (stFT.contains(XBinary::FT_XAR)) {
        _appendUnique(pListResult, "application/x-xar");
    }
    if (stFT.contains(XBinary::FT_CPIO)) {
        _appendUnique(pListResult, "application/x-cpio");
    }
    if (stFT.contains(XBinary::FT_RPM)) {
        _appendUnique(pListResult, "application/x-rpm");
    }
    if (stFT.contains(XBinary::FT_ISO9660) || stFT.contains(XBinary::FT_UDF)) {
        _appendUnique(pListResult, "application/x-cd-image");
    }
    if (stFT.contains(XBinary::FT_DMG)) {
        _appendUnique(pListResult, "application/x-apple-diskimage");
    }
    if (stFT.contains(XBinary::FT_AR)) {
        // A .deb is an ar archive; when recognized as such, prefer the Debian package MIME
        // (emitted by the record pass) over the generic ar type.
        if (!_isRecordPresent(pListRecords, XScanEngine::RECORD_NAME_DEB)) {
            _appendUnique(pListResult, "application/x-archive");
        }
    }

    // ---- Compressors ----
    if (stFT.contains(XBinary::FT_GZIP)) {
        _appendUnique(pListResult, "application/gzip");
        _appendUnique(pListResult, "application/x-gzip");
    }
    if (stFT.contains(XBinary::FT_BZIP2)) {
        _appendUnique(pListResult, "application/x-bzip2");
    }
    if (stFT.contains(XBinary::FT_XZ)) {
        _appendUnique(pListResult, "application/x-xz");
    }
    if (stFT.contains(XBinary::FT_LZIP)) {
        _appendUnique(pListResult, "application/x-lzip");
    }
    if (stFT.contains(XBinary::FT_LZMA)) {
        _appendUnique(pListResult, "application/x-lzma");
    }
    if (stFT.contains(XBinary::FT_LZ4)) {
        _appendUnique(pListResult, "application/x-lz4");
    }
    if (stFT.contains(XBinary::FT_ZSTD)) {
        _appendUnique(pListResult, "application/zstd");
        _appendUnique(pListResult, "application/x-zstd");
    }
    if (stFT.contains(XBinary::FT_ZLIB)) {
        _appendUnique(pListResult, "application/zlib");
    }
    if (stFT.contains(XBinary::FT_COMPRESS)) {
        _appendUnique(pListResult, "application/x-compress");
    }
    if (stFT.contains(XBinary::FT_LHA)) {
        _appendUnique(pListResult, "application/x-lha");
    }

    // ---- Images / fonts ----
    if (stFT.contains(XBinary::FT_PNG)) {
        _appendUnique(pListResult, "image/png");
    }
    if (stFT.contains(XBinary::FT_GIF)) {
        _appendUnique(pListResult, "image/gif");
    }
    if (stFT.contains(XBinary::FT_BMP)) {
        _appendUnique(pListResult, "image/bmp");
    }
    if (stFT.contains(XBinary::FT_JPEG)) {
        _appendUnique(pListResult, "image/jpeg");
    }
    if (stFT.contains(XBinary::FT_TIFF)) {
        _appendUnique(pListResult, "image/tiff");
    }
    if (stFT.contains(XBinary::FT_WEBP)) {
        _appendUnique(pListResult, "image/webp");
    }
    if (stFT.contains(XBinary::FT_ICO)) {
        _appendUnique(pListResult, "image/vnd.microsoft.icon");
        _appendUnique(pListResult, "image/x-icon");
    }
    if (stFT.contains(XBinary::FT_CUR)) {
        _appendUnique(pListResult, "image/x-win-bitmap");
    }
    if (stFT.contains(XBinary::FT_DJVU)) {
        _appendUnique(pListResult, "image/vnd.djvu");
    }
    if (stFT.contains(XBinary::FT_TTF)) {
        _appendUnique(pListResult, "font/ttf");
    }
    if (stFT.contains(XBinary::FT_ICC)) {
        _appendUnique(pListResult, "application/vnd.iccprofile");
    }

    // ---- Audio / video ----
    if (stFT.contains(XBinary::FT_MP3)) {
        _appendUnique(pListResult, "audio/mpeg");
    }
    if (stFT.contains(XBinary::FT_MP4)) {
        _appendUnique(pListResult, "video/mp4");
    }
    if (stFT.contains(XBinary::FT_AVI)) {
        _appendUnique(pListResult, "video/x-msvideo");
    }
    if (stFT.contains(XBinary::FT_WAV)) {
        _appendUnique(pListResult, "audio/x-wav");
    }

    // ---- Documents ----
    if (stFT.contains(XBinary::FT_PDF)) {
        _appendUnique(pListResult, "application/pdf");
    }
    if (stFT.contains(XBinary::FT_XML)) {
        _appendUnique(pListResult, "application/xml");
    }
    if (stFT.contains(XBinary::FT_CFBF)) {
        // Generic OLE2 storage; suppressed when a precise office sub-type was recognized.
        if (!_hasCfbfSubtype(pListRecords)) {
            _appendUnique(pListResult, "application/x-ole-storage");
        }
    }
}

XMIME::XMIME(QObject *pParent) : QObject(pParent)
{
}

QList<QString> XMIME::getTypes(QIODevice *pDevice, bool bIsAll)
{
    QList<QString> listResult;

    if (!pDevice || !pDevice->isOpen() || !pDevice->isReadable() || pDevice->isSequential()) {
        return listResult;
    }

    const qint64 nOriginalPosition = pDevice->pos();

    if ((nOriginalPosition < 0) || !pDevice->seek(0)) {
        return listResult;
    }

    QPointer<QIODevice> pDeviceGuard = pDevice;

    // Concrete file-type set (the tested detector the scan engine itself uses).
    QSet<XBinary::FT> stFT = XFormats::getFileTypes(pDevice, XBinary::FT_FLAG_FORMATS);

    // Deep scan for the RECORD_NAME markers no file type captures (source languages, office
    // sub-types, FT-less media/compressors, .deb).
    XScanEngine::SCAN_OPTIONS scanOptions = {};
    scanOptions.bShowType = true;
    scanOptions.bShowVersion = true;
    scanOptions.bShowInfo = true;

    XScanEngine::SCAN_RESULT scanResult = SpecAbstract().scanDevice(pDevice, &scanOptions);

    // Primary pass: file types -> MIME(s).
    _appendMimeForFileTypes(&listResult, stFT, &scanResult.listRecords, pDevice);

    // Refinement pass: record names -> MIME(s).
    qint32 nNumberOfNameRows = (qint32)(sizeof(g_nameMimeTable) / sizeof(g_nameMimeTable[0]));

    for (qint32 i = 0; i < nNumberOfNameRows; i++) {
        if (_isRecordPresent(&scanResult.listRecords, g_nameMimeTable[i].name)) {
            _appendUnique(&listResult, QString::fromLatin1(g_nameMimeTable[i].pszMime));
        }
    }

    // Generic base type - LAST, so a recognized format never gets a spurious octet-stream.
    // bIsAll == false: added only when nothing specific matched.
    // bIsAll == true : always appended in addition to the specific types.
    bool bIsText = stFT.contains(XBinary::FT_TEXT) || stFT.contains(XBinary::FT_PLAINTEXT) || stFT.contains(XBinary::FT_UTF8) ||
                   stFT.contains(XBinary::FT_UNICODE) || stFT.contains(XBinary::FT_UNICODE_BE) || stFT.contains(XBinary::FT_UNICODE_LE);

    if (listResult.isEmpty() || bIsAll) {
        if (bIsText) {
            _appendUnique(&listResult, "text/plain");
        } else {
            _appendUnique(&listResult, "application/octet-stream");
        }
    }

    if (!pDeviceGuard || !pDeviceGuard->seek(nOriginalPosition)) {
        listResult.clear();
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
