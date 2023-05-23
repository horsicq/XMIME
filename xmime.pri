INCLUDEPATH += $$PWD
DEPENDPATH += $$PWD

HEADERS += \
    $$PWD/xmime.h

SOURCES += \
    $$PWD/xmime.cpp

!contains(XCONFIG, staticscan) {
    XCONFIG += staticscan
    include($$PWD/../SpecAbstract/staticscan.pri)
}

DISTFILES += \
    $$PWD/LICENSE \
    $$PWD/README.md \
    $$PWD/xmime.cmake
