INCLUDEPATH += $$PWD
DEPENDPATH += $$PWD

HEADERS += \
    $$PWD/xmime.h

SOURCES += \
    $$PWD/xmime.cpp

!contains(XCONFIG, specabstract) {
    XCONFIG += specabstract
    include($$PWD/../SpecAbstract/specabstract.pri)
}

DISTFILES += \
    $$PWD/LICENSE \
    $$PWD/README.md \
    $$PWD/xmime.cmake
