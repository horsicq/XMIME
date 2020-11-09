INCLUDEPATH += $$PWD
DEPENDPATH += $$PWD

HEADERS += \
    $$PWD/xmime.h

SOURCES += \
    $$PWD/xmime.cpp

!contains(XCONFIG, xformats) {
    XCONFIG += xformats
    include(../Formats/xformats.pri)
}

!contains(XCONFIG, staticscan) {
    XCONFIG += staticscan
    include(../Staticscan/staticscan.pri)
}
