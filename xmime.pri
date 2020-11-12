INCLUDEPATH += $$PWD
DEPENDPATH += $$PWD

HEADERS += \
    $$PWD/xmime.h

SOURCES += \
    $$PWD/xmime.cpp

!contains(XCONFIG, staticscan) {
    XCONFIG += staticscan
    include(../Staticscan/staticscan.pri)
}
