include_directories(${CMAKE_CURRENT_LIST_DIR})

include(${CMAKE_CURRENT_LIST_DIR}/../StaticScan/staticscan.cmake)

set(XMIME_SOURCES
    ${STATICSCAN_SOURCES}
    ${CMAKE_CURRENT_LIST_DIR}/xmime.cpp
)
