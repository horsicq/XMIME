include_directories(${CMAKE_CURRENT_LIST_DIR})

include(${CMAKE_CURRENT_LIST_DIR}/../SpecAbstract/specabstract.cmake)

set(XMIME_SOURCES
    ${SPECABSTRACT_SOURCES}
    ${CMAKE_CURRENT_LIST_DIR}/xmime.cpp
)
