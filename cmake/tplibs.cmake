SET (THIRD_PARTY_PREFIX ${WORKSPACE_ROOT}/tp-compiled)
# record the locate of third party headers
SET (TP_INC_PREFIX ${THIRD_PARTY_PREFIX}/include/)
# record the locate of third party libraries
SET (TP_LIB_PREFIX ${THIRD_PARTY_PREFIX}/lib/)

if(MSVC)
    SET(TP_LIBS ${TP_LIBS} sqlapi)
else(MSVC)
    SET(TP_LIBS ${TP_LIBS} sqlapi)
endif(MSVC)

LINK_DIRECTORIES(
  "${TP_LIB_PREFIX}/sqlapi-${VERSION_SQLAPI}"
)

INCLUDE_DIRECTORIES(
  "${TP_INC_PREFIX}/sqlapi-${VERSION_SQLAPI}"
)

SET(HAVE_TPLIBS 1)
