MACRO(ADD_PACKET_TIMER_EXECUTABLE target) # expects files after target
  ADD_EXECUTABLE(${target} ${ARGN})
  ADD_SYSSHEP_LIBS(${target})
  TARGET_LINK_LIBRARIES(${target} pcapp)
ENDMACRO(ADD_PACKET_TIMER_EXECUTABLE)


SET(SRC_FILES
  capture_descriptor.cxx
  network_device.cxx
  timer/cifs_timer.cxx
  timer/dns_timer.cxx
  timer/ftp_timer.cxx
  timer/http_timer.cxx
  timer/mapi_timer.cxx
  timer/timeval.cxx)

# make a shared library for delta, else a static one
IF(DEFINED USE_STATIC_LIBS OR LIB_SYSSHEP_BUILD_MODE STREQUAL "agent")
  ADD_LIBRARY(pcapp STATIC ${SRC_FILES})
ELSE(DEFINED USE_STATIC_LIBS OR LIB_SYSSHEP_BUILD_MODE STREQUAL "agent")
  IF(UNIX)
    ADD_LIBRARY(pcapp SHARED ${SRC_FILES})
  ELSE(UNIX)
    ADD_LIBRARY(pcapp ${SRC_FILES})
  ENDIF(UNIX)
ENDIF(DEFINED USE_STATIC_LIBS OR LIB_SYSSHEP_BUILD_MODE STREQUAL "agent")


# Cxx Packed Timer
IF (UNIX)
  ADD_PACKET_TIMER_EXECUTABLE(packet-timer
    packet-timer.cxx)
  ADD_PACKET_TIMER_EXECUTABLE(packet-timer-c
    packet-timer.c)
ENDIF (UNIX)
