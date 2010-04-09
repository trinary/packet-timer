cmake_minimum_required(VERSION 2.6)

cmake_policy(SET CMP0002 OLD)
cmake_policy(SET CMP0003 OLD)

if(NOT DEFINED ROOT_PROJECT)
  set(ROOT_PROJECT "packet_timer" CACHE INTERNAL DOCSTRING)
endif(NOT DEFINED ROOT_PROJECT)

PROJECT (PacketTimer)
ENABLE_TESTING()

# include the preamble before we do anything else
include("cmake/macros/preamble.cmake")

# then check if we're the root project
if(NOT DEFINED ROOT_PROJECT)
  set(ROOT_PROJECT "packet_timer" CACHE INTERNAL DOCSTRING)
endif(NOT DEFINED ROOT_PROJECT)

#clear any build info flags for lower level libs if necessary
if(ROOT_PROJECT STREQUAL "packet_timer")
  set(PACKET_TIMER_INCLUDED "false" CACHE INTERNAL DOCSTRING)
  set(LIBSYSSHEP_INCLUDED "false" CACHE INTERNAL DOCSTRING)
endif(ROOT_PROJECT STREQUAL "packet_timer")

#then get them to build themselves and their dependencies
ADD_SUBDIRECTORY(libsysshep)

# then get their environments info, since add_subdirectory causes info set
# there to go out of scope
include(libsysshep/include_me.cmake)
LIBSYSSHEP_SETUP("${CMAKE_CURRENT_SOURCE_DIR}/libsysshep")

if(PACKET_TIMER_INCLUDED STREQUAL "false")
  LINK_DIRECTORIES("/usr/lib")
  SET(TP_LIBS pcap ${TP_LIBS})
  ADD_SUBDIRECTORY(src)
  
  if(DEFINED WITH_ALL_TESTS)
    message(STATUS "WITH ALL TESTS defined, building packet_timer tests")
    set(BUILD_TESTS "true")
  else(DEFINED WITH_ALL_TESTS)
    message(STATUS "WITH ALL TESTS not defined")
    if(DEFINED WITH_TESTS)
      if(ROOT_PROJECT STREQUAL "packet_timer")
        message(STATUS "WITH TESTS and packet_timer top project, building tests")
        set(BUILD_TESTS "true")
      endif(ROOT_PROJECT STREQUAL "packet_timer")
    endif(DEFINED WITH_TESTS)
  endif(DEFINED WITH_ALL_TESTS)
  
  if(BUILD_TESTS STREQUAL "true")
    set(OLD_PATH ${EXECUTABLE_OUTPUT_PATH})
    set(EXECUTABLE_OUTPUT_PATH ${OLD_PATH}/tests/packet_timer)
    make_directory(${EXECUTABLE_OUTPUT_PATH})
#    ADD_SUBDIRECTORY(tests)
    set(EXECUTABLE_OUTPUT_PATH ${OLD_PATH})
  endif(BUILD_TESTS STREQUAL "true")
  set(PACKET_TIMER_INCLUDED "true" CACHE INTERNAL DOCSTRING)
endif(PACKET_TIMER_INCLUDED STREQUAL "false")

#ADD_SUBDIRECTORY()


#IF (WIN32)
#  ADD_SUBDIRECTORY(installer/nsis)
#ELSE (WIN32)
#  ADD_SUBDIRECTORY(installer/unix)
#ENDIF (WIN32)
