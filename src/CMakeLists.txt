MACRO(ADD_AGENT_EXECUTABLE target) # expects files after target
  ADD_EXECUTABLE(${target} ${ARGN})
  ADD_SYSSHEP_LIBS(${target})
ENDMACRO(ADD_AGENT_EXECUTABLE)


# Unix Daemon
IF (UNIX)
  ADD_AGENT_EXECUTABLE(packet-timer
    packet-timer.c)
ENDIF (UNIX)
