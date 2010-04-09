# a macro to build tp libraries and binaries
macro(BUILD_TP_ENTITY BIN_OR_LIB VERSION TP_ENTITY_NAME EXIT)
    message(STATUS "Building ${TP_ENTITY_NAME}, if necessary.")

    if(MSVC)
        message(STATUS "  building windows style")
        exec_program(
            "C:\\cygwin\\bin\\bash"
            ${CMAKE_CURRENT_SOURCE_DIR}
            ARGS "${CMAKE_CURRENT_SOURCE_DIR}/scripts/build-tp-${BIN_OR_LIB}.sh"
                 "${WORKSPACE_ROOT}"
                 "${CMAKE_CURRENT_SOURCE_DIR}/scripts" 
                 "${TP_ENTITY_NAME}"
                 "${VERSION}"
            OUTPUT_VARIABLE SCRIPT_OUTPUT
            RETURN_VALUE SCRIPT_RETURN_VALUE
        )

        if(${SCRIPT_RETURN_VALUE})
            message(FATAL_ERROR
              "build script failed with output: ${SCRIPT_OUTPUT}")
        else(${SCRIPT_RETURN_VALUE})
            message(STATUS "${TP_ENTITY_NAME} built")
            if(${EXIT})
                message(FATAL_ERROR
                        "build script SUCCEEDED with output: ${SCRIPT_OUTPUT}")
            endif(${EXIT})
        endif(${SCRIPT_RETURN_VALUE})
    else(MSVC)
        message(STATUS "  building unix style")
        exec_program(
            ${CMAKE_CURRENT_SOURCE_DIR}/scripts/build-tp-${BIN_OR_LIB}.sh
            ${CMAKE_CURRENT_SOURCE_DIR}
            ARGS "${WORKSPACE_ROOT}"
                 "${CMAKE_CURRENT_SOURCE_DIR}/scripts" 
                 "${TP_ENTITY_NAME}"
                 "${VERSION}"
            OUTPUT_VARIABLE SCRIPT_OUTPUT
            RETURN_VALUE SCRIPT_RETURN_VALUE
        )

        if(${SCRIPT_RETURN_VALUE})
            message(FATAL_ERROR
              "build script failed with output: ${SCRIPT_OUTPUT}")
        else(${SCRIPT_RETURN_VALUE})
            message(STATUS "${TP_ENTITY_NAME} built")
            if(${EXIT})
                message(FATAL_ERROR
                        "build script SUCCEEDED with output: ${SCRIPT_OUTPUT}")
            endif(${EXIT})
        endif(${SCRIPT_RETURN_VALUE})
    endif(MSVC)
endmacro(BUILD_TP_ENTITY)
    
