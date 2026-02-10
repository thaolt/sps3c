if(NOT DEFINED INPUT)
  message(FATAL_ERROR "INPUT is not set")
endif()
if(NOT DEFINED OUTPUT)
  message(FATAL_ERROR "OUTPUT is not set")
endif()
if(NOT DEFINED SYMBOL)
  set(SYMBOL "s_tls_ca")
endif()

# Guard against accidental surrounding quotes in -DINPUT/-DOUTPUT
string(REGEX REPLACE "^\"(.*)\"$" "\\1" INPUT "${INPUT}")
string(REGEX REPLACE "^\"(.*)\"$" "\\1" OUTPUT "${OUTPUT}")

file(READ "${INPUT}" PEM_CONTENT)

# Escape for C string literal
string(REPLACE "\\" "\\\\" PEM_CONTENT "${PEM_CONTENT}")
string(REPLACE "\"" "\\\"" PEM_CONTENT "${PEM_CONTENT}")

# Turn newlines into explicit \n sequences and keep the generated file readable
string(REPLACE "\n" "\\n\"\n\"" PEM_CONTENT "${PEM_CONTENT}")

set(C_SOURCE "const char ${SYMBOL}[] = \"${PEM_CONTENT}\";\n")

get_filename_component(_out_dir "${OUTPUT}" DIRECTORY)
file(MAKE_DIRECTORY "${_out_dir}")
file(WRITE "${OUTPUT}" "${C_SOURCE}")
