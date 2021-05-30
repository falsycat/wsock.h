cmake_minimum_required(VERSION 3.18)

project(wsock.h C)
include(CTest)


add_library(wsock.h INTERFACE)
target_sources(wsock.h
  INTERFACE wsock.h
)
target_include_directories(wsock.h SYSTEM
  INTERFACE .
)


if(BUILD_TESTING)
  add_executable(wsock-test)
  target_compile_options(wsock-test
    INTERFACE
      -Wall -Wextra -Werror -Wno-missing-field-initializers
  )
  target_link_libraries(wsock-test
    PRIVATE wsock.h
  )
  target_sources(wsock-test
    PRIVATE test.c
  )

  add_test(
    NAME    wsock-test
    COMMAND $<TARGET_FILE:wsock-test>)
endif()
