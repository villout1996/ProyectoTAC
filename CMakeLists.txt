cmake_minimum_required( VERSION 3.14 )
project( scl-protocols VERSION 0.0.1 DESCRIPTION "SCL example" )

set(CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread -march=native -Wall -Wextra -pedantic -Werror -std=gnu++17 -O2")

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include_directories (.)

find_library(GMP gmp libgmp REQUIRED)
find_library(SCL scl REQUIRED)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")

set(SOURCE_FILES
  main.cc)

add_executable(run.x ${SOURCE_FILES})
target_link_libraries(run.x ${SCL})
target_link_libraries(run.x ${GMP})
