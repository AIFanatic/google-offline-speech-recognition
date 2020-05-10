cmake_minimum_required(VERSION 3.4.1)
project(inject LANGUAGES C CXX)

add_library(inject
  SHARED
    inject.cpp)

target_compile_options(inject
  PRIVATE
    -Wall -Werror)