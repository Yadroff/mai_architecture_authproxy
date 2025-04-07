cmake_minimum_required(VERSION 3.12...3.31)
project(authproxy)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(DownloadUserver)

find_package(userver COMPONENTS core QUIET)
if(NOT userver_FOUND)
  # Tries TRY_DIR first, falls back to downloading userver from GitHub using CPM.
  download_userver(TRY_DIR third_party/userver)
endif()

find_package(jwt-cpp QUIET)
if (NOT jwt-cpp_FOUND)
  message("Loading JWT-CPP")
  include(cmake/get_cpm.cmake)
  # download jwt-cpp
  CPMAddPackage(
    NAME jwt-cpp
    GITHUB_REPOSITORY Thalhammer/jwt-cpp
    VERSION 0.7.1
    OPTIONS "JWT_BUILD_EXAMPLES OFF" "JWT_BUILD_TESTS OFF" "JWT_CMAKE_FILES_INSTALL ON"
  )
endif()

userver_setup_environment()

# Common sources
add_library(${PROJECT_NAME}_objs OBJECT
    src/handlers/hello.hpp
    src/handlers/hello.cpp
    src/components/jwt_checker.hpp
    src/components/jwt_checker.cpp
    src/components/auth_factory.hpp
    src/components/auth_factory.cpp
)
target_link_libraries(${PROJECT_NAME}_objs PUBLIC userver::core jwt-cpp::jwt-cpp)
target_include_directories(${PROJECT_NAME}_objs PUBLIC ${CMAKE_SOURCE_DIR}/src)

# The Service
add_executable(${PROJECT_NAME} src/main.cpp)
target_link_libraries(${PROJECT_NAME} PRIVATE ${PROJECT_NAME}_objs)


# Unit Tests
add_executable(${PROJECT_NAME}_unittest
    src/hello_test.cpp
)
target_link_libraries(${PROJECT_NAME}_unittest PRIVATE ${PROJECT_NAME}_objs userver::utest)
add_google_tests(${PROJECT_NAME}_unittest)


# Benchmarks
add_executable(${PROJECT_NAME}_benchmark
    src/hello_benchmark.cpp
)
target_link_libraries(${PROJECT_NAME}_benchmark PRIVATE ${PROJECT_NAME}_objs userver::ubench)
add_google_benchmark_tests(${PROJECT_NAME}_benchmark)

# Functional testing
userver_testsuite_add_simple()

# Install
include(GNUInstallDirs)

if(DEFINED ENV{PREFIX})
  message(STATUS "Set install prefix: $ENV{PREFIX}")
  file(TO_CMAKE_PATH "$ENV{PREFIX}" PREFIX_PATH)
  set(CMAKE_INSTALL_PREFIX "${PREFIX_PATH}")
endif()

file(GLOB CONFIGS_FILES ${CMAKE_CURRENT_SOURCE_DIR}/configs/*.yaml ${CMAKE_CURRENT_SOURCE_DIR}/configs/*.json)

install(TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT ${PROJECT_NAME})
install(FILES ${CONFIGS_FILES} DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/${PROJECT_NAME} COMPONENT ${PROJECT_NAME})
