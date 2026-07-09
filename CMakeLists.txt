cmake_minimum_required(VERSION 3.28)
project(uEventAnalysisToolBackend VERSION 0.0.7 LANGUAGES CXX)
enable_testing()

option(BUILD_SHARED_LIBS "Build using shared libraries" OFF)
option(BUILD_CONTAINER "Build container for deployment" OFF)
option(WITH_CONAN "Build using Conan" OFF)
option(BUILD_TESTS "Compile unit tests" ON) 
option(USE_CLANG_TIDY "Build using clang-tidy" OFF)
include(GenerateExportHeader)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")
if(POLICY CMP0167)
  cmake_policy(SET CMP0167 NEW)
endif()
if (NOT ${BUILD_SHARED_LIBS})
   set(Boost_USE_STATIC_LIBS ON) 
endif()
find_package(gRPC CONFIG REQUIRED)
if (${WITH_CONAN})
   message("Will use Conan OTLP exporters")
   find_package(opentelemetry-cpp CONFIG COMPONENTS exporter_otlp_grpc exporters_otlp_http REQUIRED)
else()
   find_package(opentelemetry-cpp CONFIG COMPONENTS exporters_otlp_http REQUIRED)
endif()
find_package(spdlog REQUIRED)
find_package(Boost REQUIRED headers program_options REQUIRED)
#find_package(openldap REQUIRED)
#find_package(TBB COMPONENTS tbb REQUIRED)
find_package(Threads REQUIRED)
find_package(libpqxx REQUIRED)
find_package(jwt-cpp CONFIG REQUIRED)
if (BUILD_TESTS)
   find_package(Catch2 3 REQUIRED)
endif()

if (${USE_CLANG_TIDY} AND PROJECT_IS_TOP_LEVEL)
   message("Looking for clang-tidy")
   find_program(CLANG_TIDY_EXECUTABLE NAMES "clang-tidy")
   if (CLANG_TIDY_EXECUTABLE)
      message("Using clang-tidy  ${CLANG_TIDY_EXECUTABLE}")
      set(CMAKE_C_CLANG_TIDY   ${CLANG_TIDY_EXECUTABLE} -p ${CMAKE_BINARY_DIR})
      set(CMAKE_CXX_CLANG_TIDY ${CLANG_TIDY_EXECUTABLE} -p ${CMAKE_BINARY_DIR})
      set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
   else()
      message("clang-tidy not found")
   endif()
endif()

find_package(Git)
if (Git_FOUND)
   execute_process(
     COMMAND ${GIT_EXECUTABLE} --no-pager log -n 1 HEAD "--pretty=format:%h"
     OUTPUT_VARIABLE uEventAnalysisToolBackend_GITTAG
     RESULT_VARIABLE gitresult
     ERROR_QUIET
     OUTPUT_STRIP_TRAILING_WHITESPACE
   )
   if (gitresult EQUAL 0)
      message(STATUS "Last Git commit: ${uEventAnalysisToolBackend_GITTAG}")
   endif()
else()
   set(uEventAnalysisToolBackend_GITTAG "")
endif()
configure_file(${CMAKE_SOURCE_DIR}/lib/version.hpp.in
               ${CMAKE_SOURCE_DIR}/include/uEventAnalysisToolBackend/version.hpp)

set(HEADER_FILES
    include/uEventAnalysisToolBackend/auth/jsonWebToken.hpp
    include/uEventAnalysisToolBackend/auth/openldap.hpp
    include/uEventAnalysisToolBackend/auth/openldapOptions.hpp
    include/uEventAnalysisToolBackend/version.hpp)
set(LIBRARY_SRC
    lib/auth/jsonWebToken.cpp
    lib/auth/openldap.cpp
    lib/auth/openldapOptions.cpp
    lib/database/credentials.cpp
    lib/version.cpp)
set(LOGIN_PROTO_SRC
    uEventAnalysisToolAPI/v1/login/basic_request.proto
    uEventAnalysisToolAPI/v1/login/basic_response.proto
    uEventAnalysisToolAPI/v1/login/service.proto)
set(PROTO_SRC ${LOGIN_PROTO_SRC})

add_library(libuEventAnalysisToolBackend STATIC ${LIBRARY_SRC} ${PROTO_SRC})
add_library(uEventAnalysisToolBackend::libuEventAnalysisToolBackend ALIAS libuEventAnalysisToolBackend)
set_target_properties(libuEventAnalysisToolBackend PROPERTIES
                      OUTPUT_NAME uEventAnalysisToolBackend
                      CXX_STANDARD 23
                      CXX_STANDARD_REQUIRED YES 
                      CXX_EXTENSIONS NO) 
target_include_directories(libuEventAnalysisToolBackend
                           PRIVATE $<INSTALL_INTERFACE:include>
                           PRIVATE $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src>
                           PRIVATE $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
                          )
target_link_libraries(libuEventAnalysisToolBackend
                      PRIVATE jwt-cpp::jwt-cpp
                              libpqxx::pqxx
                              spdlog::spdlog_header_only
                              Boost::headers
                              Threads::Threads)
target_sources(libuEventAnalysisToolBackend
               PUBLIC FILE_SET
                      HEADERS
                      BASE_DIRS
                         include
                      FILES
                         ${HEADER_FILES}
               )
protobuf_generate(TARGET libuEventAnalysisToolBackend
                  LANGUAGE cpp
                  OUT_VAR PROTO_GENERATED_CXX_FILES
                 )
protobuf_generate(TARGET libuEventAnalysisToolBackend
                  LANGUAGE grpc
                  PLUGIN "protoc-gen-grpc=$<TARGET_FILE:gRPC::grpc_cpp_plugin>"
                  PLUGIN_OPTIONS generate_mock_code=true
                  GENERATE_EXTENSIONS .grpc.pb.h .grpc.pb.cc
                  OUT_VAR PROTO_GENERATED_FILES
                 )
set_source_files_properties(${PROTO_GENERATED_FILES} ${PROTO_GENERATED_CXX_FILES}
   PROPERTIES
      SKIP_LINTING ON
)

add_executable(uEventAnalysisToolBackend
               src/main.cpp)
set_target_properties(uEventAnalysisToolBackend PROPERTIES
                      CXX_STANDARD 23
                      CXX_STANDARD_REQUIRED YES
                      CXX_EXTENSIONS NO)
target_include_directories(uEventAnalysisToolBackend
                           PRIVATE $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src>
                           PRIVATE $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
                           PRIVATE $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}>
                          )
target_link_libraries(uEventAnalysisToolBackend
                      PRIVATE libuEventAnalysisToolBackend)


##########################################################################################
#                                      Testing                                           #
##########################################################################################
if (PROJECT_IS_TOP_LEVEL AND ${BUILD_TESTS})
   add_executable(unitTests
                  testing/auth/options.cpp
                  testing/database/credentials.cpp
   )
   set_target_properties(unitTests PROPERTIES
                         CXX_STANDARD 23
                         CXX_STANDARD_REQUIRED YES
                         CXX_EXTENSIONS NO)
   target_link_libraries(unitTests
                         PRIVATE
                            uEventAnalysisToolBackend::libuEventAnalysisToolBackend
                            spdlog::spdlog_header_only
                            #gRPC::grpc gRPC::grpc++
                            Threads::Threads
                            Catch2::Catch2 Catch2::Catch2WithMain)
   target_include_directories(unitTests
                              PRIVATE $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>)
   add_test(NAME unitTests
            COMMAND $<TARGET_FILE:unitTests>)

endif()

##########################################################################################
#                                      Installation                                      #
##########################################################################################
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
configure_package_config_file(
    cmake/${PROJECT_NAME}Config.cmake.in "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
    INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}")
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake"
    VERSION "${version}"
    COMPATIBILITY AnyNewerVersion
)

install(TARGETS libuEventAnalysisToolBackend
        EXPORT ${PROJECT_NAME}Targets
        FILE_SET HEADERS
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        COMPONENT libraries)
install(TARGETS uEventAnalysisToolBackend
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        COMPONENT applications)
install(EXPORT ${PROJECT_NAME}Targets
        NAMESPACE ${PROJECT_NAME}::
        FILE ${PROJECT_NAME}Targets.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME})
install(FILES
        ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME})

