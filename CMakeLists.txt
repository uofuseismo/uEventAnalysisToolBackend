cmake_minimum_required(VERSION 3.28)
project(uEventAnalysisToolBackend VERSION 0.0.1 LANGUAGES CXX)
enable_testing()

option(BUILD_SHARED_LIBS "Build using shared libraries" OFF)
option(BUILD_CONTAINER "Build container for deployment" OFF)
option(WITH_CONAN "Build using Conan" OFF)
option(BUILD_TESTS "Compile unit tests" ON) 
option(USE_CLANG_TIDY "Build using clang-tidy" OFF)
include(GenerateExportHeader)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")
set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
if(POLICY CMP0167)
  cmake_policy(SET CMP0167 NEW)
endif()
if (NOT ${BUILD_SHARED_LIBS})
   set(Boost_USE_STATIC_LIBS ON) 
endif()
find_package(Protobuf CONFIG REQUIRED)
find_package(gRPC CONFIG REQUIRED)
if (${WITH_CONAN})
   message("Will use Conan OTLP exporters")
   find_package(opentelemetry-cpp CONFIG COMPONENTS exporter_otlp_grpc exporters_otlp_http REQUIRED)
else()
   find_package(opentelemetry-cpp CONFIG COMPONENTS exporters_otlp_http REQUIRED)
endif()
find_package(spdlog REQUIRED)
find_package(Boost REQUIRED headers json program_options REQUIRED)
#find_package(TBB COMPONENTS tbb REQUIRED)
find_package(Threads REQUIRED)
find_package(libpqxx REQUIRED)
find_package(jwt-cpp CONFIG REQUIRED)
find_package(libsodium REQUIRED)
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
    include/uEventAnalysisToolBackend/auth/authenticator.hpp
    include/uEventAnalysisToolBackend/auth/authNZ.hpp
    include/uEventAnalysisToolBackend/auth/database.hpp
    include/uEventAnalysisToolBackend/auth/databaseOptions.hpp
    include/uEventAnalysisToolBackend/auth/grpc.hpp
    include/uEventAnalysisToolBackend/auth/jsonWebToken.hpp
    include/uEventAnalysisToolBackend/auth/jsonWebTokenOptions.hpp
    include/uEventAnalysisToolBackend/auth/password/hasher.hpp
    include/uEventAnalysisToolBackend/auth/password/hasherOptions.hpp
    include/uEventAnalysisToolBackend/auth/password/passwordPolicy.hpp
    include/uEventAnalysisToolBackend/database/credentials.hpp
    include/uEventAnalysisToolBackend/grpc/grpcServerOptions.hpp
    include/uEventAnalysisToolBackend/grpc/requestIdentifierInterceptor.hpp
    include/uEventAnalysisToolBackend/grpc/server.hpp
    include/uEventAnalysisToolBackend/grpc/serverOptions.hpp
    include/uEventAnalysisToolBackend/services/authService.hpp
    include/uEventAnalysisToolBackend/version.hpp
    )
set(WILL_BE_DELETED_HEADER_FILES
    include/uEventAnalysisToolBackend/database/aqms/aqms.hpp
    include/uEventAnalysisToolBackend/database/aqms/arrival.hpp
    include/uEventAnalysisToolBackend/database/aqms/durationMagnitude.hpp
    include/uEventAnalysisToolBackend/database/aqms/event.hpp
    include/uEventAnalysisToolBackend/database/aqms/humanMagnitude.hpp
    include/uEventAnalysisToolBackend/database/aqms/localMagnitude.hpp
    include/uEventAnalysisToolBackend/database/aqms/magnitude.hpp
    include/uEventAnalysisToolBackend/database/aqms/origin.hpp
    include/uEventAnalysisToolBackend/database/aqms/peakToPeakAmplitude.hpp
    include/uEventAnalysisToolBackend/database/aqms/stationLocalMagnitude.hpp
    include/uEventAnalysisToolBackend/database/aqms/stationDurationMagnitude.hpp
    include/uEventAnalysisToolBackend/database/aqms/streamIdentifier.hpp)
set(LIBRARY_SRC
    lib/auth/authenticator.cpp
    lib/auth/authNZ.cpp
    lib/auth/database.cpp
    lib/auth/databaseOptions.cpp
    lib/auth/grpc.cpp
    lib/auth/jsonWebToken.cpp
    lib/auth/jsonWebTokenOptions.cpp
    lib/auth/password/hasher.cpp
    lib/auth/password/hasherOptions.cpp
    lib/auth/password/passwordPolicy.cpp
    lib/database/credentials.cpp
    lib/grpc/grpcServerOptions.cpp
    lib/grpc/requestIdentifierInterceptor.cpp
    lib/grpc/server.cpp
    lib/grpc/serverOptions.cpp
    lib/services/authService.cpp
    lib/version.cpp
    )
set(WILL_BE_DELETED_SRC
    lib/database/aqms/aqms.cpp
    lib/database/aqms/streamIdentifier.cpp
    lib/database/aqms/arrival.cpp
    lib/database/aqms/magnitude.cpp
    lib/database/aqms/localMagnitude.cpp
    lib/database/aqms/durationMagnitude.cpp
    lib/database/aqms/humanMagnitude.cpp
    lib/database/aqms/origin.cpp
    lib/database/aqms/event.cpp
    lib/database/aqms/peakToPeakAmplitude.cpp
    lib/database/aqms/stationLocalMagnitude.cpp
    lib/database/aqms/stationDurationMagnitude.cpp
    )
set(PROTO_SRC
    #uEventAnalysisToolAPI/admin/v1/service.proto
    uEventAnalysisToolAPI/auth/v1/change_password_request.proto
    uEventAnalysisToolAPI/auth/v1/change_password_response.proto
    uEventAnalysisToolAPI/auth/v1/login_with_password_request.proto
    uEventAnalysisToolAPI/auth/v1/login_with_password_response.proto
    uEventAnalysisToolAPI/auth/v1/get_password_requirements_request.proto
    uEventAnalysisToolAPI/auth/v1/password_requirements.proto
    uEventAnalysisToolAPI/auth/v1/service.proto
    uEventAnalysisToolAPI/settings/v1/get_map_provider_request.proto
    uEventAnalysisToolAPI/settings/v1/map_provider.proto
    uEventAnalysisToolAPI/settings/v1/service.proto
    #uEventAnalysisToolAPI/v1/userSettings/add_key_request.proto
    #uEventAnalysisToolAPI/v1/userSettings/add_key_response.proto
    #uEventAnalysisToolAPI/v1/userSettings/change_password_request.proto
    #uEventAnalysisToolAPI/v1/userSettings/change_password_response.proto
    #uEventAnalysisToolAPI/v1/userSettings/list_keys_request.proto
    #uEventAnalysisToolAPI/v1/userSettings/list_keys_response.proto
    #uEventAnalysisToolAPI/v1/userSettings/revoke_key_request.proto
    #uEventAnalysisToolAPI/v1/userSettings/revoke_key_response.proto
    #uEventAnalysisToolAPI/v1/userSettings/service.proto
    )

if (${BUILD_SHARED_LIBS})
   add_library(libuEventAnalysisToolBackend SHARED ${LIBRARY_SRC} ${WILL_BE_DELETED_SRC} ${PROTO_SRC})
else()
   add_library(libuEventAnalysisToolBackend STATIC ${LIBRARY_SRC} ${WILL_BE_DELETED_SRC} ${PROTO_SRC})
endif()
add_library(uEventAnalysisToolBackend::libuEventAnalysisToolBackend ALIAS libuEventAnalysisToolBackend)
set_target_properties(libuEventAnalysisToolBackend PROPERTIES
                      OUTPUT_NAME uEventAnalysisToolBackend
                      CXX_STANDARD 23
                      CXX_STANDARD_REQUIRED YES 
                      CXX_EXTENSIONS NO) 
target_include_directories(libuEventAnalysisToolBackend
                           PRIVATE $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
                           PRIVATE $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src>
                           PRIVATE $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
                           PUBLIC  $<INSTALL_INTERFACE:>
                          )
target_link_libraries(libuEventAnalysisToolBackend
                      PUBLIC gRPC::grpc++
                      PRIVATE protobuf::libprotobuf gRPC::grpc
                              jwt-cpp::jwt-cpp
                              libpqxx::pqxx
                              spdlog::spdlog_header_only
                              Boost::headers Boost::json Boost::program_options
                              libsodium::libsodium
                              Threads::Threads)
target_sources(libuEventAnalysisToolBackend
               PUBLIC FILE_SET
                      HEADERS
                      BASE_DIRS
                         include
                      FILES
                         ${HEADER_FILES}
                         ${WILL_BE_DELETED_HEADER_FILES}
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
                           PRIVATE $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
                           PRIVATE $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src>
                           PRIVATE $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
                          )
target_link_libraries(uEventAnalysisToolBackend
                      PRIVATE uEventAnalysisToolBackend::libuEventAnalysisToolBackend
                              Boost::headers Boost::program_options)

if (${WITH_CONAN})
   target_link_libraries(uEventAnalysisToolBackend
                         PRIVATE opentelemetry-cpp::opentelemetry-cpp
                                 opentelemetry-cpp::proto_grpc
                                 opentelemetry-cpp::exporter_otlp_grpc
                                 opentelemetry-cpp::exporter_otlp_grpc_client
                                 opentelemetry-cpp::exporter_otlp_grpc_metrics
                                 opentelemetry-cpp::exporter_otlp_http 
                                 opentelemetry-cpp::exporter_otlp_http_client
                                 opentelemetry-cpp::exporter_otlp_http_metric
                                 opentelemetry-cpp::exporter_otlp_http_log
                                 opentelemetry-cpp::metrics
                                 opentelemetry-cpp::common
                                 opentelemetry-cpp::api)
   target_compile_definitions(uEventAnalysisToolBackend PRIVATE WITH_OTLP_GRPC)
else()
   target_link_libraries(uEventAnalysisToolBackend
                         PRIVATE opentelemetry-cpp::otlp_http_log_record_exporter
                                 opentelemetry-cpp::otlp_http_metric_exporter)
endif()

#add_executable(uEventAnalysisToolUserManager
#               src/manageUsers.cpp)
#set_target_properties(uEventAnalysisToolUserManager PROPERTIES
#                      CXX_STANDARD 23
#                      CXX_STANDARD_REQUIRED YES 
#                      CXX_EXTENSIONS NO) 
#target_include_directories(uEventAnalysisToolUserManager
#                           PRIVATE $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
#                           PRIVATE $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src>
#                           PRIVATE $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
#                          )
#target_link_libraries(uEventAnalysisToolUserManager
#                      PRIVATE uEventAnalysisToolBackend::libuEventAnalysisToolBackend
#                              spdlog::spdlog_header_only
#                              Boost::headers Boost::json Boost::program_options )


##########################################################################################
#                                      Testing                                           #
##########################################################################################
if (PROJECT_IS_TOP_LEVEL AND ${BUILD_TESTS})
   add_executable(unitTests
                  testing/auth/jsonWebToken.cpp
                  testing/auth/authNZ.cpp
                  testing/auth/grpc.cpp
                  testing/auth/password/hasher.cpp
                  testing/auth/password/hasherOptions.cpp
                  testing/auth/password/passwordPolicy.cpp
                  testing/database/credentials.cpp
                  testing/database/aqms.cpp
                  testing/grpc/grpcServerOptions.cpp
                  testing/grpc/requestIdentifierInterceptor.cpp
                  ${PROTO_SRC}
   )
   target_compile_definitions(unitTests
                              PRIVATE TESTING_DATA_DIR="${CMAKE_SOURCE_DIR}/testing/data")
   set_target_properties(unitTests PROPERTIES
                         CXX_STANDARD 23
                         CXX_STANDARD_REQUIRED YES
                         CXX_EXTENSIONS NO)
   target_link_libraries(unitTests
                         PRIVATE
                            uEventAnalysisToolBackend::libuEventAnalysisToolBackend
                            spdlog::spdlog_header_only
                            gRPC::grpc gRPC::grpc++
                            Threads::Threads
                            Catch2::Catch2 Catch2::Catch2WithMain)
   target_include_directories(unitTests
                              PRIVATE $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>)
   add_test(NAME unitTests
            COMMAND $<TARGET_FILE:unitTests>)
   protobuf_generate(TARGET unitTests
                     LANGUAGE cpp 
                     )   
   protobuf_generate(TARGET unitTests
                     LANGUAGE grpc
                     PLUGIN "protoc-gen-grpc=$<TARGET_FILE:gRPC::grpc_cpp_plugin>"
                     PLUGIN_OPTIONS generate_mock_code=true
                     GENERATE_EXTENSIONS .grpc.pb.h .grpc.pb.cc
                    )   
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
install(TARGETS uEventAnalysisToolBackend #uEventAnalysisToolUserManager
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

