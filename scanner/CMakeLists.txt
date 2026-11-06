# Fail closed: only the upstream YARA-X C API is an allowed release scanner.
find_package(PkgConfig REQUIRED)
pkg_check_modules(YARAX REQUIRED IMPORTED_TARGET yara_x_capi)
if(NOT YARAX_VERSION VERSION_EQUAL "1.23.0")
  message(FATAL_ERROR "Require pinned yara_x_capi=1.23.0; found ${YARAX_VERSION}")
endif()
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED COMPONENTS Crypto)
# Fail closed when the pinned, recursively fetched ELFIO checkout is absent.
if(NOT EXISTS "${PROJECT_SOURCE_DIR}/external/elfio/elfio/elfio.hpp"
   OR NOT EXISTS "${PROJECT_SOURCE_DIR}/external/elfio/LICENSE.txt")
  message(FATAL_ERROR "Pinned ELFIO submodule is missing: run git submodule update --init --recursive")
endif()
add_executable(vulnimprint-scan src/yara_x_main.cc src/elf.cc)
target_compile_features(vulnimprint-scan PRIVATE cxx_std_20)
target_include_directories(vulnimprint-scan PRIVATE include)
# External headers: no vendored ELFIO source and no first-party style gate.
target_include_directories(vulnimprint-scan SYSTEM PRIVATE "${PROJECT_SOURCE_DIR}/external/elfio")
target_link_libraries(vulnimprint-scan PRIVATE PkgConfig::YARAX Threads::Threads OpenSSL::Crypto)
target_compile_options(vulnimprint-scan PRIVATE -Wall -Wextra -Wpedantic -Werror)
set_target_properties(vulnimprint-scan PROPERTIES BUILD_RPATH_USE_ORIGIN ON INSTALL_RPATH "$ORIGIN/../lib")
install(TARGETS vulnimprint-scan RUNTIME DESTINATION bin)
