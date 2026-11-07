# Only the pinned upstream YARA-X C API is a supported scanner engine.
find_package(PkgConfig REQUIRED)
pkg_check_modules(YARAX REQUIRED yara_x_capi)
if(NOT YARAX_VERSION VERSION_EQUAL "1.23.0")
  message(FATAL_ERROR "Require pinned yara_x_capi=1.23.0; found ${YARAX_VERSION}")
endif()
# The archive is mandatory. The ordinary imported pkg-config target may select
# a dynamic library; static metadata also supplies Rust's system link flags.
find_file(YARAX_STATIC_ARCHIVE NAMES libyara_x_capi.a
  HINTS ${YARAX_LIBRARY_DIRS} NO_DEFAULT_PATH REQUIRED)
if(NOT YARAX_STATIC_LDFLAGS)
  message(FATAL_ERROR "Missing static YARA-X linker metadata")
endif()
set(YARAX_STATIC_DEPENDENCIES ${YARAX_STATIC_LDFLAGS})
list(REMOVE_ITEM YARAX_STATIC_DEPENDENCIES "-lyara_x_capi")
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED COMPONENTS Crypto)
if(NOT EXISTS "${PROJECT_SOURCE_DIR}/external/elfio/elfio/elfio.hpp"
   OR NOT EXISTS "${PROJECT_SOURCE_DIR}/external/elfio/LICENSE.txt")
  message(FATAL_ERROR "Pinned ELFIO submodule is missing: run git submodule update --init --recursive")
endif()
add_executable(vulnimprint-scan src/yara_x_main.cc src/elf.cc)
target_compile_features(vulnimprint-scan PRIVATE cxx_std_20)
target_include_directories(vulnimprint-scan PRIVATE include)
target_include_directories(vulnimprint-scan SYSTEM PRIVATE
  ${YARAX_INCLUDE_DIRS} "${PROJECT_SOURCE_DIR}/external/elfio")
target_link_libraries(vulnimprint-scan PRIVATE
  "${YARAX_STATIC_ARCHIVE}" ${YARAX_STATIC_DEPENDENCIES}
  Threads::Threads OpenSSL::Crypto)
target_compile_options(vulnimprint-scan PRIVATE -Wall -Wextra -Wpedantic -Werror)
install(TARGETS vulnimprint-scan RUNTIME DESTINATION bin)
