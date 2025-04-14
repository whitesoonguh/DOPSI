cmake_minimum_required (VERSION 3.5.1)

project(demo CXX)
set(CMAKE_CXX_STANDARD 17)

option(BUILD_STATIC "Set to ON to include static versions of the library" OFF)

find_package(OpenFHE CONFIG REQUIRED)
if (OpenFHE_FOUND)
    message(STATUS "FOUND PACKAGE OpenFHE")
    message(STATUS "OpenFHE Version: ${BASE_OPENFHE_VERSION}")
    message(STATUS "OpenFHE installed as shared libraries: ${OpenFHE_SHARED}")
    message(STATUS "OpenFHE include files location: ${OpenFHE_INCLUDE}")
    message(STATUS "OpenFHE lib files location: ${OpenFHE_LIBDIR}")
    message(STATUS "OpenFHE Native Backend size: ${OpenFHE_NATIVE_SIZE}")
else()
    message(FATAL_ERROR "PACKAGE OpenFHE NOT FOUND")
endif()

find_package(OpenSSL REQUIRED)

# Use the compiler flags from OpenFHE
set(CMAKE_CXX_FLAGS ${OpenFHE_CXX_FLAGS})

# Include paths for OpenFHE + (optionally) OpenMP
include_directories(
    ${OPENMP_INCLUDES}
    ${OpenFHE_INCLUDE}
    ${OpenFHE_INCLUDE}/third-party/include
    ${OpenFHE_INCLUDE}/core
    ${OpenFHE_INCLUDE}/pke
    ${OpenFHE_INCLUDE}/binfhe
)

# Where to find libraries
link_directories(
    ${OpenFHE_LIBDIR}
    ${OPENMP_LIBRARIES}
)


# Handle static vs. shared linking with OpenFHE
if(BUILD_STATIC)
    set(CMAKE_EXE_LINKER_FLAGS "${OpenFHE_EXE_LINKER_FLAGS} -static")
else()
    set(CMAKE_EXE_LINKER_FLAGS "${OpenFHE_EXE_LINKER_FLAGS}")
endif()

##################################################
# 1) Build a library
##################################################
add_library(DOPMT
    ${PROJECT_SOURCE_DIR}/src/demo_256bit.cpp
    ${PROJECT_SOURCE_DIR}/src/demo_comp.cpp
    ${PROJECT_SOURCE_DIR}/src/core.cpp
    ${PROJECT_SOURCE_DIR}/include/HE.h
    ${PROJECT_SOURCE_DIR}/src/server.cpp
    ${PROJECT_SOURCE_DIR}/src/client.cpp
    ${PROJECT_SOURCE_DIR}/src/tests.cpp
)

# Let the library see your include/ folder
target_include_directories(DOPMT PRIVATE
    ${PROJECT_SOURCE_DIR}/include
)

# Link OpenFHE with DOPMT
if(BUILD_STATIC)
    target_link_libraries(DOPMT PRIVATE ${OpenFHE_STATIC_LIBRARIES})
else()
    target_link_libraries(DOPMT PRIVATE ${OpenFHE_SHARED_LIBRARIES})
endif()

# For PEPSI
add_library(PEPSI
    ${PROJECT_SOURCE_DIR}/pepsi/client.cpp
    ${PROJECT_SOURCE_DIR}/pepsi/server.cpp
    ${PROJECT_SOURCE_DIR}/pepsi/core.cpp
    ${PROJECT_SOURCE_DIR}/pepsi/tests.cpp
    ${PROJECT_SOURCE_DIR}/include/HE.h
)

# Let the library see your include/ folder
target_include_directories(PEPSI PRIVATE
    ${PROJECT_SOURCE_DIR}/include
)

# Link OpenFHE with PEPSI
if(BUILD_STATIC)
    target_link_libraries(PEPSI PRIVATE ${OpenFHE_STATIC_LIBRARIES})
else()
    target_link_libraries(PEPSI PRIVATE ${OpenFHE_SHARED_LIBRARIES})
endif()

# APSI
add_library(APSI
    ${PROJECT_SOURCE_DIR}/APSI/sender.cpp
    ${PROJECT_SOURCE_DIR}/APSI/receiver.cpp
    ${PROJECT_SOURCE_DIR}/APSI/hashing.cpp
    ${PROJECT_SOURCE_DIR}/APSI/core.cpp
    ${PROJECT_SOURCE_DIR}/APSI/poly.cpp 
    ${PROJECT_SOURCE_DIR}/APSI/powers.cpp 
    ${PROJECT_SOURCE_DIR}/APSI/thread_pool_mgr.cpp 
    ${PROJECT_SOURCE_DIR}/APSI/tests.cpp
)
target_include_directories(APSI PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/APSI
)
if(BUILD_STATIC)
    target_link_libraries(APSI PRIVATE ${OpenFHE_STATIC_LIBRARIES})
else()
    target_link_libraries(APSI PRIVATE ${OpenFHE_SHARED_LIBRARIES})
endif()


##################################################
# 2) Build the main executables
##################################################
add_executable(main
    ${PROJECT_SOURCE_DIR}/src/main.cpp
)

# Let main see your include/ folder
target_include_directories(main PRIVATE
    ${PROJECT_SOURCE_DIR}/include
)

# Finally, link main with:
target_link_libraries(main PRIVATE DOPMT)

add_executable(main_pepsi
    ${PROJECT_SOURCE_DIR}/pepsi/main_pepsi.cpp
)

# PEPSI
target_include_directories(main_pepsi PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/pepsi
)

target_link_libraries(main_pepsi PRIVATE PEPSI)

# APSI
add_executable(main_apsi
    ${PROJECT_SOURCE_DIR}/APSI/main_apsi.cpp
)
target_include_directories(main_apsi PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/APSI
)
target_link_libraries(main_apsi PRIVATE APSI OpenSSL::Crypto)