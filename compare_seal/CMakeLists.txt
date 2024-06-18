project(compare_seal LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)

find_package(SEAL 4.0 REQUIRED)

add_executable(sealtest)
target_sources(sealtest PRIVATE sealtest.cpp)
target_link_libraries(sealtest SEAL::seal_shared)