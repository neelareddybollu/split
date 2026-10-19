cmake_minimum_required(VERSION 3.14)

project(ImGuiImPlotDemo LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# -----------------------------------------------------------
# Download CPM.cmake
# -----------------------------------------------------------
set(CPM_VERSION 0.43.1)
set(CPM_FILE "${CMAKE_BINARY_DIR}/cmake/CPM.cmake")

if(NOT EXISTS "${CPM_FILE}")
    file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/cmake")

    file(DOWNLOAD
        "https://github.com/cpm-cmake/CPM.cmake/releases/download/v${CPM_VERSION}/CPM.cmake"
        "${CPM_FILE}"
        TLS_VERIFY ON
    )
endif()

include("${CPM_FILE}")

# Creates imgui::imgui and implot::implot targets.
include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/ImGui.cmake")
include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/ImPlot.cmake")

# Application targets
add_subdirectory(src)
