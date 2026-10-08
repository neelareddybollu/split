include_guard(GLOBAL)

if(NOT TARGET imgui::imgui)
    message(FATAL_ERROR
        "ImGui.cmake must be included before ImPlot.cmake."
    )
endif()

CPMAddPackage(
    NAME implot
    GITHUB_REPOSITORY epezent/implot
    GIT_TAG v0.17
    DOWNLOAD_ONLY YES
)

# Includes implot_demo.cpp.
file(GLOB IMPLOT_SOURCES CONFIGURE_DEPENDS
    "${implot_SOURCE_DIR}/*.cpp"
)
list(REMOVE_ITEM IMPLOT_SOURCES "${implot_SOURCE_DIR}/implot_demo.cpp")

add_library(dear_implot STATIC
    ${IMPLOT_SOURCES}
)

add_library(implot::implot ALIAS dear_implot)

target_include_directories(dear_implot PUBLIC
    "${implot_SOURCE_DIR}"
)

target_link_libraries(dear_implot PUBLIC
    imgui::imgui
)
