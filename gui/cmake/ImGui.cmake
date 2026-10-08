include_guard(GLOBAL)

if(NOT COMMAND CPMAddPackage)
    message(FATAL_ERROR "Include CPM.cmake before ImGui.cmake.")
endif()

find_package(PkgConfig REQUIRED)
pkg_check_modules(GLFW REQUIRED IMPORTED_TARGET glfw3)

find_package(OpenGL REQUIRED)
find_package(GLEW REQUIRED)

CPMAddPackage(
    NAME imgui
    GITHUB_REPOSITORY ocornut/imgui
    GIT_TAG v1.92.9-docking
    DOWNLOAD_ONLY YES
)

# Includes imgui_demo.cpp.
file(GLOB IMGUI_SOURCES CONFIGURE_DEPENDS
    "${imgui_SOURCE_DIR}/*.cpp"
)
list(REMOVE_ITEM IMGUI_SOURCES "${imgui_SOURCE_DIR}/imgui_demo.cpp")

add_library(dear_imgui STATIC
    ${IMGUI_SOURCES}

    # GLFW platform backend and OpenGL 3 renderer backend.
    "${imgui_SOURCE_DIR}/backends/imgui_impl_glfw.cpp"
    "${imgui_SOURCE_DIR}/backends/imgui_impl_opengl3.cpp"
)

add_library(imgui::imgui ALIAS dear_imgui)

target_include_directories(dear_imgui PUBLIC
    "${imgui_SOURCE_DIR}"
    "${imgui_SOURCE_DIR}/backends"
)

target_compile_definitions(dear_imgui
    PRIVATE
        IMGUI_IMPL_OPENGL_LOADER_GLEW
    PUBLIC
        GLFW_INCLUDE_NONE
)

target_link_libraries(dear_imgui PUBLIC
    PkgConfig::GLFW
    GLEW::GLEW
    OpenGL::GL
)
