add_executable(imgui_app
    main.cpp
)

find_package(Threads REQUIRED)

find_library(PCAP_LIBRARY NAMES pcap REQUIRED)

target_link_libraries(imgui_app PRIVATE
    implot::implot
    ${PCAP_LIBRARY}
    Threads::Threads
    m
)
