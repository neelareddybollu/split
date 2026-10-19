add_executable(split_scope
    main.cpp
)

find_package(Threads REQUIRED)

find_library(PCAP_LIBRARY NAMES pcap REQUIRED)

target_link_libraries(split_scope PRIVATE
    implot::implot
    ${PCAP_LIBRARY}
    Threads::Threads
    m
)
