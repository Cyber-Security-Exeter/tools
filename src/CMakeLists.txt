add_subdirectory(networking)
add_library(toollib exceptions.h io.h io.cpp security.h security.cpp command.h command.cpp crypto.h crypto.cpp util.h util.cpp maths.h maths.cpp)
target_link_libraries(networking toollib)
target_link_libraries(toollib networking)