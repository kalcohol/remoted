cmake_minimum_required(VERSION 3.21)
project(remoted LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(libssh CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)

add_executable(remoted WIN32
  src/main.cpp
  src/log.cpp
  src/codepage.cpp
  src/config.cpp
  src/pnp.cpp
  src/serial.cpp
  src/app.cpp
  src/overlay.cpp
  src/tray.cpp
  src/ssh.cpp
  resources/remoted.rc
)

target_include_directories(remoted PRIVATE src)

target_compile_definitions(remoted PRIVATE
  UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN
  _WIN32_WINNT=0x0A00
  _WINSOCK_DEPRECATED_NO_WARNINGS _CRT_SECURE_NO_WARNINGS
)

target_link_libraries(remoted PRIVATE
  nlohmann_json::nlohmann_json
  ws2_32 user32 advapi32 shell32 setupapi gdi32 ole32
)

# robust target name handling across libssh cmake configs
if(TARGET LibSSH::LibSSH)
  target_link_libraries(remoted PRIVATE LibSSH::LibSSH)
elseif(TARGET libssh::libssh)
  target_link_libraries(remoted PRIVATE libssh::libssh)
elseif(TARGET ssh)
  target_link_libraries(remoted PRIVATE ssh)
else()
  target_link_libraries(remoted PRIVATE ${LIBSSH_LIBRARIES})
endif()

if(MSVC)
  target_compile_options(remoted PRIVATE /W3 /utf-8 /permissive-)
  # our remoted.rc embeds the manifest; suppress the linker's auto-manifest
  set_target_properties(remoted PROPERTIES LINK_FLAGS "/MANIFEST:NO")
endif()

# drop a copy of the example config next to the exe on first build
set(EXAMPLE_CFG "${CMAKE_CURRENT_SOURCE_DIR}/config/remoted.json.example")
add_custom_command(TARGET remoted POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
          "${EXAMPLE_CFG}" "$<TARGET_FILE_DIR:remoted>/remoted.json.example")
