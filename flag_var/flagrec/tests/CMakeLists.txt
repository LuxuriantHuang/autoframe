# Test configuration - simple version
# Test executables are built separately for testing

# Test runner script
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/run_tests.sh.in
    ${CMAKE_CURRENT_BINARY_DIR}/run_tests.sh
    @ONLY
)
