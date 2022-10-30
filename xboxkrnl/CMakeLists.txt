
PROJECT(NTOS)

# Make various changes throughout the kernel to support Xbox
add_compile_definitions(XBOX_KERNEL)

# Set base address?
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-Ttext-segment=0x80010000")

if (CMAKE_C_COMPILER_ID STREQUAL "GNU" OR CMAKE_C_COMPILER_ID STREQUAL "Clang")
    # Enable this again. CORE-17637
    add_compile_options(-Wunused-result)
endif()

include(../ntoskrnl/ntos.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/xbox.cmake)

set(XBOXKRNL_SOURCE ${SOURCE})
set(XBOXKRNL_ASM_SOURCE ${ASM_SOURCE})

set(NTKRNLMP_SOURCE ${SOURCE})
set(NTKRNLMP_ASM_SOURCE ${ASM_SOURCE})

spec2def(xboxkrnl.exe ../ntoskrnl/ntoskrnl.spec ADD_IMPORTLIB)

# Embed RTC libs
if (STACK_PROTECTOR)
    target_sources(libxboxkrnl PRIVATE $<TARGET_OBJECTS:gcc_ssp_nt>)
endif()

add_asm_files(xboxkrnl_asm ${XBOXKRNL_ASM_SOURCE})

if(CMAKE_C_COMPILER_ID STREQUAL "Clang")
    # Clang optimises strcmp calls to memcmp.
    target_sources(libxboxkrnl PRIVATE $<TARGET_OBJECTS:memcmp>)
endif()

list(APPEND PCH_SKIP_SOURCE
    ../ntoskrnl/guid.c)

add_executable(xboxkrnl
    ${xboxkrnl_asm}
    ${XBOXKRNL_SOURCE}
    ${PCH_SKIP_SOURCE}
    ../ntoskrnl/ntoskrnl.rc
    ${CMAKE_CURRENT_BINARY_DIR}/xboxkrnl.def)
set_module_type(xboxkrnl kernel)

#source_group(TREE ${REACTOS_SOURCE_DIR}/xboxkrnl PREFIX "Source Files" FILES ${XBOXKRNL_SOURCE})

# Stuff to link statically:
#  - investigate ${PSEH_LIB} and its deps
#  - investigate ROSSYM_LIB
target_link_libraries(xboxkrnl cportlib csq ${PSEH_LIB} arbiter cmlib ntlsalib rtl ${ROSSYM_LIB} libcntpr wdmguid ioevent)

if(STACK_PROTECTOR)
    target_sources(xboxkrnl PRIVATE $<TARGET_OBJECTS:gcc_ssp_nt>)
endif()

# Work out how to link hal etc statically
add_importlibs(xboxkrnl hal kdcom bootvid)
add_pch(xboxkrnl ${REACTOS_SOURCE_DIR}/ntoskrnl/include/ntoskrnl.h "${PCH_SKIP_SOURCE}")
add_dependencies(xboxkrnl psdk asm)
add_cd_file(TARGET xboxkrnl DESTINATION reactos/system32 NO_CAB FOR all)
add_cd_file(FILE "${CMAKE_CURRENT_LIST_DIR}/default.xbe" DESTINATION reactos/system32 NO_CAB FOR all)

# if(BUILD_MP)
#     add_subdirectory(ntkrnlmp)
# endif()

# add_asm_files(ntdllsys_asm ntdll.S)
# add_library(ntdllsys ${ntdllsys_asm})
# set_target_properties(ntdllsys PROPERTIES LINKER_LANGUAGE "C")
# add_dependencies(ntdllsys asm)
