# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.22

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/dtalexundeer/code/project

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/dtalexundeer/code/project/build

# Include any dependencies generated for this target.
include CMakeFiles/project.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/project.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/project.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/project.dir/flags.make

CMakeFiles/project.dir/main.c.o: CMakeFiles/project.dir/flags.make
CMakeFiles/project.dir/main.c.o: ../main.c
CMakeFiles/project.dir/main.c.o: CMakeFiles/project.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/dtalexundeer/code/project/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/project.dir/main.c.o"
	gcc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/project.dir/main.c.o -MF CMakeFiles/project.dir/main.c.o.d -o CMakeFiles/project.dir/main.c.o -c /home/dtalexundeer/code/project/main.c

CMakeFiles/project.dir/main.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/project.dir/main.c.i"
	gcc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/dtalexundeer/code/project/main.c > CMakeFiles/project.dir/main.c.i

CMakeFiles/project.dir/main.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/project.dir/main.c.s"
	gcc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/dtalexundeer/code/project/main.c -o CMakeFiles/project.dir/main.c.s

CMakeFiles/project.dir/src/sniffer.c.o: CMakeFiles/project.dir/flags.make
CMakeFiles/project.dir/src/sniffer.c.o: ../src/sniffer.c
CMakeFiles/project.dir/src/sniffer.c.o: CMakeFiles/project.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/dtalexundeer/code/project/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/project.dir/src/sniffer.c.o"
	gcc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/project.dir/src/sniffer.c.o -MF CMakeFiles/project.dir/src/sniffer.c.o.d -o CMakeFiles/project.dir/src/sniffer.c.o -c /home/dtalexundeer/code/project/src/sniffer.c

CMakeFiles/project.dir/src/sniffer.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/project.dir/src/sniffer.c.i"
	gcc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/dtalexundeer/code/project/src/sniffer.c > CMakeFiles/project.dir/src/sniffer.c.i

CMakeFiles/project.dir/src/sniffer.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/project.dir/src/sniffer.c.s"
	gcc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/dtalexundeer/code/project/src/sniffer.c -o CMakeFiles/project.dir/src/sniffer.c.s

CMakeFiles/project.dir/src/interfaces.c.o: CMakeFiles/project.dir/flags.make
CMakeFiles/project.dir/src/interfaces.c.o: ../src/interfaces.c
CMakeFiles/project.dir/src/interfaces.c.o: CMakeFiles/project.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/dtalexundeer/code/project/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object CMakeFiles/project.dir/src/interfaces.c.o"
	gcc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/project.dir/src/interfaces.c.o -MF CMakeFiles/project.dir/src/interfaces.c.o.d -o CMakeFiles/project.dir/src/interfaces.c.o -c /home/dtalexundeer/code/project/src/interfaces.c

CMakeFiles/project.dir/src/interfaces.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/project.dir/src/interfaces.c.i"
	gcc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/dtalexundeer/code/project/src/interfaces.c > CMakeFiles/project.dir/src/interfaces.c.i

CMakeFiles/project.dir/src/interfaces.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/project.dir/src/interfaces.c.s"
	gcc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/dtalexundeer/code/project/src/interfaces.c -o CMakeFiles/project.dir/src/interfaces.c.s

CMakeFiles/project.dir/src/config.c.o: CMakeFiles/project.dir/flags.make
CMakeFiles/project.dir/src/config.c.o: ../src/config.c
CMakeFiles/project.dir/src/config.c.o: CMakeFiles/project.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/dtalexundeer/code/project/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building C object CMakeFiles/project.dir/src/config.c.o"
	gcc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/project.dir/src/config.c.o -MF CMakeFiles/project.dir/src/config.c.o.d -o CMakeFiles/project.dir/src/config.c.o -c /home/dtalexundeer/code/project/src/config.c

CMakeFiles/project.dir/src/config.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/project.dir/src/config.c.i"
	gcc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/dtalexundeer/code/project/src/config.c > CMakeFiles/project.dir/src/config.c.i

CMakeFiles/project.dir/src/config.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/project.dir/src/config.c.s"
	gcc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/dtalexundeer/code/project/src/config.c -o CMakeFiles/project.dir/src/config.c.s

# Object files for target project
project_OBJECTS = \
"CMakeFiles/project.dir/main.c.o" \
"CMakeFiles/project.dir/src/sniffer.c.o" \
"CMakeFiles/project.dir/src/interfaces.c.o" \
"CMakeFiles/project.dir/src/config.c.o"

# External object files for target project
project_EXTERNAL_OBJECTS =

project: CMakeFiles/project.dir/main.c.o
project: CMakeFiles/project.dir/src/sniffer.c.o
project: CMakeFiles/project.dir/src/interfaces.c.o
project: CMakeFiles/project.dir/src/config.c.o
project: CMakeFiles/project.dir/build.make
project: /usr/lib/x86_64-linux-gnu/libpcap.so
project: CMakeFiles/project.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/dtalexundeer/code/project/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Linking C executable project"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/project.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/project.dir/build: project
.PHONY : CMakeFiles/project.dir/build

CMakeFiles/project.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/project.dir/cmake_clean.cmake
.PHONY : CMakeFiles/project.dir/clean

CMakeFiles/project.dir/depend:
	cd /home/dtalexundeer/code/project/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/dtalexundeer/code/project /home/dtalexundeer/code/project /home/dtalexundeer/code/project/build /home/dtalexundeer/code/project/build /home/dtalexundeer/code/project/build/CMakeFiles/project.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/project.dir/depend

