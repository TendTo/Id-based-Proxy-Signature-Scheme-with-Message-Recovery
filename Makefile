CONFIG_FILE := Makefile.conf
-include $(CONFIG_FILE)

UNAME := $(shell uname -s)
IS_MAC = $(filter Darwin, $(UNAME))
IS_LNX = $(filter Linux, $(UNAME))
IS_WIN = $(filter Windows_NT, $(UNAME))

ifeq ($(strip $(IS_MAC)$(IS_WIN)$(IS_LNX)),)
	$(error Unrecognized platform!)
endif

#==============================================================================
#  TARGETS
#==============================================================================

.PHONY: test clean files help compile run

help:
	@echo "---------------------------------------------------------------------"
	@echo " $(BOLD)$(YELLOW)$(PROJECT_NAME)$(RESET) $(BOLD)$(VERSION)$(RESET)"
	@echo "---------------------------------------------------------------------"
	@echo " $(BOLD)make [help]$(RESET)  - Prints out this help message."
	@echo " $(BOLD)make compile$(RESET) - Compiles the project."
	@echo " $(BOLD)make run$(RESET)     - Compiles and runs the project."
	@echo " $(BOLD)make test$(RESET)    - Compiles the whole test suite and runs it."
	@echo " $(BOLD)make files$(RESET)   - Prints out the files registered by make."
	@echo " $(BOLD)make clean$(RESET)   - Cleans up the build directory."

#==============================================================================
#  COMPILE TARGETS
#==============================================================================

# Compile the whole project
compile: $(OBJ_DIR) $(BIN_DIR) $(ENTRY_OBJECT)
	@cc -o $(BIN_DIR)/$(BINARY) $(ENTRY_OBJECT) $(SOURCE_OBJECTS) $(CFLAGS) $(CDEFINE) $(LDLIBS)

# Compiling the object files
$(ENTRY_OBJECT) $(SOURCE_OBJECTS): $(ENTRY_FILE) $(SOURCE_FILES) $(HEADER_FILES)
	@echo "Compiling production code..  "
	@$(CC) $(CFLAGS) $(LDLIBS) $(CDEFINE) -c $^ \
	2> temp_error_file; if [ $$? -ne 0 ]; then touch _error_flag; fi; true
	@if [ -f _error_flag ]; then \
	  rm -f _error_flag; \
		echo "$(RED)$(BOLD)Error$(RESET)"; \
		cat temp_error_file; \
		rm -f temp_error_file; \
		echo "$(RED)$(BOLD)Make aborted!$(RESET)"; \
		false; \
	else \
		if [ -s temp_error_file ]; then \
			echo "$(YELLOW)$(BOLD)Warning$(RESET)"; \
			cat temp_error_file; \
		else \
			echo "$(GREEN)$(BOLD)Done$(RESET)"; \
		fi \
	fi
	@rm -f temp_error_file
	@rm -f $(INC_DIR)/*.gch
	@mv $(notdir $(SOURCE_OBJECTS) $(ENTRY_OBJECT)) $(OBJ_DIR)

#==============================================================================
#  TEST TARGETS
#==============================================================================

test: $(OBJ_DIR) $(BIN_DIR) $(ENTRY_OBJECT)
	@$(CC) $(TEST_ENTRY_FILE) $(SOURCE_OBJECTS) -o $(BIN_DIR)/$(TEST_BINARY) $(TEST_CFLAGS) $(TEST_LDLIBS) $(TEST_CDEFINE)
	@echo "Testing...  $(YELLOW)$(BOLD)Start$(RESET)"
	@./$(BIN_DIR)/$(TEST_BINARY) \
	2> temp_error_file; if [ $$? -ne 0 ]; then touch _error_flag; fi; true
	@if [ -f _error_flag ]; then \
	  rm -f _error_flag; \
		echo "Testing...  $(RED)$(BOLD)Error$(RESET)"; \
		cat temp_error_file; \
		rm -f temp_error_file; \
		false; \
	else \
		if [ -s temp_error_file ]; then \
			echo "Testing...  $(YELLOW)$(BOLD)Warning$(RESET)"; \
			cat temp_error_file; \
		else \
			echo "Testing...  $(GREEN)$(BOLD)Success$(RESET)"; \
		fi \
	fi
	@rm -f temp_error_file

#==============================================================================
#  UTILITY TARGETS
#==============================================================================

# Creating the build directory
$(OBJ_DIR):
	@mkdir -p $@

# Creating the bin directory
$(BIN_DIR):
	@mkdir -p $@

# Running the project
run: compile
	@echo "Running $(BOLD)$(PROJECT_NAME)$(RESET) $(BOLD)$(VERSION)$(RESET)"
	@echo "---------------------------------------------------------------------"
	@$(BIN_DIR)/$(BINARY)

# Cleaning up the build directory
clean:
	@echo "Cleaning up.. "
	@rm -rf $(OBJ_DIR)
	@rm -rf $(BIN_DIR)
	@echo "$(GREEN)$(BOLD)Done$(RESET)"


# File and target listing
files:
	@echo ' $(YELLOW)$(BOLD)Production files$(RESET)'
	@echo '   $(BOLD)Entry$(RESET):     $(ENTRY_FILE)'
	@echo '   $(BOLD)Headers$(RESET):   $(HEADER_FILES)'
	@echo '   $(BOLD)Sources$(RESET):   $(SOURCE_FILES)'
	@echo ' $(YELLOW)$(BOLD)Test files$(RESET)'
	@echo '   $(BOLD)Entry$(RESET):     $(TEST_ENTRY_FILE)'
	@echo ' '
	@echo ' $(GREEN)$(BOLD)Production objects$(RESET)'
	@echo '   $(BOLD)Entry$(RESET):     $(ENTRY_OBJECT)'
	@echo '   $(BOLD)Objects$(RESET):   $(SOURCE_OBJECTS)'
	@echo ' $(GREEN)$(BOLD)Test objects$(RESET)'
	@echo '   $(BOLD)Entry$(RESET):     $(TEST_ENTRY_OBJECT)'
