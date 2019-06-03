# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: vsteffen <marvin@42.fr>                    +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2016/02/06 20:52:05 by vsteffen          #+#    #+#              #
#    Updated: 2018/03/20 18:17:27 by vsteffen         ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

PROJECT	= ft_ssl_md5
NAME	= ft_ssl

CC 	=	/usr/bin/clang
RM 	=	/bin/rm
MAKE 	=	/usr/bin/make
MKDIR 	=	/bin/mkdir -p
AR 	=	/usr/bin/ar
RANLIB 	=	/usr/bin/ranlib
GIT	=	/usr/bin/git

OBJ = $(patsubst %.c, $(OPATH)/%.o, $(SRC))

CFLAGS = -Wall -Wextra -Werror -g

ifeq ($(no-asm),y)
	NO-ASM:= no-asm
endif

LIB	=	$(ROOT)/lib
LIBSRCS	=	$(ROOT)/libsrcs
LIBFT 	=	$(LIBSRCS)/libft

ROOT  	=	$(shell /bin/pwd)
OPATH 	=	$(ROOT)/objs
CPATH 	=	$(ROOT)/srcs
LPATH	=	$(LIBFT)/libft.a
HPATH 	=	-I $(ROOT)/includes -I $(LIBFT)/includes

SHA_2	=	/sha_2
MD5		=	/md5

SRC =	main.c \
		parsing.c \
		parsing_2.c \
		shell.c \
		tools.c \
		tools_32.c \
		tools_64.c \
		tools_inputs.c \
		debug.c \
		$(MD5)/md5.c \
		$(MD5)/md5_read_input.c \
		$(MD5)/md5_read_input_2.c \
		$(MD5)/md5_auxiliaries.c \
		$(MD5)/md5_compute.c \
		$(SHA_2)/sha_2.c \
		$(SHA_2)/sha_2_init.c \
		$(SHA_2)/sha_2_read_input.c \
		$(SHA_2)/sha_2_update.c \
		$(SHA_2)/sha_2_auxiliaries_32.c \
		$(SHA_2)/sha_2_auxiliaries_32_2.c \
		$(SHA_2)/sha_2_auxiliaries_64.c \
		$(SHA_2)/sha_2_auxiliaries_64_2.c \
		$(SHA_2)/sha_2_compute_32.c \
		$(SHA_2)/sha_2_compute_64.c \
		fn_flags.c

PRE_CHECK_SUB_LIBFT	:= $(LIBFT)/Makefile
PRE_CHECK_SUB		:= $(PRE_CHECK_SUB_LIBFT)

PRE_CHECK_LIB_LIBFT := $(LIBFT)/libft.a
PRE_CHECK_LIB		:= $(PRE_CHECK_LIB_LIBFT) $(PRE_CHECK_LIB_LULZ)

COMPILE	= no

OS	:= $(shell uname -s)

ifeq ($(OS),Darwin)
	NPROCS:=$(shell sysctl -n hw.ncpu)
else
	NPROCS:=$(shell grep -c ^processor /proc/cpuinfo)
endif


define PRINT_RED
	printf "\033[31m$(1)\033[0m"
endef

define PRINT_GREEN
	printf "\033[32m$(1)\033[0m"
endef

define PRINT_YELLOW
	printf "\033[33m$(1)\033[0m"
endef

define PRINT_STATUS
	printf '['
	$(if $(filter $(2),SUCCESS),$(call PRINT_GREEN,$(1)))
	$(if $(filter $(2),FAIL),$(call PRINT_RED,$(1)))
	$(if $(filter $(2),WARN),$(call PRINT_YELLOW,$(1)))
	$(if $(filter $(2),INFO),printf $(1))
	$(if $(filter $(3),-n),printf $(1),echo ']')
endef

.PHONY: all clean fclean re lib-clean lib-update
.SILENT: $(PRE_CHECK_SUB) $(PRE_CHECK_LIB) $(NAME) $(OPATH) $(OPATH)/%.o clean fclean re lib-clean lib-update

all: $(NAME)

$(PRE_CHECK_SUB):
	@echo $(PROJECT)": Init submodule $(dir $@) ... "
	@$(GIT) submodule init > /dev/null  # can't directly redirect stdout on /dev/null cause of sync wait on Linux
	@$(GIT) submodule update --recursive --remote > /dev/null
	@printf $(PROJECT)": $(dir $@) "
	@$(call PRINT_STATUS,INITIALIZED,SUCCESS)

$(PRE_CHECK_LIB): $(PRE_CHECK_SUB)
	echo $(PROJECT)": Compile $@ ... " ; \
	if [ $@ = $(PRE_CHECK_LIB_LIBFT) ] ; then \
		if [ $(OS) = "Darwin" ] ; then \
			$(MAKE) -C $(LIBFT) $(NO-ASM) -j$(NPROCS) > /dev/null ; \
		else \
			$(MAKE) -C $(LIBFT) no-asm -j$(NPROCS) ; \
		fi; \
	else \
		echo "Other libraries here" ; \
	fi; \
	printf $(PROJECT)": $@ " ; \
	$(call PRINT_STATUS,COMPILED,SUCCESS) ;

$(NAME): $(PRE_CHECK_LIB) $(OPATH) $(OBJ)
	$(if $(filter $(COMPILE),yes),echo ']')
	printf $(PROJECT)": Building $@ ... "
	$(CC) -o $@ $(CFLAGS) $(OBJ) $(LPATH) $(HPATH)
	$(call PRINT_STATUS,DONE,SUCCESS)

$(OPATH)/%.o: $(CPATH)/%.c | $(PRE_CHECK_LIB)
	$(if $(filter $(COMPILE),no),@printf $(PROJECT)': Files compiling [')
	$(eval COMPILE := yes)
	@$(CC) $(CFLAGS) -c $< -o $@ $(HPATH)
	@$(call PRINT_GREEN,.)

$(OPATH):
	echo $(PROJECT)": Creation of objects directory"
	$(MKDIR) $@ $@$(MD5) $@$(SHA_2)

clean:
	$(RM) -Rf $(OPATH)
	echo $(PROJECT)": Objects cleaned "
	printf $(PROJECT)": $@ rule "
	$(call PRINT_STATUS,DONE,SUCCESS)

fclean: clean
	$(RM) -f $(NAME)
	echo $(PROJECT)": executable clean"
	printf $(PROJECT)": $@ rule "
	$(call PRINT_STATUS,DONE,SUCCESS)

re: fclean
	$(MAKE) -C $(ROOT) -j$(NPROCS) -s

lib-clean:
	echo $(PROJECT)": cleaning libraries ..."
	-$(MAKE) -C $(LIBFT) fclean -j$(NPROCS) > /dev/null
	printf $(PROJECT)": $@ rule "
	$(call PRINT_STATUS,DONE,SUCCESS)

lib-update:
	echo $(PROJECT)": Update submodules ... "
	$(GIT) submodule update --recursive --remote > /dev/null
	printf $(PROJECT)": submodules "
	$(call PRINT_STATUS,UPDATED,SUCCESS)
