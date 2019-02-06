# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: jjourdai <marvin@42.fr>                    +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2017/01/17 13:28:01 by jjourdai          #+#    #+#              #
#*   Updated: 2017/03/06 14:29:20 by jjourdai         ###   ########.fr       *#
#                                                                              #
# **************************************************************************** #

SRC_PATH = ./src/

SRC_NAME =	main.c \
			param.c \
			options.c \
			display_recv_packet.c \
			init.c \

OBJ_PATH = ./.obj/

CPPFLAGS = -Iinclude -I ./libft/include

LDFLAGS = -Llibft

LDLIBS = -lft

NAME = ft_traceroute
	
CC = gcc

CFLAGS = -Wall -Wextra -fsanitize=address

OBJ_NAME = $(SRC_NAME:.c=.o)

SRC = $(addprefix $(SRC_PATH), $(SRC_NAME))

OBJ = $(addprefix $(OBJ_PATH), $(OBJ_NAME))

.PHONY: all, clean, fclean, re

all: $(NAME)

$(NAME): $(OBJ)
	make -C ./libft/
	$(CC) $^ -o $(NAME) $(CFLAGS) $(LDFLAGS) $(LDLIBS)

$(OBJ_PATH)%.o: $(SRC_PATH)%.c ./include
	@mkdir $(OBJ_PATH) 2> /dev/null || true
	$(CC) -o $@ $(CFLAGS) $(CPPFLAGS) -c $<

clean:
	rm -fv $(OBJ)
	make clean -C ./libft/
	@rmdir $(OBJ_PATH) 2> /dev/null || true

fclean: clean
	make fclean -C ./libft/
	rm -fv $(NAME)

re: fclean all
