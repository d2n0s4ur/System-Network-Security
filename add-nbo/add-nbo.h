// add-nbo.h

#ifndef _ADD_NBO_H_
# define _ADD_NBO_H_

# pragma once

# include <stdio.h>
# include <stdint.h>
# include <string.h>
# include <errno.h>
# include <netinet/in.h>

void	print_error(const char *str);
void	check_close(FILE *fp1, FILE *fp2);

#endif
