// add.cpp

#include "add-nbo.h"

void	print_error(const char *str)
{
	printf("Error: ");
	printf("%s", str);
	printf("\n");
}

void	check_close(FILE *fp1, FILE *fp2)
{
	if (fp1) fclose(fp1);
	if (fp2) fclose(fp2);
}
