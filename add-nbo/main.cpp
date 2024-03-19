// main.cpp

#include "add-nbo.h"

int	main(int argc, char *argv[])
{
	FILE		*fp1, *fp2;
	uint32_t	a, b;
	int		len1, len2;

	if (argc != 3)
	{
		print_error("usage: ./add-nbo <file1> <file2>");
		return (1);
	}
	fp1 = fopen(argv[1], "rb");
	fp2 = fopen(argv[2], "rb");
	if (!fp1 || !fp2)
	{
		print_error(strerror(errno));
		check_close(fp1, fp2);
		return (1);
	}
	len1 = fread(&a, sizeof(uint32_t), 1, fp1);
	len2 = fread(&b, sizeof(uint32_t), 1, fp2);
	if (len1 != 1 || len2 != 1 || ferror(fp1) || ferror(fp2))
	{
		print_error("reading datas");
		check_close(fp1, fp2);
		return (1);
	}
	a = ntohl(a);
	b = ntohl(b);
	printf("%u(0x%x) + %u(0x%x) = %u(0x%x)\n", a, a, b, b, a+b, a+b);
	check_close(fp1, fp2);
	return (0);
}
