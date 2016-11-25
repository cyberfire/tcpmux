#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

const char *banner = "***************\necho server started\n************\n";

int main(int argc, char *argv[])
{
	char buf[1024];

	setbuf(stdout, NULL);
	setbuf(stdin, NULL);

	fputs(banner, stdout);

	while (1) {
		if (fgets(buf, 1024, stdin) == NULL)
			break;

		fputs(buf, stdout);

	}

	return 0;
}
