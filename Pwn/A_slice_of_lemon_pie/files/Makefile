CC = gcc
CFLAGS = -fstack-protector-all -Wl,-z,relro,-z,lazy -pie

all: format_pie

format_pie: vuln.c
	$(CC) $(CFLAGS) -o format_pie vuln.c

clean:
	rm -f format_pie
