src = $(wildcard *.c)
obj = $(src:.c=.o)

LDFLAGS = -lcrypto

name =u2f

$(name): $(obj)
	$(CC) -O3 -Wall -Werror -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(obj) $(name)
