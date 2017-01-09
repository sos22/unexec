all: libunexec.so smoke

libunexec.so: unexec.po
	gcc -shared -Bexport -fPIC -o $@ $^

unexec.po: unexec.c unexec.h
	gcc -g -c -mno-red-zone -fPIC -shared -Wall -Wextra $< -o $@

smoke: smoke.o libunexec.so
	gcc -Wl,-rpath -Wl,`pwd` -g $^ -o smoke

smoke.o: smoke.c unexec.h
	gcc -g -Wall -Wextra -c smoke.c

clean:
	rm -f smoke *.po *.o *.so *~
