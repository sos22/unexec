all:: libunexec.so

libunexec.so: unexec.po save_registers.po
	gcc -shared -Bexport -fPIC -o $@ $^

unexec.po: unexec.c unexec.h
	gcc -g -c -mno-red-zone -fPIC -shared -Wall -Wextra $< -o $@

save_registers.po: save_registers.S
	as $< -o $@

clean::
	rm -f *.po *.so *~

include tests/mk
