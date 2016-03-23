all:
	gcc learn.c -o learn -lpcap
	gcc process.c -o process -lpcap -lm

clean:
	rm -f learn
	rm -f process