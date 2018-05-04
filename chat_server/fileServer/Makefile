# All protection mechanisms on, except stack protection
all: fs

fs: fileserver.c ./multipart-parser/libmultipartparser.so
	gcc -o fs fileserver.c ./multipart-parser/libmultipartparser.so
