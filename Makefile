# 
# This Makefile is only used to generate "binary" version of the program.
# It is not really binary, but the executable with Python interpreter included,
# and it still may need to Python libraries installed locally.
#

ifneq ($(OS),Windows_NT)

sniftran: sniftran.py
	pyinstaller --onefile sniftran.py
	mv dist/sniftran ./sniftran
	rm -rf dist build sniftran.spec

else

sniftran.exe: sniftran.py
	pyinstaller --onefile sniftran.py
	cmd //C move //Y dist\sniftran.exe
	cmd //C rmdir //S //Q dist build
	cmd //C del sniftran.spec
	
endif
