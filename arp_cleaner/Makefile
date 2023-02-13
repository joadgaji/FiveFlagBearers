# Makefile for the python program

SOURCE = main.py
PROGRAM = arp_cleaner

default : $(PROGRAM)

$(PROGRAM) : $(SOURCE) 
	cat $(SOURCE) > $(PROGRAM)
	chmod +x $(PROGRAM)
	
clean:
	rm -ft __pycache__ $(PROGRAM)