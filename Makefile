.PHONY: clean

clean:
	find . -name '*~' | xargs rm -f
	find . -name '*pyc' | xargs rm -f
	cd tests ; make clean

