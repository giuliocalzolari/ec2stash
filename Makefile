.PHONY: clean-pyc clean-build clean

clean: clean-build clean-pyc

clean-build:
	rm -fr build/
	rm -fr dist/	
	rm -fr .eggs/
	find . -name '*.egg-info' -exec rm -fr {} +
	find . -name '*.egg' -exec rm -f {} +

clean-pyc:
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f {} +
	find . -name '__pycache__' -exec rm -fr {} +

lint:
	flake8 ec2stash tests

dist: clean
	python setup.py sdist
	python setup.py bdist_wheel
	ls -l dist	

pip: dist
	twine upload dist/*	
	clean	

install: clean
	python setup.py install
