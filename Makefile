check:
	pylint stbt_rig.py
	pylint3 stbt_rig.py
	pytest -vv -rs
	pytest-3 -vv -rs

pypi-publish:
	rm -rf dist/
	python3 setup.py sdist
	twine upload dist/*
