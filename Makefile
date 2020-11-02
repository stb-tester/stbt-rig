check:
	pylint stbt_rig.py
	pylint3 stbt_rig.py
	pytest -vv -rs
	pytest-3 -vv -rs
