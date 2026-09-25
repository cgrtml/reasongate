# Every setting lives in pyproject.toml. This shim exists only so that older pip and
# setuptools versions can still run `pip install -e .`.
from setuptools import setup

setup()
