"""metadata_utils installation script.
"""
import os
import re

from setuptools import find_packages
from setuptools import setup

HERE = os.path.abspath(os.path.dirname(__file__))

long_description = description = "TLS/SSL Certiicate Utilities"
with open(os.path.join(HERE, "README.md")) as fp:
    long_description = fp.read()

# store version in the init.py
with open(os.path.join(HERE, "src", "cert_utils", "__init__.py")) as v_file:
    VERSION = re.compile(r'.*__VERSION__ = "(.*?)"', re.S).match(v_file.read()).group(1)

requires = [
    "python-dateutil",
    "psutil>=4.4.0",  # for Python2/3 compat
    "requests",
]
tests_require = [
    "certbot",
    "cryptography",
    "josepy",
    "mypy",
    "pyOpenSSL",
    "pytest",
    "types-psutil",
    "types-pyOpenSSL",
    "types-python-dateutil",
    "types-requests",
]

testing_extras = tests_require + []

setup(
    name="cert_utils",
    description="TLS/SSL Certiicate Utilities",
    long_description=long_description,
    long_description_content_type="text/markdown",
    version=VERSION,
    url="https://github.com/aptise/cert_utils",
    author="Jonathan Vanasco",
    author_email="jonathan@findmeon.com",
    zip_safe=False,
    python_requires=">=3.6",
    keywords="web",
    install_requires=requires,
    tests_require=tests_require,
    extras_require={
        "testing": testing_extras,
    },
    test_suite="tests",
    packages=find_packages(
        where="src",
    ),
    package_dir={"": "src"},
    package_data={"cert_utils": ["py.typed"]},
    include_package_data=True,
    classifiers=[
        "Intended Audience :: Developers",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: MIT License",
    ],
    license="MIT",
)
