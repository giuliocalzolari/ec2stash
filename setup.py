#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup


with open("README.rst") as readme_file:
    readme = readme_file.read()


with open("VERSION") as version_file:
    version = version_file.read()    

with open("requirements.txt") as requirements_file:
    requirements = [
        requirement for requirement in requirements_file.read().split("\n")
        if requirement != ""
    ]

setup_requirements = [
    "pytest-runner==2.6.2"
]

setup(
    name="ec2stash",
    version=version,
    description="EC2 stash using AWS Parameters Store",
    long_description=readme,
    author="giuliocalzolari",
    author_email="gc@hide.me",
    license='MIT',
    url="https://github.com/giuliocalzolari/ec2stash",
    packages=[
        "ec2stash"
    ],
    package_dir={
        "ec2stash": "ec2stash"
    },
    py_modules=["ec2stash"],
    entry_points="""
        [console_scripts]
        ec2stash=ec2stash.cli:cli
    """,
    include_package_data=True,
    install_requires=requirements,
    zip_safe=False,
    keywords="ec2stash",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Natural Language :: English",
        "Environment :: Console",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.6",
        "Programming Language :: Python :: 2.7",
    ],
    test_suite="tests",
    setup_requires=setup_requirements
)
