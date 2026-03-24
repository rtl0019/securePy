#!/usr/bin/env python3
"""Setup script for SecurePy."""

from setuptools import setup, find_packages

setup(
    name="securepy",
    version="1.0.0",
    description="A powerful static security analyzer for Python code",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="SecurePy Contributors",
    url="https://github.com/rtl0019/securePy",
    license="MIT",
    packages=find_packages(),
    python_requires=">=3.10",
    entry_points={
        "console_scripts": [
            "securepy=securepy.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Topic :: Security",
    ],
)
