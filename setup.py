#!/usr/bin/env python3
from pathlib import Path
from setuptools import setup, find_packages

ROOT = Path(__file__).parent
long_description = (ROOT / "README.md").read_text(encoding="utf-8")

setup(
    name="js-extractor",
    version="2.0.0",
    description="Extract, beautify, and analyze all JavaScript from a web page (recon/pentest tool).",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Sobhan",
    license="MIT",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "requests>=2.31.0",
        "beautifulsoup4>=4.12.0",
        "jsbeautifier>=1.15.0",
    ],
    extras_require={
        "dynamic": ["playwright>=1.40.0"],
        "full": ["playwright>=1.40.0"],
        "dev": ["pytest>=7.0"],
    },
    entry_points={
        "console_scripts": [
            "js-extractor=js_extractor.cli:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Intended Audience :: Information Technology",
    ],
)
