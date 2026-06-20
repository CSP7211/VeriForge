"""Setup configuration for VeriForge DSL."""

from setuptools import find_packages, setup

setup(
    name="veriforge_dsl",
    version="0.5.0",
    description="Formal Specification Language for Python -- property-based testing, contracts, and natural-language-to-code pipelines",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="VeriForge Contributors",
    author_email="veriforge@example.com",
    url="https://github.com/veriforge/dsl",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[],
    extras_require={
        "dev": ["pytest>=7.0", "pytest-cov", "black", "mypy", "ruff"],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Testing",
        "Topic :: Software Development :: Quality Assurance",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    entry_points={
        "console_scripts": [
            "veriforge=veriforge_dsl.__main__:main",
        ],
    },
)
