"""VeriForge SDK — Unified developer kit for the entire VeriForge ecosystem."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="veriforge-sdk",
    version="1.0.0",
    author="CSP7211",
    author_email="csp7211@veriforge.dev",
    description="Unified SDK for the VeriForge security ecosystem",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/CSP7211/VeriForge",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.10",
    install_requires=[
        "cryptography>=41.0.0",
        "jinja2>=3.1.0",
        "requests>=2.31.0",
        "pydantic>=2.0.0",
        "typing-extensions>=4.8.0",
    ],
    extras_require={
        "dev": ["pytest>=7.4.0", "pytest-asyncio>=0.21.0", "black>=23.0.0", "mypy>=1.5.0"],
        "full": [
            "veriforge-red>=1.0.0",
            "vericlaw>=0.5.0",
            "veriforge-dsl>=0.5.0",
            "veriforge-mcp>=0.5.0",
            "veriforge-swarm>=0.5.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "veriforge-sdk=veriforge_sdk.cli:main",
        ],
    },
)
