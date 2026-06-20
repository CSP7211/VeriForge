"""Setup configuration for VeriForge Hardened Platform."""

from setuptools import setup, find_packages

setup(
    name="veriforge-hardened",
    version="0.4.0",
    description="Hardened code verification platform with immutable audit trails",
    author="VeriForge Security Team",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "PyJWT>=2.8.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "mypy>=1.5.0",
            "bandit>=1.7.5",
            "safety>=2.3.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "veriforge=veriforge.__main__:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
    ],
)
