from setuptools import setup, find_packages

setup(
    name="veriforge",
    version="0.4.0-hardened",
    packages=find_packages(),
    install_requires=["jinja2>=3.1.0", "cryptography>=42.0.0"],
    extras_require={
        "dev": [
            "pytest>=8.0",
            "black>=24.0",
            "mypy>=1.10",
            "bandit[toml]>=1.7",
            "pytest-cov>=5.0",
        ],
    },
    python_requires=">=3.10",
    description="Hardened formal verification platform",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="VeriForge Team",
    url="https://github.com/veriforge/veriforge",
    license="MIT",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    keywords="verification security static-analysis audit compliance",
    entry_points={
        "console_scripts": [
            "veriforge=veriforge.__main__:main",
        ],
    },
)
