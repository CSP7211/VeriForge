"""Setup configuration for VeriClaw."""

from pathlib import Path

from setuptools import find_packages, setup

README = (Path(__file__).parent / "README.md").read_text(encoding="utf-8")

setup(
    name="vericlaw",
    version="0.5.0",
    author="VeriForge Security",
    author_email="security@veriforge.dev",
    description="Adversarial security testing framework built on VeriForge",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/veriforge/vericlaw",
    packages=find_packages(exclude=["tests", "tests.*"]),
    package_data={
        "vericlaw": ["templates/*.html"],
    },
    include_package_data=True,
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Software Development :: Testing",
        "Topic :: Software Development :: Quality Assurance",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
    ],
    python_requires=">=3.10",
    install_requires=[
        "jinja2>=3.1.0",
    ],
    extras_require={
        "dev": [
            "pytest>=8.0.0",
            "pytest-cov>=5.0.0",
            "black>=24.0.0",
            "mypy>=1.10.0",
            "bandit[toml]>=1.7.0",
            "ruff>=0.5.0",
        ],
        "docs": [
            "mkdocs>=1.6.0",
            "mkdocs-material>=9.5.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "vericlaw=vericlaw.__main__:main",
        ],
    },
    project_urls={
        "Bug Reports": "https://github.com/veriforge/vericlaw/issues",
        "Source": "https://github.com/veriforge/vericlaw",
        "Documentation": "https://docs.veriforge.dev/vericlaw",
    },
)
