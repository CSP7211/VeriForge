"""Setup script for veriforge_mcp package."""

from setuptools import setup, find_packages

setup(
    name="veriforge_mcp",
    version="0.5.0",
    description="MCP Server for code verification, compliance, and security scanning",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="VeriForge Team",
    author_email="team@veriforge.dev",
    url="https://github.com/veriforge/veriforge-mcp",
    packages=find_packages(exclude=["tests", "tests.*"]),
    python_requires=">=3.10",
    install_requires=[],
    extras_require={
        "dev": [
            "pytest>=7.0",
            "pytest-cov>=4.0",
            "mypy>=1.5",
            "ruff>=0.1.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "veriforge-mcp=veriforge_mcp.server:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    keywords="mcp llm code-verification security compliance soc2 iso27001 pci-dss",
    license="MIT",
)
