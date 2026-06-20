"""Setup script for VeriForge Agent Swarm."""

from setuptools import find_packages, setup

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="veriforge-swarm",
    version="0.5.0",
    author="VeriForge Team",
    description="Multi-agent security testing swarm with BFT consensus",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/veriforge/veriforge-swarm",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Software Development :: Testing",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.10",
    install_requires=[],
    extras_require={
        "dev": [
            "pytest>=7.0",
            "pytest-cov>=4.0",
            "mypy>=1.0",
            "ruff>=0.1.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "veriforge-demo=veriforge_swarm.demo:run_all_demos",
        ],
    },
)
