"""Setup configuration for VeriForge Red."""

from pathlib import Path

from setuptools import find_packages, setup

README = (Path(__file__).parent / "README.md").read_text(encoding="utf-8")

setup(
    name="veriforge-red",
    version="1.0.0",
    author="VeriForge Security",
    author_email="security@veriforge.dev",
    description="Local-first security sentinel — scans code, protects privacy, quarantines threats",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/veriforge/veriforge-red",
    packages=find_packages(exclude=["tests", "tests.*", "build"]),
    package_data={
        "veriforge_red": ["website/*.html", "website/*.css", "website/*.js",
                         "mobile/*.kv", "build/*.spec", "build/*.iss"],
    },
    include_package_data=True,
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: End Users/Desktop",
        "Topic :: Security",
        "Topic :: System :: Monitoring",
        "Topic :: Software Development :: Quality Assurance",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Environment :: Win32 (MS Windows)",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.10",
    install_requires=[
        "jinja2>=3.1.0",
        "cryptography>=42.0.0",
        "watchdog>=4.0.0",
    ],
    extras_require={
        "windows": [
            "pystray>=0.19.0",
            "pywin32>=306; platform_system=='Windows'",
            "WMI>=1.5.1; platform_system=='Windows'",
            "plyer>=2.1.0",
        ],
        "android": [
            "kivy>=2.3.0",
            "pyjnius>=1.6.0",
            "plyer>=2.1.0",
        ],
        "dev": [
            "pytest>=8.0.0",
            "pytest-cov>=5.0.0",
            "black>=24.0.0",
            "mypy>=1.10.0",
            "bandit[toml]>=1.7.0",
            "pyinstaller>=6.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "veriforge-red=veriforge_red.core.engine:main",
        ],
        "gui_scripts": [
            "veriforge-red-gui=veriforge_red.desktop.__main__:main",
        ],
    },
    project_urls={
        "Bug Reports": "https://github.com/veriforge/veriforge-red/issues",
        "Source": "https://github.com/veriforge/veriforge-red",
        "Website": "https://veriforge.dev/red",
    },
)
