from setuptools import setup, find_packages
setup(
    name="veriforge",
    version="1.0.0",
    description="VeriForge Red",
    author="CSP7211",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=["PyJWT>=2.8.0"],
    extras_require={"dev": ["pytest>=7.0"]},
    entry_points={"console_scripts": ["veriforge=veriforge.cli:main"]},
)
