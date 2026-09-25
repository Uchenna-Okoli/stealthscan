from setuptools import setup, find_packages

setup(
    name="stealthscan",
    version="0.1.0",
    packages=find_packages(),
    install_requires=["python-nmap>=0.7.1", "requests>=2.28.0"],
    entry_points={"console_scripts": ["stealthscan=stealthscan.cli:main"]},
    python_requires=">=3.9",
)