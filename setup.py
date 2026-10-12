from setuptools import setup, find_packages

setup(
    name="sscan",
    version="0.2.0",
    description="SSCAN — network reconnaissance with vulnerability assessment",
    packages=find_packages(),
    install_requires=[
        "python-nmap>=0.7.1",
        "requests>=2.28.0",
    ],
    entry_points={
        "console_scripts": [
            "sscan=stealthscan.cli:main",
            "stealthscan=stealthscan.cli:main",
        ],
    },
    python_requires=">=3.9",
)