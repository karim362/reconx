from setuptools import setup, find_packages

setup(
    name="reconx",
    version="3.0.0",
    description="ReconX — Professional Subdomain Reconnaissance Framework",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "requests>=2.31.0",
        "dnspython>=2.4.0",
        "rich>=13.7.0",
        "beautifulsoup4>=4.12.0",
        "lxml>=5.0.0",
        "urllib3>=2.1.0",
        "PyYAML>=6.0",
    ],
    entry_points={
        "console_scripts": [
            "reconx=reconx.cli:main",
        ],
    },
)
