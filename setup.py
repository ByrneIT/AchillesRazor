from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="ics-scanner",
    version="1.0.0",
    author="Your Name",
    description="OT/ICS Security Scanner - Comprehensive ICS security assessment suite",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/ics-scanner",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
    python_requires=">=3.6",
    install_requires=[
        "requests>=2.25.0",
        "dnspython>=2.0.0",
    ],
    entry_points={
        "console_scripts": [
            "ics-scan=ics_scanner.ics_main:main",
        ],
    },
)