from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="privacy-protocol-toolkit-p2p",
    version="0.1.0",
    author="Hany Almnaem",
    author_email="",
    description="Privacy protocol toolkit for py-libp2p with real proof exchange (experimental)",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Hany-Almnaem/privacy-protocol-toolkit-p2p",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: System :: Networking",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
    ],
    python_requires=">=3.9",
    install_requires=[
        "libp2p>=0.2.0",
        "trio>=0.27.0",
        "multiaddr>=0.0.9",
        "cbor2>=5.6.0",
        "pynacl>=1.5.0",
        "cryptography>=44.0.0",
        "numpy>=1.24.0",
        "pandas>=2.0.0",
        "click>=8.1.0",
        "rich>=13.0.0",
        "pyyaml>=6.0",
    ],
    extras_require={
        "dev": [
            "pytest>=8.0.0",
            "pytest-trio>=0.8.0",
            "pytest-asyncio>=0.21.0",
            "black>=24.0.0",
            "flake8>=7.0.0",
            "mypy>=1.8.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "privacy-protocol-toolkit-p2p=libp2p_privacy_poc.cli:main",
            "libp2p-privacy=libp2p_privacy_poc.cli:main",
        ],
    },
)
