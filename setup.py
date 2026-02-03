from setuptools import setup, find_packages

setup(
    name="chrome-extension-security-analyzer",
    version="0.1.0",
    description="Static and dynamic security analysis tool for Chrome extensions",
    author="debarshi17",
    author_email="your-email@example.com",
    url="https://github.com/debarshi17/chrome-extension-security-analyzer",
    packages=find_packages(),
    install_requires=[
        "requests>=2.31.0",
        "beautifulsoup4>=4.12.2",
        "pyyaml>=6.0.1",
        "fastapi>=0.109.0",
        "uvicorn>=0.27.0",
        "python-multipart>=0.0.6",
        "sqlalchemy>=2.0.25",
        "tqdm>=4.66.1",
        "colorama>=0.4.6",
        "python-dotenv>=1.0.0",
        "jinja2>=3.1.2",
        "markdown>=3.5.1",
        "esprima>=4.0.1",
    ],
    python_requires=">=3.9",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.9",
    ],
)