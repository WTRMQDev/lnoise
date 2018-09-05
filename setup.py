import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="lnoise",
    version="0.1.0",
    author="Example Author", #TODO insert credentials
    author_email="author@example.com", #TODO insert credentials
    description="Noise Protocol Framework library compatible with bitcoin lightning transport protocol",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/pypa/sampleproject", #TODO insert credentials
    packages=setuptools.find_packages(exclude=["example", ".git"]),
    install_requires=['tlslite', 'secp256k1'],
    classifiers=[
        "Programming Language :: Python :: 3",
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
