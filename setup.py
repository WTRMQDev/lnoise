import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="lnoise",
    version="0.1.1",
    author="Crez Khansick",
    author_email="TetsuwanAtomu@tuta.io",
    description="Noise Protocol Framework library compatible with bitcoin lightning transport protocol",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/WTRMQDev/lnoise",
    packages=setuptools.find_packages(exclude=["example", ".git"]),
    install_requires=['chacha20poly1305', 'secp256k1_zkp'],
    classifiers=[
        "Programming Language :: Python :: 3",
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
