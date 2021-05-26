import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="napalm-aruba-cx",
    version="0.1.4",
    author="Aruba Automation",
    author_email="aruba-automation@hpe.com",
    description="NAPALM drivers for Aruba AOS-CX Switches",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/napalm-automation-community/napalm-aruba-cx",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)
