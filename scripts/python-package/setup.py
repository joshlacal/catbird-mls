from setuptools import setup, find_packages

setup(
    name="catbird-mls",
    version="0.1.0",
    description="Python bindings for catbird-mls (MLS messaging)",
    packages=find_packages(),
    python_requires=">=3.8",
    package_data={
        "catbird_mls": ["*.dylib", "*.so", "*.dll"],
    },
)
