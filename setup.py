from setuptools import setup

setup(
    name="password-strength-analyzer",
    version="1.0.0",
    description="Password Strength Analyzer and Entropy Calculator (Linux CLI)",
    py_modules=["tricky"],
    install_requires=["zxcvbn>=4.4.0"],
    entry_points={"console_scripts": ["tricky=tricky:main"]},
    python_requires=">=3.8",
)
