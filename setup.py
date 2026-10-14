from setuptools import setup, find_packages

setup(
    name="cyberlaws-guard",
    version="1.0.0",
    description="Marco de seguridad dual-layer para agentes de IA autónomos (AST + Z3 + Docker Seccomp)",
    author="CyberLaws-AI",
    license="MIT",
    py_modules=["cyberlaws_guard", "reference_monitor", "ast_extractor", "agent_executor"],
    python_requires=">=3.10",
    install_requires=[
        "z3-solver>=4.12",
    ],
    entry_points={
        "console_scripts": [
            "cyberlaws-cli=cyberlaws_guard:_cli",
        ],
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.10",
    ],
)
