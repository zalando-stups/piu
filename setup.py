#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
import inspect

import setuptools
from setuptools.command.test import test as TestCommand
from setuptools import setup

if sys.version_info < (3, 4, 0):
    sys.stderr.write("FATAL: STUPS Piu needs to be run with Python 3.4+\n")
    sys.exit(1)

__location__ = os.path.join(os.getcwd(), os.path.dirname(inspect.getfile(inspect.currentframe())))


def read_version(package):
    data = {}
    with open(os.path.join(package, "__init__.py"), "r") as fd:
        exec(fd.read(), data)
    return data["__version__"]


NAME = "stups-piu"
MAIN_PACKAGE = "piu"
VERSION = read_version(MAIN_PACKAGE)
DESCRIPTION = 'Command line client for "even" SSH access granting service'
LICENSE = "Apache License 2.0"
URL = "https://github.com/zalando-stups/piu"
AUTHOR = "Henning Jacobs"
EMAIL = "henning.jacobs@zalando.de"

COVERAGE_XML = True
COVERAGE_HTML = False
JUNIT_XML = True

# Add here all kinds of additional classifiers as defined under
# https://pypi.python.org/pypi?%3Aaction=list_classifiers
CLASSIFIERS = [
    "Development Status :: 4 - Beta",
    "Environment :: Console",
    "Intended Audience :: Developers",
    "Intended Audience :: System Administrators",
    "License :: OSI Approved :: Apache Software License",
    "Operating System :: POSIX :: Linux",
    "Programming Language :: Python",
    "Programming Language :: Python :: 3.4",
    "Programming Language :: Python :: Implementation :: CPython",
]

CONSOLE_SCRIPTS = ["piu = piu.cli:main"]


class PyTest(TestCommand):

    user_options = [
        ("cov=", None, "Run coverage"),
        ("cov-xml=", None, "Generate junit xml report"),
        ("cov-html=", None, "Generate junit html report"),
    ]

    def initialize_options(self):
        TestCommand.initialize_options(self)
        self.cov = None
        self.cov_xml = False
        self.cov_html = False

    def finalize_options(self):
        TestCommand.finalize_options(self)
        if self.cov is not None:
            self.cov = ["--cov", self.cov, "--cov-report", "term-missing"]
            if self.cov_xml:
                self.cov.extend(["--cov-report", "xml"])
            if self.cov_html:
                self.cov.extend(["--cov-report", "html"])

    def run_tests(self):
        try:
            import pytest
        except ImportError:
            raise RuntimeError("py.test is not installed, run: pip install pytest")
        params = {"args": self.test_args}
        if self.cov:
            params["args"] += self.cov
        params["args"] += ["--doctest-modules", MAIN_PACKAGE, "-s"]
        errno = pytest.main(**params)
        sys.exit(errno)


def get_install_requirements(path):
    content = open(os.path.join(__location__, path)).read()
    return [req for req in content.split("\\n") if req != ""]


def read(fname):
    return open(os.path.join(__location__, fname), encoding="utf-8").read()


def setup_package():
    # Assemble additional setup commands
    cmdclass = {}
    cmdclass["test"] = PyTest

    # Some helper variables
    version = VERSION

    install_reqs = get_install_requirements("requirements.txt")

    command_options = {"test": {"test_suite": ("setup.py", "tests"), "cov": ("setup.py", MAIN_PACKAGE)}}
    if COVERAGE_XML:
        command_options["test"]["cov_xml"] = "setup.py", True
    if COVERAGE_HTML:
        command_options["test"]["cov_html"] = "setup.py", True

    setup(
        name=NAME,
        version=version,
        url=URL,
        description=DESCRIPTION,
        author=AUTHOR,
        author_email=EMAIL,
        license=LICENSE,
        keywords="aws account saml login federated shibboleth",
        long_description=read("README.rst"),
        classifiers=CLASSIFIERS,
        test_suite="tests",
        packages=setuptools.find_packages(exclude=["tests", "tests.*"]),
        install_requires=install_reqs,
        setup_requires=["six", "black"],
        cmdclass=cmdclass,
        tests_require=["pytest-cov", "pytest"],
        command_options=command_options,
        entry_points={"console_scripts": CONSOLE_SCRIPTS},
    )


if __name__ == "__main__":
    setup_package()
