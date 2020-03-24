===
Più
===

.. image:: https://travis-ci.org/zalando-stups/piu.svg?branch=master
   :target: https://travis-ci.org/zalando-stups/piu
   :alt: Build Status

.. image:: https://coveralls.io/repos/zalando-stups/piu/badge.svg
   :target: https://coveralls.io/r/zalando-stups/piu
   :alt: Code Coverage

.. image:: https://img.shields.io/pypi/dw/stups-piu.svg
   :target: https://pypi.python.org/pypi/stups-piu/
   :alt: PyPI Downloads

.. image:: https://img.shields.io/pypi/v/stups-piu.svg
   :target: https://pypi.python.org/pypi/stups-piu/
   :alt: Latest PyPI version

.. image:: https://img.shields.io/pypi/l/stups-piu.svg
   :target: https://pypi.python.org/pypi/stups-piu/
   :alt: License

Più is the command line client for the "even" SSH access granting service.

Installation
============

.. code-block:: bash

    $ sudo pip3 install --upgrade stups-piu

Usage
=====

.. code-block:: bash

    $ piu myuser@myhost my-reason

See the `STUPS documentation on Più`_ for details.

.. _STUPS documentation on Più: http://stups.readthedocs.org/en/latest/components/piu.html

Running Unit Tests
==================

.. code-block:: bash

    $ python3 setup.py test --cov-html=true

