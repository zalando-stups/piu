===
Piu
===

.. image:: https://travis-ci.org/zalando-stups/piu.svg?branch=master
   :target: https://travis-ci.org/zalando-stups/piu
   :alt: Build Status

.. image:: https://coveralls.io/repos/zalando-stups/piu/badge.svg
   :target: https://coveralls.io/r/zalando-stups/piu
   :alt: Code Coverage

.. image:: https://pypip.in/download/stups-piu/badge.svg
   :target: https://pypi.python.org/pypi/stups-piu/
   :alt: PyPI Downloads

.. image:: https://pypip.in/version/stups-piu/badge.svg
   :target: https://pypi.python.org/pypi/stups-piu/
   :alt: Latest PyPI version

.. image:: https://pypip.in/license/stups-piu/badge.svg
   :target: https://pypi.python.org/pypi/stups-piu/
   :alt: License

Piu is the command line client for the "even" SSH access granting service.

Installation
============

.. code-block:: bash

    $ sudo pip3 install --upgrade stups-piu

Usage
=====

.. code-block:: bash

    $ piu myuser@myhost my-reason

See the `STUPS documentation on Piu`_ for details.

.. _STUPS documentation on Piu: http://stups.readthedocs.org/en/latest/components/piu.html

Releasing
=========

.. code-block:: bash

    $ ./release.sh <NEW-VERSION>
