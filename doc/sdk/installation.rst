Library Installation
====================

Prerequisites
*************

* An ePolicy Orchestrator Server with DXL 4.0 (or above) extensions installed

* Python 2.7.9 or higher installed within a Windows or Linux environment 
  (Python 3 is not supported at this time)

* OpenDXL Python Client library installed
   `<https://github.com/opendxl/opendxl-client-python>`_

* The OpenDXL Python Client prerequisites must be satisfied
   `<https://opendxl.github.io/opendxl-client-python/pydoc/installation.html>`_

Installation
************

Use ``pip`` to automatically install the library:

    .. parsed-literal::

        pip install dxlthreateventclient-\ |version|\-py2.7-none-any.whl

Or with:

    .. parsed-literal::

        pip install dxlthreateventclient-\ |version|\.zip

As an alternative (without PIP), unpack the dxlthreateventclient-\ |version|\.zip (located in the lib folder) and run the setup
script:

    .. parsed-literal::

        python setup.py install
