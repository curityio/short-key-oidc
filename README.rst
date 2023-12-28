ShortKeyOidc Authenticator Plug-in
===================================

.. image:: https://travis-ci.org/curityio/short-key-oidc-authenticator.svg?branch=dev
     :target: https://travis-ci.org/curityio/short-key-oidc-authenticator

This project provides an Authenticator plug-in for the Curity Identity Server. The plugin is a basic authenticator using an OIDC provider for authentication. This plugin is specifically made to work with OIDC providers that sign their ID token with a key that is too short to be accepted by the built-in OIDC authenticator, but may also serve as an example of how such an authenticator can be implemented.

.. note::
    This authenticator does not implement its own client authentication, meaning that the configured HTTP client must have the Basic authentication scheme enabled, and the provider must support Basic authentication for the token request.


System Requirements
~~~~~~~~~~~~~~~~~~~

* Curity Identity Server 8.6.0 and `its system requirements <https://curity.io/docs/idsvr/latest/system-admin-guide/system-requirements.html>`_ (Older versions may be supported if the SDK version is changed in the pom.xml)

Requirements for Building from Source
"""""""""""""""""""""""""""""""""""""

* Maven 3
* Java JDK v. 8

Compiling the Plug-in from Source
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The source is very easy to compile. To do so from a shell, issue this command: ``mvn package``. The result will be the plugin jar in the `target` folder, as well as the necessary dependencies in `target/dependency`

Installation
~~~~~~~~~~~~

To install this plug-in, compile it from source (as described above). The resulting JAR file as well as the dependencies needs to placed in the directory ``${IDSVR_HOME}/usr/share/plugins/short-key-oidc``. (The name of the last directory, ``short-key-oidc``, which is the plug-in group, is arbitrary and can be anything.) After doing so, the plug-in will become available as soon as the node is restarted.

.. note::

    The JAR file needs to be deployed to each run-time node and the admin node. For simple test deployments where the admin node is a run-time node, the JAR file only needs to be copied to one location.

For a more detailed explanation of installing plug-ins, refer to the `Curity developer guide <https://curity.io/docs/idsvr/latest/developer-guide/plugins/index.html#plugin-installation>`_.


License
~~~~~~~

This plugin and its associated documentation is listed under the `Apache 2 license <LICENSE>`_.

More Information
~~~~~~~~~~~~~~~~

Please visit `curity.io <https://curity.io/>`_ for more information about the Curity Identity Server.

Copyright (C) 2018 Curity AB.
