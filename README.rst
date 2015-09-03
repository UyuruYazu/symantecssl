.. image:: https://travis-ci.org/cloudkeep/symantecssl.svg?branch=master
    :target: https://travis-ci.org/cloudkeep/symantecssl
.. image:: https://coveralls.io/repos/cloudkeep/symantecssl/badge.png
    :target: https://coveralls.io/r/cloudkeep/symantecssl

symantecssl
===========

Supports working with the Symantec SSL service


Discussion
----------

If you run into bugs, you can file them in our `issue tracker`_.


.. _`issue tracker`: https://github.com/cloudkeep/symantecssl/issues


User Guide
----------

Here is a quick guide on how to use this Library successfully.

First, the user must have access to the Symantec API documentation. This library
was written based off of the Symantec API May 2014 documentation and will be
referenced often throughout the code and this documentation.

If you have any questions about our implementation here, please feel free
to ask but the most reliable source of truth is the Symantec API documentation
itself.

UPDATE AS OF AUGUST 6 2015:
Symantec has released their own version of a python library as well as
documentation on the SOAP XML api at the following website:
https://developers.websecurity.symantec.com


The calls currently implemented are as follows:

* Quick Order (QuickOrderRequest)
* Reissue (Reissue)
* Get Modified Orders (GetModifiedOrderRequest)
* Get Order by Partner Order ID (GetOrderByPartnerOrderID)

Please reference each section for more details on how to execute each call.

Post Request
------------

The post request is used to execute an order or query against Symantec's API.

This call requires the following:

* endpoint: an order or query endpoint (can be found in documentation)
* order_or_query_object: an object with required order/query information
  to be translated to SOAP XML and then passed to Symantec's endpoint.
* credentials: a dictionary with required login information to be passed to
  Symantec. (Items are partner_code, username, and password)

.. code-block::

    endpoint = "http://{symantec_endpoint_here}/orders"
    order_or_query_object = QueryObject()
    # Set object values here!
    credentials = {
        'partner_code': # Your partner_code,
        'username': # Your username,
        'password': # Your password
    }

    post_request(endpoint, order_or_query_object, credentials)

Quick Order
-----------

To execute a quick order call the user must set the order parameters.

The order parameters that can be set are as follows:

* CSR (csr)
* Domain Name (domain_name)
* Order Partner Order ID (partner_order_id)
* Renewal Indicator (renewal_indicator)
* Renewal Behavior (renewal_behavior)
* Signature Hash Algorithm (hash_algorithm)
* Special Instructions (special_instructions)
* Valid Period (valid_period)
* Web Server Type (web_server_type)
* Wildcard (wildcard)
* DNS Names (dns_names)

These parameters can be set using the set_order_parameters() call. This
function is available off of the QuickOrderRequest object.

.. code-block::

    quick_order_object = QuickOrderRequest()
    quick_order_object.set_order_parameters(
        csr, domain_name, partner_order_id, renewal_indicator,
        renewal_behavior, hash_algorithm, special_instructions, valid_period,
        web_server_type, wildcard, dns_names
    )
    post_request(order_endpoint, quick_order_object, credentials)

Reissue
-------

To execute a reissue order, the user must have an already existing and
completed certificate order. Reissues also support adding, deleting, and
editing SANs. The order type that was previously ordered must support SAN in
order for one to be added or removed. For further information about the
limitations, consult the Symantec API docs.

The user must set the reissue e-mail address, which must be an admin or
technical contact on record for the existing order.

.. code-block::

    reissue_order_object = Reissue()
    reissue_order_object.add_san(new_san)
    reissue_order_object.delete_san(old_san)
    reissue_order_object.edit_san(old_san, new_san)
    reissue_order_object.reissue_email.reissue_email = admin_contact
    reissue_order_object.set_order_parameters(
        csr, domain_name, partner_order_id, renewal_indicator,
        renewal_behavior, hash_algorithm, special_instructions, valid_period,
        web_server_type, wildcard, dns_names
    )

Get Modified Orders
-------------------

To retrieve modified orders within a determined time period you must set the
date range for the data. The user will be able to edit the query options;
however, all options are defaulted to True so that the user retrieve the most
information. If the user would like to receive less information, you may change
some of the flags to False.

Query options, which are always set to True, are as follows:

* Product Detail
* Contacts
* Payment Info
* Certificate Info
* Fulfillment
* CA Certificates
* PKCS7 Certificate
* Partner Tags
* Auth Comments
* Auth Statuses
* File Auth DV Summary
* Trust Services Summary
* Trust Services Details
* Vulnerability Scan Summary
* Vulnerability Scan Details
* Certificate Algorithm Info

.. code-block::

    get_modified_order_object = GetModifiedOrderRequest()
    get_modified_order_object.set_time_frame(from_date, to_date)
    post_request(query_endpoint, get_modified_order_object, credentials)

Get Order By Partner Order ID
-----------------------------

To retrieve a specific order by partner order ID, the user must set the
partner order ID. The user will be able to edit the query options; however,
all options are defaulted to True so that the user retrieves the most
information. If you would like to receive less information, the user may change
some of the flags to False.

See Get Modified Orders section for details on the query options available.

.. code-block::

    partner_order_id_object = GetOrderByPartnerOrderID()
    partner_order_id_object.set_partner_order_id(partner_order_id)
    post_request(query_endpoint, partner_order_id_object, credentials)

