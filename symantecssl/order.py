from __future__ import absolute_import, division, print_function
import requests


from lxml import etree

from symantecssl.request_models import RequestEnvelope as ReqEnv


class FailedRequest(Exception):
    def __init__(self, response):
        super(FailedRequest, self).__init__()
        self.response = response


def _prepare_request(request_model, credentials):
    """
    Prepare the request for execution.

    :param request_model: an object with a ``serialize`` method that returns
        some LXML Etrees.
    :param dict credentials: A dictionary containing the following keys:

            - ``partner_code``

            - ``username``

            - ``password``

    :return: a 2-tuple of C{bytes} - the contents of the request and C{dict}
             mapping C{bytes} to C{bytes} - the HTTP headers for the request.
    """
    request_model.set_credentials(**credentials)
    model = ReqEnv(request_model=request_model)
    serialized_xml = etree.tostring(model.serialize(), pretty_print=True)
    headers = {'Content-Type': 'application/soap+xml'}

    return (serialized_xml, headers)


def _parse_response(request_model, response, status_code, response_content):
    """
    Parse a response from Symantec.

    :param request_model: an object with a ``response_model`` attribute,
        representing the request that this response maps to.
    :param response: An HTTP response object; used only to instantiate
        :obj:`FailedRequest`.
    :param int status_code: The HTTP status code of the response.
    :param bytes response_content: The bytes of the response.

    :return: some LXML DOM nodes.
    """
    # Symantec not expected to return 2xx range; only 200
    if status_code != 200:
        raise FailedRequest(response)
    xml_root = etree.fromstring(response_content)
    return request_model.response_model.deserialize(xml_root)


def post_request(endpoint, request_model, credentials):
    """Create a post request against Symantec's SOAPXML API.

    Currently supported Request Models are:
    GetModifiedOrders
    QuickOrderRequest

    note:: the request can take a considerable amount of time if the
    date range covers a large amount of changes.

    note:: credentials should be a dictionary with the following values:

    partner_code
    username
    password

    Access all data from response via models

    :param endpoint: Symantec endpoint to hit directly
    :param request_model: request model instance to initiate call type
    :type request_model: :obj:`symantecssl.request_models.Request`
    :param credentials: Symantec specific credentials for orders.
    :return response: deserialized response from API
    """
    serialized_xml, headers = _prepare_request(request_model, credentials)
    response = requests.post(endpoint, serialized_xml, headers=headers)
    setattr(response, "model", None)
    deserialized = _parse_response(request_model, response,
                                   response.status_code, response.content)
    setattr(response, "model", deserialized)
    return response


def _after(something):
    def decorator(decoratee):
        return something.addCallback(decoratee)
    return decorator


def post_request_treq(treq, endpoint, request_model, credentials):
    """
    Like ``post_request``, but using the Twisted HTTP client in ``treq``.

    :param treq: the ``treq`` module to use; either the treq module itself or
        an HTTPClient with an added ``.content`` attribute like
        ``treq.content``.
    :param text_type endpoint: the URL of the full Symantec endpoint for either
        orders or queries
    :param request_model: the request to issue to symantec.
    :type request_model: :obj:`symantecssl.request_models.Request`

    :return: a Deferred firing with an instance of the appropriate response
             model for ``request_model`` looked up via the ``.response_model``
             attribute on it, or failing with ``FailedRequest``.
    """
    serialized_xml, headers = _prepare_request(request_model, credentials)

    @_after(treq.post(endpoint, serialized_xml, headers=headers))
    def posted(response):
        @_after(treq.content(response))
        def content(response_content):
            deserialized = _parse_response(request_model, response,
                                           response.code, response_content)
            return deserialized
        return content
    return posted
