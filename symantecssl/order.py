from __future__ import absolute_import, division, print_function
import requests


from lxml import etree

from symantecssl.request_models import RequestEnvelope as ReqEnv


class FailedRequest(Exception):
    def __init__(self, response):
        super(FailedRequest, self).__init__()
        self.response = response


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
    :param credentials: Symantec specific credentials for orders.
    :return response: deserialized response from API
    """

    request_model.set_credentials(**credentials)
    model = ReqEnv(request_model=request_model)
    serialized_xml = etree.tostring(model.serialize(), pretty_print=True)

    headers = {'Content-Type': 'application/soap+xml'}

    response = requests.post(endpoint, serialized_xml, headers=headers)
    setattr(response, "model", None)

    # Symantec not expected to return 2xx range; only 200
    if response.status_code != 200:
        raise FailedRequest(response)
    xml_root = etree.fromstring(response.content)
    deserialized = request_model.response_model.deserialize(xml_root)
    setattr(response, "model", deserialized)

    return response
