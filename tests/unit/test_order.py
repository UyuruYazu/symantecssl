from __future__ import absolute_import, division, print_function
from mock import patch
from lxml import etree

import pytest

from symantecssl.order import FailedRequest, post_request, post_request_treq
from symantecssl.request_models import GetModifiedOrderRequest
from tests.unit import utils as test_utils


class TestPostRequest(object):

    @patch("requests.post")
    def test_successful_post_request(self, mocked_post):

        endpoint = "http://www.example.com/"
        request_model = GetModifiedOrderRequest()
        credentials = {
            "partner_code": "123456",
            "username": "Krieg",
            "password": "TrainConductor"
        }
        response = etree.tostring(
            test_utils.create_node_from_file('get_order_by_poid.xml')
        )
        mocked_post.return_value.status_code = 200
        mocked_post.return_value.content = response

        response = post_request(
            endpoint, request_model, credentials
        )

        detail = response.model[0]

        assert detail.organization_contacts.admin.email == (
            "administrator@example.com"
        )
        assert detail.organization_info.city == "City"
        assert detail.organization_info.country == "US"
        assert detail.status_code == "ORDER_COMPLETE"

    @patch("requests.post")
    def test_bad_response(self, mocked_post):

        endpoint = "http://www.example.com/"
        request_model = GetModifiedOrderRequest()
        credentials = {
            "partner_code": "123456",
            "username": "Krieg",
            "password": "TrainConductor"
        }

        mocked_post.return_value.status_code = 500
        with pytest.raises(FailedRequest):
            post_request(
                endpoint, request_model, credentials
            )


class TestTreqRequest(object):

    def test_successful_post_request(self):
        pytest.importorskip("treq")
        from treq.testing import (StubTreq,
                                  StringStubbingResource,
                                  RequestSequence)
        credentials = {
            "partner_code": "123456",
            "username": "Krieg",
            "password": "TrainConductor"
        }
        errors = []
        from mock import ANY
        sequence_stubs = RequestSequence(
            [((ANY, ANY, ANY, ANY, ANY),
              (200, {}, etree.tostring(
                  test_utils.create_node_from_file('get_order_by_poid.xml')
              )))],
            errors.append
        )
        stub_treq = StubTreq(StringStubbingResource(sequence_stubs))
        with sequence_stubs.consume(errors.append):
            d = post_request_treq(stub_treq,
                                  "https://symantec.endpoint.example.com",
                                  GetModifiedOrderRequest(),
                                  credentials)
            responses = []
            d.addCallback(responses.append)
            d.addErrback(errors.append)
            assert len(responses) == 1
        assert errors == []
