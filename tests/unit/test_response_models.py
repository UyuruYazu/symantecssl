from __future__ import absolute_import, division, print_function

from symantecssl import utils
from symantecssl.models import OrderContacts, ContactInfo
from symantecssl.response_models import (
    Certificate, CertificateInfo, IntermediateCertificate, ModificationEvent,
    ModificationEvents, OrganizationInfo, OrderDetail, OrderDetails,
    OrderResponseHeader, QuickOrderResponse, QuickOrderResult, Vulnerabilities,
    ReissueResponse, ReissueResult
)
from tests.unit import utils as test_utils


class TestOrganizationInfo(object):

    def test_deserialize(self):
        node = test_utils.create_node_from_file('organization_info.xml')

        org_info = OrganizationInfo.deserialize(node)

        assert org_info.name == "MyOrg"
        assert org_info.city == "San Antonio"
        assert org_info.region == "Texas"
        assert org_info.country == "US"


class TestOrderContacts(object):

    def test_deserialize(self):
        node = test_utils.create_node_from_file('order_contacts.xml')

        contacts = OrderContacts.deserialize(node)

        assert contacts.admin, ContactInfo
        assert contacts.tech, ContactInfo
        assert contacts.billing, ContactInfo


class TestContactInfo(object):

    def test_deserialize(self):
        node = test_utils.create_node_from_file('contact_info.xml')

        contact = ContactInfo.deserialize(node)

        assert contact.first_name == "John"
        assert contact.last_name == "Doe"
        assert contact.phone == "2103122400"
        assert contact.email == "someone@email.com"
        assert contact.title == "Caesar"


class TestCertificateInfo(object):

    def test_deserialize(self):
        node = test_utils.create_node_from_file('certificate_info.xml')

        certificate_info = CertificateInfo.deserialize(node)
        assert certificate_info.common_name == "example.com"
        assert certificate_info.status == "ACTIVE"
        assert certificate_info.hash_algorithm == "SHA1"
        assert certificate_info.encryption_algorithm == "RSA"


class TestCertificate(object):

    def test_deserialize(self):
        node = test_utils.create_node_from_file('certificate.xml')

        certificate = Certificate.deserialize(node)
        assert certificate.intermediates[0], IntermediateCertificate
        assert certificate.intermediates[1], IntermediateCertificate
        assert certificate.intermediates[2], IntermediateCertificate


class TestIntermediateCertificate(object):

    def test_deserialize(self):
        node = test_utils.create_node_from_file('intermediate_certificate.xml')

        intermediate = IntermediateCertificate.deserialize(node)
        assert intermediate.type == "INTERMEDIATE"
        assert intermediate.cert == """-----BEGIN CERTIFICATE-----
DEF
-----END CERTIFICATE-----
""".rstrip()


class TestModificationEvents(object):

    def test_deserialize(self):
        node = test_utils.create_node_from_file('mod_events.xml')

        modifications = ModificationEvents.deserialize(node)
        assert len(modifications) == 2


class TestModificationEvent(object):

    def test_deserialize(self):
        node = test_utils.create_node_from_file('mod_event.xml')

        event = ModificationEvent.deserialize(node)
        assert event.event_name == "Order Created"
        assert event.time_stamp == "2014-08-05T15:05:33+00:00"
        assert event.mod_id == "21612526"


class TestOrderDetail(object):

    def test_deserialize_with_modification_events(self):
        node = test_utils.create_node_from_file('order_detail.xml')

        order_detail = OrderDetail.deserialize(node)
        assert order_detail.status_code == "ORDER_WAITING_FOR_APPROVAL"
        assert order_detail.status_name == "Order Waiting For Approval"
        assert order_detail.approver_email == "admin@example.com"
        assert order_detail.organization_contacts, OrderContacts
        assert order_detail.organization_info, OrganizationInfo
        assert order_detail.modified_events, ModificationEvents
        assert order_detail.certificates, Certificate

    def test_deserialize_with_vulnerabilities(self):
        node = test_utils.create_node_from_file('order_detail_with_vuln.xml')

        order_detail = OrderDetail.deserialize(node)

        assert order_detail.vulnerabilities, Vulnerabilities

    def test_deserialize_without_modification_events(self):
        node = test_utils.create_node_from_file(
            'order_detail_no_mod_event.xml'
        )
        order_detail = OrderDetail.deserialize(node)
        assert order_detail.status_code == "ORDER_WAITING_FOR_APPROVAL"
        assert order_detail.status_name == "Order Waiting For Approval"
        assert order_detail.approver_email == "admin@example.com"
        assert order_detail.organization_contacts, OrderContacts
        assert order_detail.organization_info, OrganizationInfo

    def test_deserialize_without_fulfillment(self):
        node = test_utils.create_node_from_file('order_detail_no_cert.xml')
        order_detail = OrderDetail.deserialize(node)
        assert order_detail.certificates is None


class TestOrderDetails(object):

    def test_deserialize(self):
        node = test_utils.create_node_from_file('order_details.xml')

        order_details = OrderDetails.deserialize(node)
        assert len(order_details) == 1


class TestGetElementText(object):

    def test_get_element_text_with_none_type(self):
        element = None
        text = utils.get_element_text(element)

        assert text == "None"


class TestQuickOrderResponse(object):

    def test_deserialize(self):
        node = test_utils.create_node_from_file('quick_order_response.xml')

        order_response = QuickOrderResponse.deserialize(node)
        assert type(order_response) == QuickOrderResponse


class TestQuickOrderResult(object):

    def test_deserialize(self):
        node = test_utils.create_node_from_file('quick_order_result.xml')
        order_result = QuickOrderResult.deserialize(node)

        assert order_result.order_id == '1912794'


class TestOrderResponseHeader(object):

    def test_deserialize(self):
        node = test_utils.create_node_from_file('order_response_header.xml')

        response = OrderResponseHeader.deserialize(node)
        assert response.success_code == '0'
        assert response.partner_order_id == '04201988'


class TestReissueResponse(object):

    def test_deserialize(self):
        node = test_utils.create_node_from_file('reissue_response.xml')

        response = ReissueResponse.deserialize(node)
        assert type(response) == ReissueResponse


class TestReissueResult(object):

    def test_deserialize(self):
        node = test_utils.create_node_from_file('reissue_result.xml')

        response = ReissueResult.deserialize(node)
        assert response.order_response.success_code == '0'
