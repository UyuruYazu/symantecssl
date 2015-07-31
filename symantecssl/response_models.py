from __future__ import absolute_import, division, print_function

from symantecssl import utils
from symantecssl.models import OrderContacts


class OrderDetails(list):

    def __init__(self, details_to_add=[]):
        self.extend(details_to_add)

    @classmethod
    def deserialize(cls, xml_node):
        """ Deserializes order details section in response.

        :param xml_node: XML node to be parsed. Expected to explicitly be
        Order Details XML node.
        :return: details in order detail section.
        """
        details = [OrderDetail.deserialize(node) for node in
                   xml_node.findall('.//m:OrderDetail', utils.NS)]
        return OrderDetails(details)


class OrderDetail(object):

    def __init__(self):
        self.status_code = ''
        self.status_message = ''
        self.certificates = None
        self.organization_info = OrganizationInfo()
        self.organization_contacts = OrderContacts()
        self.modified_events = ModificationEvents()
        self.vulnerabilities = Vulnerabilities()
        self.approver_email = ''

    @classmethod
    def deserialize(cls, xml_node):
        """Deserializes the order detail section in response.

        :param xml_node: XML node to be parsed. Expected to explicitly be
        Order Detail XML node.
        :return: parsed order detail response.
        """
        od = OrderDetail()

        od.status_code = utils.get_element_text(
            xml_node.find('.//m:OrderStatusMinorCode', utils.NS)
        )
        od.status_name = utils.get_element_text(
            xml_node.find('.//m:OrderStatusMinorName', utils.NS)
        )
        od.approver_email = utils.get_element_text(
            xml_node.find('.//m:ApproverEmailAddress', utils.NS)
        )

        # Deserialize Child nodes
        org_info_node = xml_node.find('.//m:OrganizationInfo', utils.NS)
        org_contacts_node = xml_node.find('.//m:OrderContacts', utils.NS)
        od.organization_info = OrganizationInfo.deserialize(org_info_node)
        od.organization_contacts = OrderContacts.deserialize(org_contacts_node)

        mod_events_node = xml_node.find('.//m:ModificationEvents', utils.NS)
        if mod_events_node is not None:
            od.modified_events = (
                ModificationEvents.deserialize(mod_events_node)
            )

        vulnerability_node = xml_node.find('.//m:Vulnerabilities', utils.NS)
        if vulnerability_node is not None:
            od.vulnerabilities = (
                Vulnerabilities.deserialize(vulnerability_node)
            )

        fulfillment_node = xml_node.find('.//m:Fulfillment', utils.NS)
        if fulfillment_node is not None:
            od.certificates = Certificate.deserialize(fulfillment_node)

        return od


class OrganizationInfo(object):

    def __init__(self):
        self.name = ''
        self.city = ''
        # Region is also state
        self.region = ''
        self.country = ''

    @classmethod
    def deserialize(cls, xml_node):
        """Deserializes the organization information section in response.

        :param xml_node: XML node to be parsed. Expected to explicitly be
        Organization Information XML node.
        :return: parsed organization information response.
        """
        org_info = OrganizationInfo()
        org_info.name = utils.get_element_text(
            xml_node.find('.//m:OrganizationName', utils.NS)
        )
        org_info.city = utils.get_element_text(
            xml_node.find('.//m:City', utils.NS)
        )
        org_info.region = utils.get_element_text(
            xml_node.find('.//m:Region', utils.NS)
        )
        org_info.country = utils.get_element_text(
            xml_node.find('.//m:Country', utils.NS)
        )

        return org_info


class CertificateInfo(object):

    def __init__(self):
        self.common_name = ''
        self.status = ''
        self.hash_algorithm = ''
        self.encryption_algorithm = ''

    @classmethod
    def deserialize(cls, xml_node):
        """Deserializes the certificate information section in the response.

        :param xml_node: XML node to be parsed. Expected to explicitly be
        Certificate Information XML node.
        :return: parsed certificate information response.
        """
        cert_info = CertificateInfo()
        cert_info.common_name = utils.get_element_text(
            xml_node.find('.//m:CommonName', utils.NS)
        )
        cert_info.status = utils.get_element_text(
            xml_node.find('.//m:CertificateStatus', utils.NS)
        )
        cert_info.hash_algorithm = utils.get_element_text(
            xml_node.find('.//m:SignatureHashAlgorithm', utils.NS)
        )
        cert_info.encryption_algorithm = utils.get_element_text(
            xml_node.find('.//m:SignatureEncryptionAlgorithm', utils.NS)
        )

        return cert_info


class Certificate(object):

    def __init__(self):
        self.server_cert = ''
        self.intermediates = []

    @classmethod
    def deserialize(cls, xml_node):
        """Deserializes the certificate section in the response.

        :param xml_node:XML node to be parsed. Expected to explicitly be
        Certificates XML node.
        :return: parsed certificate response.
        """
        cert = Certificate()
        cert.server_cert = utils.get_element_text(
            xml_node.find('.//m:ServerCertificate', utils.NS)
        )
        ca_certs = xml_node.find('.//m:CACertificates', utils.NS)

        for x in ca_certs:
            cert.intermediates.append(IntermediateCertificate.deserialize(x))

        return cert


class IntermediateCertificate(object):

    def __init__(self):
        self.type = ''
        self.cert = ''

    @classmethod
    def deserialize(cls, xml_node):
        """Deserializes the intermediate certificates section in the response.

        :param xml_node: XML node to be parsed. Expected to explicitly be
        Intermediate Certificate XML node.
        :return: parsed intermediate certificate response.
        """

        inter_info = IntermediateCertificate()
        inter_info.type = utils.get_element_text(
            xml_node.find('.//m:Type', utils.NS)
        )
        inter_info.cert = utils.get_element_text(
            xml_node.find('.//m:CACert', utils.NS)
        )

        return inter_info


class ModificationEvents(list):

    def __init__(self, details_to_add=[]):
        self.extend(details_to_add)

    @classmethod
    def deserialize(cls, xml_node):
        """Deserializes the modification events section in the response.

        This is the section which holds multiple modification events. It will
        loop through each node found within it and initialize deserialization.

        :param xml_node: XML node to be parsed. Expected to explicitly be
        Modification Events XML node.
        :return: parsed modification events
        response.
        """
        details = [ModificationEvent.deserialize(node) for node in
                   xml_node.findall('.//m:ModificationEvent', utils.NS)]
        return ModificationEvents(details)


class ModificationEvent(object):
    def __init__(self):
        self.event_name = ''
        self.time_stamp = ''
        self.mod_id = ''

    @classmethod
    def deserialize(cls, xml_node):
        """ Deserializes the modification event section in the response.

        :param xml_node: XML node to be parsed. Expected to explicitly be
        Modification Event XML node.
        :return: parsed modification event response.
        """
        me = ModificationEvent()

        me.mod_id = utils.get_element_text(
            xml_node.find('.//m:ModificationEventID', utils.NS)
        )
        me.event_name = utils.get_element_text(
            xml_node.find('.//m:ModificationEventName', utils.NS)
        )
        me.time_stamp = utils.get_element_text(
            xml_node.find('.//m:ModificationTimestamp', utils.NS)
        )

        return me


class Vulnerabilities(list):

    def __init__(self, details_to_add=[]):
        self.extend(details_to_add)

    @classmethod
    def deserialize(cls, xml_node):
        """Deserializes the Vulnerabilities section in the response.

        :param xml_node: XML node to be parsed. Expected to explicitly be
        Vulnerabilities XML node.
        :return: parsed vulnerabilities response.
        """
        details = [Vulnerability.deserialize(node) for node in
                   xml_node.findall('.//m:Vulnerability', utils.NS)]
        return Vulnerabilities(details)


class Vulnerability(object):
    def __init__(self):
        self.severity = ''
        self.number_found = ''

    @classmethod
    def deserialize(cls, xml_node):
        """ Deserializes the vulnerability section in the response.

        :param xml_node: XML node to be parsed. Expected to explicitly be
        Vulnerability XML node.
        :return: parsed vulnerability response.
        """
        vuln = Vulnerability()

        vuln.mod_id = utils.get_element_text(
            xml_node.find('.//m:Severity', utils.NS)
        )
        vuln.event_name = utils.get_element_text(
            xml_node.find('.//m:NumberFound', utils.NS)
        )

        return vuln


class QuickOrderResponse(object):
    def __init__(self):
        self.result = QuickOrderResult()

    @classmethod
    def deserialize(cls, xml_node):
        response = QuickOrderResponse()
        response.result = QuickOrderResult.deserialize(xml_node)
        return response


class QuickOrderResult(object):
    def __init__(self):
        self.order_id = ''
        self.order_response = OrderResponseHeader()

    @classmethod
    def deserialize(cls, xml_node):
        result = QuickOrderResult()
        result.order_id = utils.get_element_text(
            xml_node.find('.//m:GeoTrustOrderID', utils.ONS)
        )
        result.order_response = OrderResponseHeader.deserialize(xml_node)

        return result


class OrderResponseHeader(object):
    def __init__(self):
        self.partner_order_id = ''
        self.success_code = ''
        self.timestamp = ''

    @classmethod
    def deserialize(cls, xml_node):
        order_response = OrderResponseHeader()
        order_response.partner_order_id = utils.get_element_text(
            xml_node.find('.//m:PartnerOrderID', utils.ONS)
        )
        order_response.success_code = utils.get_element_text(
            xml_node.find('.//m:SuccessCode', utils.ONS)
        )
        order_response.timestamp = utils.get_element_text(
            xml_node.find('.//m:Timestamp', utils.ONS)
        )

        return order_response


class ReissueResponse(object):
    def __init__(self):
        self.result = ReissueResult()

    @classmethod
    def deserialize(cls, xml_node):
        """Deserializes the reissue section in the response.

        :param xml_node: XML node to be parsed. Expected to explicitly be
        Reissue Response XML node.
        :return: response. Parsed reissue response.
        """
        response = ReissueResponse()
        response.result = ReissueResult.deserialize(xml_node)
        return response


class ReissueResult(object):
    def __init__(self):
        self.order_response = OrderResponseHeader()

    @classmethod
    def deserialize(cls, xml_node):
        """Deserializes the reissue result section in the response.

        :param xml_node: XML node to be parsed. Expected to explicitly be
        ReissueResult XML node.
        :return: result. Parsed reissue response.
        """
        result = ReissueResult()
        result.order_response = OrderResponseHeader.deserialize(xml_node)
        return result
