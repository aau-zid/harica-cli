#!/usr/bin/env python3
#########
### aau cert manager script for harica 
#
### version: v3.8
#
### by Martin Schrott <martin.schrott@aau.at>
#########

import argparse
import logging
import requests
import json
import time
import os
import pyotp
import yaml
import socket
import ssl
import subprocess
import glob
from bs4 import BeautifulSoup
from OpenSSL import crypto
from datetime import datetime
from requests_toolbelt.multipart.encoder import MultipartEncoder
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography.x509.extensions import ExtensionNotFound
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization.pkcs7 import load_pem_pkcs7_certificates
from tabulate import tabulate
import smtplib
from email.message import EmailMessage
import secrets
import string
import hashlib
from cryptography.x509.oid import ExtensionOID

### config
# root ca cert url
rootcertURL = "https://repo.harica.gr/certs/HARICA-TLS-Root-2021-RSA.pem"
LOCAL_rootcertFILENAME = "rootCA.crt"
# HARICA API Base URL
#BASE_URL = "https://cm-stg.harica.gr" # staging
BASE_URL = "https://cm.harica.gr" #productive

# Logging Setup
logger = logging.getLogger("harica-cli")
c_handler = logging.StreamHandler()
c_handler.setLevel(logging.INFO)
c_format = logging.Formatter('%(levelname)s: %(message)s')
c_handler.setFormatter(c_format)
logger.addHandler(c_handler)
logger.setLevel(logging.INFO)


def generate_secure_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(characters) for _ in range(length))


def download_cert(url):
    response = requests.get(url)
    response.raise_for_status()
    return response.content

def file_hash(filepath):
    if not os.path.exists(filepath):
        return None
    with open(filepath, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

def content_hash(content):
    return hashlib.sha256(content).hexdigest()

def get_ski(cert):
    try:
        # Zugriff auf den Subject Key Identifier (SKI)
        ski_extension = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
        ski = ski_extension.value
        # Zugriff auf den key_identifier und Ausgabe als hexadezimale Zeichenkette
        ski_key_identifier = ski.key_identifier.hex()  # Umwandlung von bytes zu hex-String
        return ski_key_identifier
    except Exception as e:
        logger.error(f"Fehler beim Extrahieren des SKI: {e}")
        return None

def get_aki(cert):
    try:
        # Zugriff auf den Authority Key Identifier (AKI)
        aki_extension = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
        aki = aki_extension.value
        # Zugriff auf den key_identifier und Ausgabe als hexadezimale Zeichenkette
        aki_key_identifier = aki.key_identifier.hex()  # Umwandlung von bytes zu hex-String
        return aki_key_identifier
    except Exception as e:
        logger.error(f"Fehler beim Extrahieren des AKI: {e}")
        return None

def sort_cert_chain(certificates):
    # Map SKI → cert
    ski_map = {get_ski(cert): cert for cert in certificates}

    # Map AKI → cert (um später die Kette aufbauen zu können)
    aki_map = {get_aki(cert): cert for cert in certificates if get_aki(cert) is not None}

    # Finde das Root-Zertifikat: Es hat keinen AKI oder einen AKI, der in keinem SKI vorkommt
    root = None
    for cert in certificates:
        aki = get_aki(cert)
        if aki and aki not in ski_map:  # Kein SKI für den AKI
            root = cert
            break

    if not root:
        logger.error("Root-Zertifikat konnte nicht eindeutig bestimmt werden. Zertifikate werden nicht sortiert!")
        return certificates

    # Baue die Kette vom Root bis zum Leaf
    sorted_certs = [root]
    current = root

    while True:
        current_ski = get_ski(current)  # Holen des SKI des aktuellen Zertifikats
        next_cert = aki_map.get(current_ski)  # Holen des nächsten Zertifikats, basierend auf dem AKI
        if not next_cert or next_cert in sorted_certs:
            break
        sorted_certs.append(next_cert)
        current = next_cert

    # Umkehren der Liste, um die Kette vom Leaf bis zum Root anzuzeigen
    sorted_certs.reverse()
    return sorted_certs

def update_rootcert_if_changed(s, URL, FILE):
    LOCAL_FILE = f"{s.my_args.path_certs}/{FILE}"
    try:
        remote_content = download_cert(URL)
        remote_hash = content_hash(remote_content)
        local_hash = file_hash(LOCAL_FILE)

        if remote_hash != local_hash:
            with open(LOCAL_FILE, "wb") as f:
                f.write(remote_content)
            logger.info("root ca cert was updated")
        else:
            logger.debug("root ca cert file has not changed")
    except Exception as e:
        logger.error(f"error fetching root ca cert: {e}")

def send_cert_via_email(s, cert_name, email):
        # load cert to send via email
        cert_path = f"./{s.my_args.path_certs}/{cert_name}.pkcs7"
        if os.path.exists(cert_path):
            with open(cert_path, "r", encoding="utf-8") as f:
                cert_pkcs7 = f.read().strip()
        else:
            logger.error(f"error loading cert")
            return False

        email = None
        #check if email is stored in a file
        email_path = f"./{s.my_args.path_certs}/{cert_name}.email"
        if os.path.exists(email_path):
            with open(email_path, "r", encoding="utf-8") as f:
                email = f.read().strip()
        # if email was specified as parameter override file stores and save along with the cert
        if s.my_args.email:
            email = s.my_args.email
            with open(email_path, "w", encoding="utf-8") as f:
                f.write(email)
        # send email if specified
        if email:
            emailText = f"""\
Hallo,

Im Anhang befindet sich das angeforderte Zertifikat für {cert_name}.
    
    Bei weiteren Fragen steht der IT Servicedesk gerne zur Verfügung!
            """
            subject = f"Zertifikat für {cert_name}"
            send_email(s, email, subject, emailText, cert_pkcs7, "pkcs7",cert_name)
        else:
            logger.error(f"error sending mail - no email address available")
            return False

def send_email(s, email, subject, emailText, file=None, filetype="zip", filename=None):
# E-Mail vorbereiten
    logger.debug(f"sending mail to {email}: subject: {subject}, text: {emailText} ...")
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = s.my_args.mail_sender
    msg['To'] = email
    msg.set_content(emailText)

    # Anhang hinzufügen
    if file:
        if not filename:
            filename = email
        logger.debug(f"adding file to mail: {filename}.{filetype}:\n{file}")
        # String in Bytes umwandeln
        if not isinstance(file, bytes):
            file_bytes = file.encode('utf-8')
        else:
            file_bytes = file
        msg.add_attachment(file_bytes, maintype='application', subtype=filetype, filename=f"{filename}.{filetype}")

        # Anhang 2: Lokales Root-Zertifikat hinzufügen
        rootcert_path = f"./{s.my_args.path_certs}/{s.my_args.rootcert}"
        if rootcert_path and os.path.isfile(rootcert_path):
            with open(rootcert_path, "rb") as f:
                rootcert_data = f.read()
                cert_filename = os.path.basename(rootcert_path)
                logger.debug(f"adding root certificate to mail: {cert_filename}")
                msg.add_attachment(rootcert_data, maintype='application', subtype='octet-stream', filename=cert_filename)
        else:
            logger.warning(f"Root certificate file not found or invalid: {rootcert_path}")

        logger.debug("sending mail ...")
    # E-Mail versenden
    with smtplib.SMTP(s.my_args.smtp_server) as server:
        server.starttls()
        server.login(s.my_args.smtp_user, s.my_args.smtp_password)
        server.send_message(msg)

    logger.info(f"Email including cert for {filename} successfully send to {email}.")

def write_certs(s, cert_name, cert_pem, cert_pkcs7):
    # PKCS7 Zertifikate laden
    certificates = load_pem_pkcs7_certificates(cert_pkcs7.encode())
    sorted_certs = sort_cert_chain(certificates)

    # leave und combined CRT erstellen
    combined_crt = ""
    leave_crt = ""
    for cert in sorted_certs:
        cert_pem = cert.public_bytes(Encoding.PEM).decode("utf-8")    
        # BEGIN/END-Zeilen entfernen
        cert_body = cert_pem.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "")
        cert_body = cert_body.strip().replace("\n", "")  # Alle Leerzeilen und Zeilenumbrüche entfernen
        # Sauber mit 64 Zeichen pro Zeile formatieren und wieder BEGIN/END setzen
        cert_clean = "-----BEGIN CERTIFICATE-----\n"
        cert_clean += "\n".join(cert_body[i:i+64] for i in range(0, len(cert_body), 64))
        cert_clean += "\n-----END CERTIFICATE-----\n"
        combined_crt += cert_clean
        # first cert is leave cert
        if leave_crt == "":
            leave_crt = cert_clean

    try:
        #save pkcs7 file
        with open(f"./{s.my_args.path_certs}/{cert_name}.pkcs7", "w") as f:
            f.write(cert_pkcs7)

        # leave cert speichern
        with open(f"./{s.my_args.path_certs}/{cert_name}.crt", "w") as f:
            f.write(leave_crt)

        # combined cert speichern
        with open(f"./{s.my_args.path_certs}/{cert_name}.combined.crt", "w") as f:
            f.write(combined_crt)
        
        # Root-Zertifikat laden und .fullchain.crt schreiben
        fullchain_path = f"./{s.my_args.path_certs}/{cert_name}.fullchain.crt"
        root_path = f"./{s.my_args.path_certs}/{s.my_args.rootcert}"
        if os.path.exists(root_path):
            with open(root_path, "r") as f:
                root_crt = f.read()

            with open(fullchain_path, "w") as f:
                f.write(combined_crt)   # Intermediates
                f.write(root_crt)       # Root
        else:
            logger.warning(f"Root-cert {root_path} not found. .fullchain.crt cannot be created.")

        # cert chain speichern
        with open(f"./{s.my_args.path_certs}/{cert_name}.chain.crt", "w") as f:
            f.write(cert_pem)

        return True  # Alles erfolgreich
    except Exception as e:
        logger.error(f"Fehler beim Speichern: {e}")
        return False  # Fehlerfall

def generate_otp(secret):
    totp = pyotp.TOTP(secret)
    return totp.now()


def get_RequestVerificationToken(s,):
    # Get __RequestVerificationToken for login
    apiform = s.get(BASE_URL)
    soup = BeautifulSoup(apiform.text, 'html.parser')
    verify_token = soup.find('input', {"name":"__RequestVerificationToken"})['value']
    logger.debug(f"verify_token: {verify_token}")
    return verify_token

def login_mfa(s, email, password, otp_secret):
    otp = generate_otp(otp_secret)
    url = f"{BASE_URL}/api/User/Login2FA"
    payload = {"email": email, "password": password, "token": otp}
    logger.debug(f"Logging in with: {payload} at url: {url}")
    # get_RequestVerificationToken
    verify_token = get_RequestVerificationToken(s)
    s.headers = {
        "RequestVerificationToken": verify_token,
        "Content-Type":"application/json"
    }
    # Get auth token and set to header
    auth_resp = s.post(url, json=payload)
    auth_token = auth_resp.text
    logger.debug(f"auth token: {auth_token}")
    s.headers["Authorization"] = auth_token
    # Get new verify token
    verify_token = get_RequestVerificationToken(s)
    logger.debug(f"new verify_token: {verify_token}")
    s.headers["RequestVerificationToken"] = verify_token
    # Make API calls to list domains
    #groups = s.post(API_GROUPS, json={'key':'', 'value':''})
    return s.headers

def check_domain_organization(s, cn, alt_names=[]):
    url = f"{BASE_URL}/api/ServerCertificate/CheckMachingOrganization"
    domains = format_request_domains(cn, alt_names)    
    logger.debug(f"request organisation: domains: {domains} headers: {s.headers}")

    try:
        response = s.post(url, json=domains)
        response.raise_for_status()
    except requests.exceptions.HTTPError as e:
        logger.error(f"HTTPError: {e}")
        logger.error(f"{response.text}")
        exit(1)  # Beendet das Skript bei einem Fehler
    organizations = response.json()
    logger.debug(f"org_info: {organizations} ") 
    if not organizations:
        raise ValueError("No available organization for this domain list")
    if len(organizations) > 1:
        raise ValueError("Multiple organizations found.'")
    return organizations[0]

def build_organization_dn(organization):
    # Build the organization DN (Distinguished Name)
    orgDN = f"OrganizationId:{organization.get('id')}"
    if organization.get("country"):
        orgDN += "&C:" + organization["country"]
    if organization.get("state"):
        orgDN += "&ST:" + organization["state"]
    if organization.get("locality"):
        orgDN += "&L:" + organization["locality"]
    if organization.get("organizationName"):
        orgDN += "&O:" + organization["organizationName"]
    if organization.get("organizationUnitName"):
        orgDN += "&OU:" + organization["organizationUnitName"]

    logger.debug(f"Organisation DN: {orgDN}")
    return orgDN


def validate_transaction(s, transaction_id, validator_email, validator_password, validator_otp_secret):
        url = f"{BASE_URL}/api/OrganizationValidatorSSL/UpdateReviews"

        s.close()
        s = requests.Session()
        try:
            s.headers = login_mfa(s, validator_email, validator_password, validator_otp_secret)
        except:
            logger.error(f"Could not login during validate.")
            return None

        # output user info
        user_info = get_user_info(s)
        logger.debug(f"changed to validation user: {user_info}")

        # get transactions pending
        transactions = get_pending_certs(s)
        # Initialize a list to store reviews to be processed
        reviews = []

        # Iterate through the transactions to find the matching certificate
        for transaction in transactions:
            if transaction.get("transactionId") == transaction_id:

                # Extract the reviews for the matching certificate transaction
                review_dtos = transaction.get("reviewGetDTOs", [])
                for rev in review_dtos:
                    if not rev.get("isReviewed") and rev.get("reviewId") and "reviewValue" in rev:
                        reviews.append((rev["reviewId"], rev["reviewValue"]))

        # Check if there are reviews to process
        if not reviews:
            logger.warning(f"No available reviews for transaction with ID {transaction_id}")
            return False

        # correct headers for multipart post
        s.headers["Content-Type"] = None

        # Perform the review process for each review found
        for review_id, review_value in reviews:
            # Prepare the payload for submitting the review
            review_payload = {
                "reviewId": (None, review_id),
                "isValid": (None, "true"),
                "informApplicant": (None, "true"),
                "reviewMessage": (None, "Automatic Review by IT-Portal"),
                "reviewValue": (None, review_value),
            }

            # Make the POST request to update the review status
            response = s.post(url, files=review_payload)
            logger.debug(f"Response Status Code: {response.status_code}")
            logger.debug(f"Response Headers: {response.headers}")
            logger.debug(f"Response Content: {response.content}")
            logger.debug(f"Full Response Object: {vars(response)}")

            # Check if the review submission was successful
            if response.status_code != 200:
                logger.error(f"Failed to approve review {review_id} for transaction {transaction_id}")
                return False

        # Return True if all reviews were successfully processed
        return True

def request_ssl_certificate(s, csr, organization_id, cn, alt_names):
    url = f"{BASE_URL}/api/ServerCertificate/RequestServerCertificate"
    domains = format_request_domains(cn, alt_names)    
# check if same request already pending
    transactions = get_pending_certs(s)
    for item in transactions:
        transaction_domains = ",".join([domain["fqdn"] for domain in item["domains"]])
        if cn in transaction_domains:
            logger.error(f"there are pending certificates for the domain {cn}:\nuser requesting: {item["user"]}  \ntransaction id: {item["transactionId"]}\nplease cancel or validate this transaction first!")
            exit(1)  # Beendet das Skript bei einem Fehler
    payload = {
        "domains": (None, json.dumps(domains)),
        "domainsString": (None, json.dumps(domains)),
        "duration": (None, "1"),
        "csr": (None, csr.public_bytes(serialization.Encoding.PEM).decode()),
        "transactionType": (None, "OV"),
        "friendlyName": (None, cn),
        "isManualCSR": (None, "true"),
        "consentSameKey": (None, "true"),
        "organizationDN": (None, organization_id)
    }
    s.headers["Content-Type"] = None
    logger.debug(f"requesting cert: {payload} \n headers: {s.headers}")
    try:
        response = s.post(url, files=payload)
        logger.debug(f"Response Status Code: {response.status_code}")
        logger.debug(f"Response Headers: {response.headers}")
        logger.debug(f"Response Content: {response.content}")
        logger.debug(f"Full Response Object: {vars(response)}")
        logger.debug(f"Cookies: {response.cookies}")
        logger.debug(f"Raw response content: {response.text}")
        response.raise_for_status()
    except requests.exceptions.HTTPError as e:
        logger.error(f"HTTPError: {e}")
        logger.error(f"{response.text}")
        exit(1)  # Beendet das Skript bei einem Fehler
    return response.json()["id"]


def get_user_info(s):
    url = f"{BASE_URL}/api/User/GetCurrentUser"
    payload = {}
    try:
        response = s.post(url, json=payload)
        response.raise_for_status()
    except requests.exceptions.HTTPError as e:
        logger.error(f"HTTPError: {e}")
        logger.error(f"{response.text}")
        exit(1)  # Beendet das Skript bei einem Fehler
    return response.text

def revoke_cert(s, transaction_id):
        url = f"{BASE_URL}/api/OrganizationValidatorSSL/RevokeCertificate"

        payload = {
            "transactionId": transaction_id,
            # Name seems to be always 4.9.1.1.1.1
            "name": "4.9.1.1.1.1",
            "notes": f"Revoked via harica-cli ",
            "message": "",
        }

        # Make the POST request to revoke the transaction
        try:
            response = s.post(url, json=payload)
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            logger.error(f"HTTPError: {e}")
            logger.error(f"{response.text}")
            exit(1)  # Beendet das Skript bei einem Fehler

        # Check if the revokation was successful
        return response.status_code == 200


def cancel_transaction(s, transaction_id):
        url = f"{BASE_URL}/api/Transaction/CancelTransaction"
        # Prepare the payload for cancelling the transaction
        cancel_payload = {"id": transaction_id}

        # Make the POST request to cancel the transaction
        try:
            response = s.post(url, json=cancel_payload)
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            logger.error(f"HTTPError: {e}")
            logger.error(f"{response.text}")
            exit(1)  # Beendet das Skript bei einem Fehler

        # Check if the cancellation was successful
        return response.status_code == 200

def get_active_certs(s, start_index: int = 0):
        url = f"{BASE_URL}/api/OrganizationValidatorSSL/GetSSLTransactions"
        status = "Completed"

        json_payload = {"startIndex": start_index, "status": status, "filterPostDTOs": []}

        try:
            data = s.post(url, json=json_payload)
            data.raise_for_status()
        except requests.exceptions.HTTPError as e:
            logger.error(f"HTTPError: {e}")
            logger.error(f"{data.text}")
            exit(1)  # Beendet das Skript bei einem Fehler

        certs = data.json()
        # Add status to each certificate
#        for cert in certs:
#            cert["status"] = status

#        return json.dumps(certs)
        return certs

def get_pending_certs(s, start_index: int = 0):
        # for valid certs: url = f"{BASE_URL}/api/OrganizationValidatorSSL/GetSSLTransactions"
        url = f"{BASE_URL}/api/OrganizationValidatorSSL/GetSSLReviewableTransactions"
        status = "Pending"
#        status = "Canceled"

        json_payload = {"startIndex": start_index, "status": status, "filterPostDTOs": []}

        try:
            data = s.post(url, json=json_payload)
            data.raise_for_status()
        except requests.exceptions.HTTPError as e:
            logger.error(f"HTTPError: {e}")
            logger.error(f"{data.text}")
            exit(1)  # Beendet das Skript bei einem Fehler

        certs = data.json()
        # Add status to each certificate
#        for cert in certs:
#            cert["status"] = status

#        return json.dumps(certs)
        return certs


def get_certificate(s, cert_id):
    url = f"{BASE_URL}/api/OrganizationAdmin/GetEnterpriseCertificate"
    payload = {"id": cert_id}
    try:
        response = s.post(url, json=payload)
        response.raise_for_status()
    except requests.exceptions.HTTPError as e:
        logger.error(f"HTTPError: {e}")
        logger.error(f"{response.text}")
        exit(1)  # Beendet das Skript bei einem Fehler
    logger.debug(f"cert data: {response.json()} \n\n cert file: {response.json()["certificate"]} \n\n cert name: {response.json()["friendlyName"]} ")
#    cert_name = get_cert_name(response.json()["certificate"])
#    logger.debug(f"cert name: {cert_name}")

    return (response.json()["friendlyName"], response.json()["certificate"], response.json()["pKCS7"])

def get_smime_cert(s, email):
    certs = get_smime_certs(s)
    url = f"{BASE_URL}/api/OrganizationAdmin/GetBulkCertificatesOfAnEntry"
    user_certs = []
    for cert in certs:
        payload = { 'id': cert['id'], }
        try:
            data = s.post(url, json=payload)
            data.raise_for_status()
        except requests.exceptions.HTTPError as e:
            logger.error(f"HTTPError: {e}")
            logger.error(f"{data.text}")
            exit(1)  # Beendet das Skript bei einem Fehler
        bulk_certs = data.json()
        for user_cert in bulk_certs:
            if user_cert['friendlyName'] == email:
                logger.debug(f"s/mime cert: {user_cert['friendlyName']}  | valid till: {user_cert['validTo']} id: {user_cert['id']}")
                user_certs.append([user_cert['friendlyName'], user_cert['validTo'], user_cert['id']])
    return user_certs

def get_smime_certs(s):
    url = f"{BASE_URL}/api/OrganizationAdmin/GetBulkCertificateEntries"
    try:
        data = s.post(url, json={})
        data.raise_for_status()
    except requests.exceptions.HTTPError as e:
        logger.error(f"HTTPError: {e}")
        logger.error(f"{data.text}")
        exit(1)  # Beendet das Skript bei einem Fehler
    certs = data.json()

    logger.debug(f"s/mime certs: {json.dumps(certs)}")
    return certs


def request_smime_cert(s, email):
    url = f"{BASE_URL}/api/OrganizationAdmin/CreateBulkCertificatesSMIME"
    passphrase = generate_secure_password()

    # Extrahiere Given Name und Surname aus der E-Mail
    names, domain= email.split('@')
    gn, sn = names.capitalize().split('.')

    # get org info
    organization = check_domain_organization(s, domain)
    orgDN = build_organization_dn(organization)
    # check if csr exists else create new csr
    csr = None
    if os.path.exists(f"./{s.my_args.path_email_certs}/{email}.csr"):
        csr_path = f"./{s.my_args.path_email_certs}/{email}.csr"
        logger.info(f"csr already exists. Using: {csr_path}")
        # load csr 
        try:
            with open(csr_path, "rb") as f:
                csr = x509.load_pem_x509_csr(f.read(), default_backend())
                cn = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                try:
                    alt_names = [x.value for x in csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value]
                except ExtensionNotFound:
                    logger.debug("SAN-extension altNames not found. use empty array.")
                    alt_names = []
                logger.debug(f"csr info: {cn} {alt_names}") 
        except FileNotFoundError:
            logger.debug("no CSR file available!")

    # CSV erstellen
    csv_content = (
        "FriendlyName,Email,Email2,Email3,GivenName,Surname,PickupPassword,CertType,CSR\n"
        f"{email},{email},,,{gn},{sn},{'' if csr else passphrase},{'natural_legal_lcp' if csr else 'email_only'},{f'\"{csr.public_bytes(serialization.Encoding.PEM).decode()}\"' if csr else ''}\n"
    )

    payload ={
            "groupId": (None, organization.get('id')),
            "csv": ("bulk.csv", csv_content),
    }

    s.headers["Content-Type"] = None
    s.headers["Accept"]= "application/zip"
    logger.debug(f"requesting cert: {payload} \n headers: {s.headers}")
    try:
        response = s.post(url, files=payload)
        logger.debug(f"Response Status Code: {response.status_code}")
        logger.debug(f"Response Headers: {response.headers}")
#        logger.debug(f"Response Content: {response.content}")
#        logger.debug(f"Full Response Object: {vars(response)}")
#        logger.debug(f"Cookies: {response.cookies}")
#        logger.debug(f"Raw response content: {response.text}")
        response.raise_for_status()
    except requests.exceptions.HTTPError as e:
        logger.error(f"HTTPError: {e}")
        logger.error(f"{response.text}")
        exit(1)  # Beendet das Skript bei einem Fehler

    # ZIP-Datei speichern
    zip = response.content
    logger.debug(f"writing zip file: {zip}")
    with open(f"./{s.my_args.path_email_certs}/{email}.zip", "wb") as f:
        f.write(zip)
    # send zip via mail
    emailText = f"""\
Hallo {gn},

Im Anhang befindet sich das angeforderte S/MIME Zertifikat für {email}.
    Das Importpasswort lautet: {passphrase}
    
    Bei weiteren Fragen steht der IT Servicedesk gerne zur Verfügung!
    """
    subject = "S/MIME Zertifikat"
    send_email(s, email, subject, emailText, zip)
    return True

def ensure_directory_exists(path):
    if not os.path.exists(path):
        os.makedirs(path)
        logger.debug(f"created folder '{path}'.")


def run_cmd(cmd, cmd_input=None, check=True, logerror=True, logoutput=False, returncodes=(0,)):
    if logger.level == logging.DEBUG:
        logger.debug(cmd)
        input('--- press enter >>>\n')
    shell = True
    if isinstance(cmd, list):
        shell = False
    cp = subprocess.run(cmd, input=cmd_input, capture_output=True, shell=shell, check=False, text=True)
    if cp.returncode in returncodes and logoutput:
        logger.debug(f'--- stdout ---\n{cp.stdout}\n\n--- stderr ---\n{cp.stderr}')
    if cp.returncode not in returncodes and logerror:
        logger.error(
            f'CalledProcessError: Command {cmd} returned non-zero exit status {cp.returncode}\n--- stdout ---\n{cp.stdout}\n--- stderr ---\n{cp.stderr}')
    if cp.returncode not in returncodes and check:
        raise subprocess.CalledProcessError(cp.returncode, f'{cmd}')
    return cp


def ssh_cmd(cmd, node, user='root', cmd_input=None, check=True, logerror=True, logoutput=False,
            returncodes=(0,), connect_timeout=None):
    ssh_list = ['ssh', '-q', '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null']
    if connect_timeout:
        ssh_list += ['-o', f'ConnectTimeout={connect_timeout}']
    ssh_list.append(f'{user}@{node}')
    ssh = ' '.join(ssh_list)

    if isinstance(cmd, list):
        cmds = ssh_list + cmd
    else:
        cmds = f'{ssh} "{cmd}"'

    return run_cmd(cmds, cmd_input, check, logerror, logoutput, returncodes)


def deploy(s, cert_name, host=None):
    if host:
        hosts = [host]
    else:
        hosts = sorted(set(get_subject_alt_names(s, cert_name)))
    for host in hosts:
        logger.info(f"Deploing cert {cert_name} to host {host}")
        deploy_certificate(s, cert_name, host)

def deploy_certificate(s, cert_name, deployhost):
    scp_cmd = ["scp", "-q", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null"]

    certs = [ f"{cert_name}.crt", f"{cert_name}.combined.crt", f"{cert_name}.key" ]
    for cert in certs:
        if not os.path.exists(f"./{s.my_args.path_certs}/{cert}"):
            logger.error(f"certfile missing: ./{s.my_args.path_certs}/{cert}")
            return

    # check if host can be reached and figure out cert dir
    if ssh_cmd(["exit"], deployhost, connect_timeout=5, check=False).returncode != 0:
        logger.warning(f"host {deployhost} unreachable - skipping deployment!")
        return

    if ssh_cmd(["test", "-d", "/etc/pki/tls"], deployhost, returncodes=(0,1)).returncode == 0:
        certdir = '/etc/pki/tls'
    elif ssh_cmd(["test", "-d", "/etc/ssl"], deployhost, returncodes=(0,1)).returncode == 0:
        certdir = '/etc/ssl'
    else:
        logger.info(f'no cert dir found on host {deployhost} - skipping deployment!')
        return

    for cert in certs:
        if cert.split('.')[-1] == 'crt':
            logger.info(f'scp ./{s.my_args.path_certs}/{cert} to {deployhost}:{certdir}/certs/{cert}')
            run_cmd(scp_cmd + [f"./{s.my_args.path_certs}/{cert}",
                               f"root@{deployhost}:{certdir}/certs/{cert}"])
        elif cert.split('.')[-1] == 'key':
            logger.info(f'scp ./{s.my_args.path_certs}/{cert} to {deployhost}:{certdir}/private/{cert}')
            run_cmd(scp_cmd + [f"./{s.my_args.path_certs}/{cert}",
                               f"root@{deployhost}:{certdir}/private/{cert}"])
            ssh_cmd(["chmod", "640", f"{certdir}/private/{cert}"], deployhost)

    # run /etc/ssl.d scripts
    if not s.my_args.noscripts:
        cp = ssh_cmd('ls /etc/ssl.d/*', deployhost, returncodes=(0,2))
        if cp.returncode == 0:
            # run post deploy scripts from /etc/ssl.d
            for script in cp.stdout.strip().splitlines():
                if ssh_cmd(["test", "-x", script], deployhost, returncodes=(0,1)).returncode == 0:
                    logger.info(f"{deployhost}: executing post deploy script - {script}")
                    ssh_cmd([script], deployhost, check=False)

    # try reloading standard services otherwise
    for service in ["apache2", "httpd", "nginx", "postfix", "squid"]:
        if ssh_cmd(["systemctl", "status", f"{service}.service"], deployhost,
                   check=False, logerror=False).returncode == 0:
            logger.info(f"{deployhost}: reloading {service}.service")
            ssh_cmd(["systemctl", "reload", f"{service}.service"], deployhost, check=False)

    # check for proxmox node
    if ssh_cmd(["test", "-d", "/etc/pve"], deployhost, returncodes=(0,1)).returncode == 0:
        logger.info(f'{deployhost}: proxmox host - reloading pveproxy')
        proxy_key_path = '/etc/pve/local/pveproxy-ssl.key'
        proxy_crt_path = '/etc/pve/local/pveproxy-ssl.pem'
        ssh_cmd(["cp", f"{certdir}/private/{deployhost}.key", proxy_key_path], deployhost)
        ssh_cmd(["cp", f"{certdir}/certs/{deployhost}.combined.crt", proxy_crt_path], deployhost)
        ssh_cmd(["chown", "root:www-data", proxy_key_path], deployhost)
        ssh_cmd(["chmod", "640", proxy_key_path], deployhost)
        ssh_cmd(["chown", "root:www-data", proxy_crt_path], deployhost)
        ssh_cmd(["chmod", "640", proxy_crt_path], deployhost)

        ssh_cmd(["systemctl", "reload", "pveproxy"], deployhost)

    # check for proxmox backup server
    elif ssh_cmd(["test", "-d", "/etc/proxmox-backup"], deployhost, returncodes=(0,1)).returncode == 0:
        logger.info(f'{deployhost}: proxmox backup host - reloading proxmox-backup-proxy')
        proxy_key_path = '/etc/proxmox-backup/proxy.key'
        proxy_crt_path = '/etc/proxmox-backup/proxy.pem'

        ssh_cmd(["cp", f"{certdir}/private/{deployhost}.key", proxy_key_path], deployhost)
        ssh_cmd(["cp", f"{certdir}/certs/{deployhost}.combined.crt", proxy_crt_path], deployhost)
        ssh_cmd(["chown", "root:backup", proxy_key_path], deployhost)
        ssh_cmd(["chmod", "640", proxy_key_path], deployhost)
        ssh_cmd(["chown", "root:backup", proxy_crt_path], deployhost)
        ssh_cmd(["chmod", "640", proxy_crt_path], deployhost)

        ssh_cmd(["systemctl", "reload", "proxmox-backup-proxy"], deployhost)


def request_and_validate_ssl(s, cert_name, alt_names, validator_email, validator_password, validator_otp_secret):
    # get org info
    organization = check_domain_organization(s, cert_name, alt_names)
    orgDN = build_organization_dn(organization)
    # check if csr exists else create new csr
    if os.path.exists(f"./{s.my_args.path_certs}/{cert_name}.csr"):
        csr_path = f"./{s.my_args.path_certs}/{cert_name}.csr"
        logger.info(f"csr already exists. Using: {csr_path}")
    else:
    # create csr
        csr_path = create_csr(s, cn=cert_name, alt_names=alt_names, organization=organization)
    # load csr 
    try:
        with open(csr_path, "rb") as f:
            csr = x509.load_pem_x509_csr(f.read(), default_backend())

            cn = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            try:
                alt_names = [x.value for x in csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value]
            except ExtensionNotFound:
                logger.debug("SAN-extension altNames not found. use empty array.")
                alt_names = []

    except FileNotFoundError:
        logger.error("CSR file not found!")
        exit(1)
    except Exception as e:
        logger.error(f"Error reading CSR file: {e}")
        exit(1)
    logger.debug(f"csr info: {cn} {alt_names}") 

    # request cert
    cert_id = request_ssl_certificate(s, csr, orgDN, cn, alt_names)    
    logger.info(f"Certificate requested. ID: {cert_id}. Awaiting validation...")

    if validate_transaction(s, cert_id, validator_email, validator_password, validator_otp_secret):
        logger.info(f"Certificate {cert_id} validated.\n Fetching certificate...")   
        (cert_name, cert_pem, cert_pkcs7) = get_certificate(s, cert_id)
        if write_certs(s, cert_name, cert_pem, cert_pkcs7):
            logger.info(f"Certificate saved: {cert_name}.crt|.combined.crt|.fullchain.crt|.pkcs7")
        else:
            logger.error(f"Certificate could not be saved: {cert_name}.crt|.combined.crt|.pkcs7")
        # send cert_pkcs7 via email if address was specified  as parameter or stored in the corresponding file
        email = None
        #check if email is stored in a file
        email_path = f"./{s.my_args.path_certs}/{cert_name}.email"
        if os.path.exists(email_path):
            with open(email_path, "r", encoding="utf-8") as f:
                email = f.read().strip()
        # if email was specified as parameter override file stores and save along with the cert
        if s.my_args.email:
            email = s.my_args.email
            with open(email_path, "w", encoding="utf-8") as f:
                f.write(email)
        # send email if specified
        if email:
            emailText = f"""\
Hallo,

Im Anhang befindet sich das angeforderte Zertifikat für {cert_name}.
    
    Bei weiteren Fragen steht der IT Servicedesk gerne zur Verfügung!
            """
            subject = f"Zertifikat für {cert_name}"
            send_email(s, email, subject, emailText, cert_pkcs7, "pkcs7",cert_name)
    else:
        logger.error(f"Certificate validation failed: {cert_name}")

def get_subject_alt_names(s, cert_name):
    try:
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, open(f"./{s.my_args.path_certs}/{cert_name}.crt").read())
    except FileNotFoundError:
        logger.error(f"Certificate {cert_name}.crt not found")
        return []
    
    aliases = []
    for i in range(cert.get_extension_count()):
        ext = cert.get_extension(i)
        if "subjectAltName" in str(ext.get_short_name()):
            aliases = ext.__str__().replace("DNS:", "").split(', ')
    return aliases

def remove_certificate(cert_name, args):
    cert_files = glob.glob(f"./{args.path_certs}/{cert_name}.*")
    if not cert_files:
        logger.error(f"no files for {cert_name} found in {args.path_certs}")
    for cert_file in cert_files:
        os.remove(cert_file)
        logger.info(f"Removed {cert_file}")

    email_cert_files = glob.glob(f"./{args.path_email_certs}/{cert_name}.*")
    if not email_cert_files:
        logger.error(f"no files for {cert_name} found in {args.path_email_certs}")
    for cert_file in email_cert_files:
        os.remove(cert_file)
        logger.info(f"Removed {cert_file}")

def renew_certificate(s, email, password, otp_secret, cert_name, validator_email, validator_password, validator_otp_secret):
    # check if csr exists else create new csr
    if os.path.exists(f"./{s.my_args.path_certs}/{cert_name}.csr"):
        csr_path = f"./{s.my_args.path_certs}/{cert_name}.csr"
        # load csr 
        try:
            with open(csr_path, "rb") as f:
                csr = x509.load_pem_x509_csr(f.read(), default_backend())
                cn = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                try:
                    alt_names = [x.value for x in csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value]
                except ExtensionNotFound:
                    logger.debug("SAN-extension altNames not found. use empty array.")
                    alt_names = []

        except FileNotFoundError:
            logger.error("CSR file not found!")
            exit(1)
        except Exception as e:
            logger.error(f"Error reading CSR file: {e}")
            exit(1)
        logger.debug(f"csr info: {cn} {alt_names}") 
    else:
        logger.error(f"Cannot renew {cert_name} - CSR file not found!")
        exit(1)

#    request_domains = format_request_domains(cn, alt_names)    
    logger.debug(f"csr exists. renewing: {csr_path}")
# get id of current cert
    transactions = get_active_certs(s)
    for item in transactions:
        transaction_id = False
        transaction_domains = ",".join([domain["fqdn"] for domain in item["domains"]])
        transaction_status = item["transactionStatus"]
        logger.debug(f"transaction: {item["transactionId"]} '{transaction_status}'")
        if cn in transaction_domains and transaction_status == "Completed":
            transaction_notes = item["notes"]
            if transaction_notes and "Revoked" in transaction_notes:
                logger.debug(f"Skipping revoked certificate: {item["transactionId"]}")
                continue
            transaction_id = item["transactionId"]
            logger.debug(f"setting transaction_id for {transaction_domains} with notes {transaction_notes} to {item["transactionId"]}")
            break
    if not transaction_id:
        logger.error(f"Currently there are no certs for the domain {cn} to renew!")
        exit(1)

    request_and_validate_ssl(s, cn, alt_names, validator_email, validator_password, validator_otp_secret)


def ssl_expiry_datetime(s, cert_name):
    try:
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, open(f"./{s.my_args.path_certs}/{cert_name}.crt").read())
    except FileNotFoundError:
        logger.error(f"Certificate {cert_name}.crt not found")
        return None
    return cert.get_notAfter().decode("utf-8")

def get_cert_name(cert_pem: str):
    try:
        # Zertifikat aus Variable laden
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)
    except crypto.Error:
        logger.error("Ungültiges Zertifikat")
        return None

    # CN aus dem Zertifikat auslesen
    subject = cert.get_subject()
    common_name = subject.CN

    return common_name
def create_csr(s, cn, alt_names, organization):
        # Generate the private key
        key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())

        # Write the private key to disk
        output_folder = f"./{s.my_args.path_certs}/"
        os.makedirs(output_folder, exist_ok=True)
        key_path = os.path.join(output_folder, f"{cn}.key")
        with open(key_path, "wb") as f:
            f.write(
                key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        logger.debug(f"Private key created in {key_path}")
        os.chmod(key_path, 0o600)

        # Prepare Subject Alternative Names
        subject_alt_names = [cn]
        for item in alt_names:
            if item and item not in subject_alt_names:
                subject_alt_names.append(item)

        # Generate a CSR
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.COUNTRY_NAME, organization["country"].upper()),
                        x509.NameAttribute(NameOID.COMMON_NAME, cn),
                    ]
                )
            )
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(x) for x in subject_alt_names]),
                critical=False,
            )
            .sign(key, hashes.SHA512(), default_backend())
        )

        # Write the CSR to disk
        csr_path = os.path.join(output_folder, f"{cn}.csr")
        with open(csr_path, "wb") as f:
            f.write(csr.public_bytes(serialization.Encoding.PEM))
        logger.debug(f"CSR created in {csr_path}")

        return csr_path

def format_csr(csr):
    csr_obj = crypto.load_certificate_request(crypto.FILETYPE_PEM, csr)
    return crypto.dump_certificate_request(crypto.FILETYPE_PEM, csr_obj).decode()

def format_request_domains(cert_name, alternative_domains=[]):
        logger.debug(f"certificate name: {cert_name}")
        domains = alternative_domains
        domains.append(cert_name)
        logger.debug(f"domains to prepare: {domains}")

        domains_info = []
        processed_domains = set()

        for dom in domains:
            # Check if this is a 'www.' domain and skip if its non-www version has been processed
            base_domain = dom.replace("www.", "")

            if base_domain in processed_domains:
                continue

            domain_info = {
                "isWildcard": "*" in dom,
                "domain": base_domain,
                "includeWWW": f"www.{base_domain}" in domains,
                "isPrevalidated": True,
                "isValid": True,
                "isFreeDomain": True,
                "isFreeDomainDV": True,
                "isFreeDomainEV": False,
                "canRequestOV": True,
                "canRequestEV": False,
                "errorMessage": "",
                "warningMessage": "",
            }
            processed_domains.add(base_domain)
            domains_info.append(domain_info)

        logger.debug(f"domains info: {domains_info}")
        return domains_info

def main():
    parser = argparse.ArgumentParser(description="HARICA CLI for SSL Certificates with Management Features")
    cmd_group = parser.add_mutually_exclusive_group(required=True)
    cmd_group.add_argument("--validate", action="store_true", help="validate SSL Certificate with id --cert ")
    cmd_group.add_argument("--get-smime-cert", action="store_true", help="list s/mime Certificates for email --cert ")
    cmd_group.add_argument("--request-smime-cert", action="store_true", help="request s/mime Certificate for email --cert ")
    cmd_group.add_argument("--get-cert", action="store_true", help="get certificate --cert")
    cmd_group.add_argument("--list-pending", action="store_true", help="list pending transactions")
    cmd_group.add_argument("--revoke", action="store_true", help="revoke cert with id --cert ")
    cmd_group.add_argument("--cancel", action="store_true", help="cancel transaction with id --cert ")
    cmd_group.add_argument("--request-cert", action="store_true", help="Request, validate and download SSL servercertificate for --cert - if --email was specified or cert_name.email exists the cert will be send via mail")
    cmd_group.add_argument("--send-cert", action="store_true", help="send existing SSL servercertificate for --cert - via mail to --email or cert_name.email if exists")
    cmd_group.add_argument("--remove", action="store_true", help="Remove certificate files")
    cmd_group.add_argument("--deploy", action="store_true", help="Deploy certificate --cert to server--host ")
    cmd_group.add_argument("--renew", action="store_true", help="Renew certificate --cert ")
    cmd_group.add_argument("--info", action="store_true", help="Show certificate details of --cert ")
    
    parser.add_argument("--cert", required=True, help="Certificate name, email  or id - as required for the command choosen")
    parser.add_argument("--alias", nargs="*", default=[], help="Additional domain aliases  for SAN")
    parser.add_argument("--path-certs", help="path to certs", default="certs")
    parser.add_argument("--path-email-certs", help="path to s/mime certs", default="email_certs")
    parser.add_argument("--mail-sender", help="sender for mails", default="")
    parser.add_argument("--smtp-server", help="smtp server", default="")
    parser.add_argument("--smtp-user", help="smtp User", default="")
    parser.add_argument("--smtp-password", help="smtp password", default="")
    parser.add_argument("--email", help="User email - if specified server certificates will be send to this address via mail and the address will be stored for future in cert_name.email file")
    parser.add_argument("--admin-email", help="tcs admin email", default="")
    parser.add_argument("--password", help="User password", default="")
    parser.add_argument("--otp-secret", help="OTP Secret for MFA", default="")
    parser.add_argument("--validator-email", help="Validator email", default="")
    parser.add_argument("--validator-password", help="Validator password", default="")
    parser.add_argument("--validator-otp-secret", help="Validator OTP Secret for MFA", default="")
    parser.add_argument("--host", help="Host for deployment (optional, if not given, --cert will be used as host)")
    parser.add_argument('--noscripts', default=False, action='store_true', help='do not execute /etc/ssl.d scripts on destination host after deploy')

    args = parser.parse_args()

    # start session
    s = requests.Session() 
    s.my_args = args
    logger.debug(f"session started: {s}")

# set paths
    ensure_directory_exists(s.my_args.path_certs)
    ensure_directory_exists(s.my_args.path_email_certs)

    # download root ca cert if it has changed
    s.my_args.rootcert = LOCAL_rootcertFILENAME
    update_rootcert_if_changed(s, rootcertURL, LOCAL_rootcertFILENAME)

    # login
    try:
        s.headers = login_mfa(s, args.admin_email, args.password, args.otp_secret)
    except:
        logger.error(f"Could not login during request and validate.")
        return None

    # output user info
    user_info = get_user_info(s)
    logger.debug(f"user: {user_info}")

    #commands
    if args.request_cert:
        request_and_validate_ssl(s, args.cert, args.alias, args.validator_email, args.validator_password, args.validator_otp_secret)

    if args.send_cert:
        send_cert_via_email(s, args.cert, args.alias)

    if args.revoke:
        if revoke_cert(s, args.cert):
            logger.info(f"revoked cert: {args.cert}")
        else:
            logger.info(f"Could not revoke cert: {args.cert}")

    if args.cancel:
        if cancel_transaction(s, args.cert):
            logger.info(f"canceled transaction: {args.cert}")
        else:
            logger.info(f"Could not cancel transaction: {args.cert}")

    if args.get_smime_cert:
        certs = get_smime_cert(s, args.cert)
        logger.info(
            "\n" + tabulate(
                certs,
                headers=[
                    "email",
                    "valid till",
                    "id",
                ],
            )
        )

    if args.request_smime_cert:
        result = request_smime_cert(s, args.cert)
        logger.debug(f"s/mime certificates: {result}")

    if args.list_pending:
        transactions = get_pending_certs(s)
        logger.debug(f"pending certificates: {transactions}")
        data = []
        for item in transactions:
            data.append(
                [
                    item["transactionId"],
                    ",".join([domain["fqdn"] for domain in item["domains"]]),
                    item["transactionStatus"],
                    item["user"],
                ]
            )

        # Log the data in a tabular format using tabulate
        logger.info(
            "\n" + tabulate(
                data,
                headers=[
                    "ID",
                    "CN",
                    "Status",
                    "Requested by",
                ],
            )
        )


    if args.get_cert:
        (cert_name, cert_pem, cert_pkcs7) = get_certificate(s, args.cert)
        if write_certs(s, cert_name, cert_pem, cert_pkcs7):
            logger.info(f"Certificate saved: {cert_name}.crt|.combined.crt|.pkcs7")
        else:
            logger.error(f"Certificate could not be saved: {cert_name}.crt|.combined.crt|.pkcs7")

    if args.validate:
        if validate_transaction(s, args.cert, args.validator_email, args.validator_password, args.validator_otp_secret):
            logger.info(f"validated certificate: {args.cert}")
        else:
            logger.error(f"Could not validate certificate: {args.cert}")

    if args.deploy:
        deploy(s, args.cert, args.host)
    
    if args.renew:
        renew_certificate(s, args.admin_email, args.password, args.otp_secret, args.cert, args.validator_email, args.validator_password, args.validator_otp_secret)
    
    if args.remove:
        remove_certificate(args.cert, args)
    
    if args.info:
        expiry_date = ssl_expiry_datetime(s, args.cert)
        aliases = get_subject_alt_names(s, args.cert)
        if expiry_date:
            expiry_date_nice = datetime.strptime(expiry_date, "%Y%m%d%H%M%SZ").strftime("%d.%m.%Y %H:%M:%S")    
            print(f"{args.cert} expires on {expiry_date_nice}")
            print(f"Domain: {args.cert}")
            print(f"Aliases: {', '.join(aliases)}")
        else:
            print("Certificate not found or could not be read.")

if __name__ == "__main__":
    main()
