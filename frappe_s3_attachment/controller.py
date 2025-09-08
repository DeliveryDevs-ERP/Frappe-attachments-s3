from __future__ import unicode_literals

import datetime
import os
import random
import re
import string

import boto3
from botocore.client import Config
from botocore.exceptions import ClientError

import frappe
import magic
from urllib.parse import quote


class S3Operations(object):

    def __init__(self):
        """
        Initialise AWS settings from the Single doctype 'S3 File Attachment'.
        Ensures we will always talk to the bucket's *regional* endpoint.
        """
        self.s3_settings_doc = frappe.get_doc('S3 File Attachment', 'S3 File Attachment')

        # Core settings
        self.BUCKET = self.s3_settings_doc.bucket_name
        self.folder_name = self.s3_settings_doc.folder_name

        # Caches
        self._bucket_region = None
        self._client_cache = {}

        # If the doctype already stores region, cache it (ensure it's correct, e.g., "me-central-1")
        if getattr(self.s3_settings_doc, "region_name", None):
            self._bucket_region = self.s3_settings_doc.region_name.strip()

        # Probe client (global) ONLY to discover bucket region when needed
        probe_kwargs = {"config": Config(signature_version="s3v4")}
        if self.s3_settings_doc.aws_key and self.s3_settings_doc.aws_secret:
            probe_kwargs.update({
                "aws_access_key_id": self.s3_settings_doc.aws_key,
                "aws_secret_access_key": self.s3_settings_doc.aws_secret,
            })
        self._probe = boto3.client("s3", **probe_kwargs)

    # ---------------- Region & client helpers ----------------

    def _get_bucket_region(self) -> str:
        """Discover and cache this bucket's region (None => us-east-1)."""
        if self._bucket_region:
            return self._bucket_region
        resp = self._probe.get_bucket_location(Bucket=self.BUCKET)
        region = resp.get("LocationConstraint") or "us-east-1"
        self._bucket_region = region
        return region

    def _get_regional_client(self):
        """Return an S3 client pinned to the bucket's region (virtual-hosted style)."""
        region = self._get_bucket_region()
        if region not in self._client_cache:
            base_kwargs = {
                "region_name": region,
                "config": Config(signature_version="s3v4", s3={"addressing_style": "virtual"}),
            }
            if self.s3_settings_doc.aws_key and self.s3_settings_doc.aws_secret:
                base_kwargs.update({
                    "aws_access_key_id": self.s3_settings_doc.aws_key,
                    "aws_secret_access_key": self.s3_settings_doc.aws_secret,
                })
            self._client_cache[region] = boto3.client("s3", **base_kwargs)
        return self._client_cache[region]

    # ---------------- Utility helpers ----------------

    def strip_special_chars(self, file_name):
        """
        Strips characters which don't match the regex (safe for S3/object headers).
        """
        return re.sub(r'[^0-9a-zA-Z._-]', '', file_name)

    def key_generator(self, file_name, parent_doctype, parent_name):
        """
        Generate keys for S3 objects; supports hook override.
        """
        hook_cmd = frappe.get_hooks().get("s3_key_generator")
        if hook_cmd:
            try:
                k = frappe.get_attr(hook_cmd[0])(
                    file_name=file_name,
                    parent_doctype=parent_doctype,
                    parent_name=parent_name
                )
                if k:
                    return k.rstrip('/').lstrip('/')
            except Exception:
                # ignore hook errors; fall back to default
                pass

        file_name = self.strip_special_chars(file_name.replace(' ', '_'))
        key = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))

        today = datetime.datetime.now()
        year = today.strftime("%Y")
        month = today.strftime("%m")
        day = today.strftime("%d")

        if self.folder_name:
            return f"{self.folder_name}/{year}/{month}/{day}/{parent_doctype}/{key}_{file_name}"
        return f"{year}/{month}/{day}/{parent_doctype}/{key}_{file_name}"

    # ---------------- Core ops ----------------

    def upload_files_to_s3_with_key(self, file_path, file_name, is_private, parent_doctype, parent_name):
        """
        Upload a new file to S3 with correct ContentType and metadata.
        """
        mime_type = magic.from_file(file_path, mime=True)
        key = self.key_generator(file_name, parent_doctype, parent_name)
        s3 = self._get_regional_client()

        extra = {
            "ContentType": mime_type,
            "Metadata": {"ContentType": mime_type, "file_name": file_name},
        }
        if not is_private:
            # Public files explicitly set ACL; private files rely on bucket policy
            extra["ACL"] = "public-read"

        try:
            s3.upload_file(file_path, self.BUCKET, key, ExtraArgs=extra)
        except boto3.exceptions.S3UploadFailedError:
            frappe.throw(frappe._("File Upload Failed. Please try again."))
        return key

    def delete_from_s3(self, key):
        """Delete file from S3 (if setting enabled)."""
        # Refresh in case setting changed
        self.s3_settings_doc = frappe.get_doc('S3 File Attachment', 'S3 File Attachment')

        if self.s3_settings_doc.delete_file_from_cloud:
            s3 = self._get_regional_client()
            try:
                s3.delete_object(Bucket=self.s3_settings_doc.bucket_name, Key=key)
            except ClientError:
                frappe.throw(frappe._("Access denied: Could not delete file"))

    def read_file_from_s3(self, key):
        """
        Read object bytes/stream from S3 (returns GetObject response).
        """
        s3 = self._get_regional_client()
        return s3.get_object(Bucket=self.BUCKET, Key=key)

    def get_url(self, key, file_name=None):
        """
        Return a presigned GET URL using the *regional* endpoint.
        """
        s3 = self._get_regional_client()
        expiry = getattr(self.s3_settings_doc, "signed_url_expiry_time", None) or 120

        params = {"Bucket": self.BUCKET, "Key": key.lstrip("/")}
        if file_name:
            # Standards-compliant Content-Disposition (handles spaces/UTF-8)
            safe_ascii = file_name.replace('"', "'")
            utf8_quoted = quote(file_name, safe="")
            params["ResponseContentDisposition"] = (
                f'attachment; filename="{safe_ascii}"; filename*=UTF-8\'\'{utf8_quoted}'
            )

        return s3.generate_presigned_url(
            ClientMethod="get_object",
            Params=params,
            ExpiresIn=int(expiry),
        )


@frappe.whitelist()
def file_upload_to_s3(doc, method):
    """
    Upload File doc's payload to S3 and update File.file_url appropriately.
    Uses *regional* public URL for non-private files; presigned redirect for private.
    """
    s3_upload = S3Operations()
    path = doc.file_url
    site_path = frappe.utils.get_site_path()
    parent_doctype = doc.attached_to_doctype or 'File'
    parent_name = doc.attached_to_name
    ignore_s3_upload_for_doctype = frappe.local.conf.get('ignore_s3_upload_for_doctype') or ['Data Import']

    if parent_doctype in ignore_s3_upload_for_doctype:
        return

    file_path = site_path + ('/public' + path if not doc.is_private else path)

    key = s3_upload.upload_files_to_s3_with_key(
        file_path, doc.file_name, doc.is_private, parent_doctype, parent_name
    )

    if doc.is_private:
        # Private: serve via presigned redirect method
        method = "frappe_s3_attachment.controller.generate_file"
        file_url = f"/api/method/{method}?key={key}&file_name={quote(doc.file_name or '', safe='')}"
    else:
        # Public: use regional, virtual-hosted style URL
        region = s3_upload._get_bucket_region()
        file_url = f"https://{s3_upload.BUCKET}.s3.{region}.amazonaws.com/{key}"

    # Cleanup local temp
    try:
        os.remove(file_path)
    except Exception:
        pass

    # Persist updates
    frappe.db.sql(
        """UPDATE `tabFile`
           SET file_url=%s, folder=%s, old_parent=%s, content_hash=%s
           WHERE name=%s""",
        (file_url, 'Home/Attachments', 'Home/Attachments', key, doc.name)
    )
    doc.file_url = file_url

    # If parent doctype has an image field, set it to this file_url
    if parent_doctype and frappe.get_meta(parent_doctype).get('image_field'):
        frappe.db.set_value(
            parent_doctype,
            parent_name,
            frappe.get_meta(parent_doctype).get('image_field'),
            file_url
        )

    frappe.db.commit()


@frappe.whitelist()
def generate_file(key=None, file_name=None):
    """
    Redirect to a regional presigned URL for private files.
    """
    if key:
        s3_upload = S3Operations()
        signed_url = s3_upload.get_url(key, file_name)
        frappe.local.response["type"] = "redirect"
        frappe.local.response["location"] = signed_url
    else:
        frappe.local.response['body'] = "Key not found."
    return


def upload_existing_files_s3(name, file_name):
    """
    Upload an existing File doc's file to S3 and rewrite its URL.
    """
    file_doc_name = frappe.db.get_value('File', {'name': name})
    if not file_doc_name:
        return

    doc = frappe.get_doc('File', name)
    s3_upload = S3Operations()
    path = doc.file_url
    site_path = frappe.utils.get_site_path()
    parent_doctype = doc.attached_to_doctype
    parent_name = doc.attached_to_name

    file_path = site_path + ('/public' + path if not doc.is_private else path)

    key = s3_upload.upload_files_to_s3_with_key(
        file_path, doc.file_name, doc.is_private, parent_doctype, parent_name
    )

    if doc.is_private:
        method = "frappe_s3_attachment.controller.generate_file"
        file_url = f"/api/method/{method}?key={key}"
    else:
        region = s3_upload._get_bucket_region()
        file_url = f"https://{s3_upload.BUCKET}.s3.{region}.amazonaws.com/{key}"

    try:
        os.remove(file_path)
    except Exception:
        pass

    frappe.db.sql(
        """UPDATE `tabFile`
           SET file_url=%s, folder=%s, old_parent=%s, content_hash=%s
           WHERE name=%s""",
        (file_url, 'Home/Attachments', 'Home/Attachments', key, doc.name)
    )
    frappe.db.commit()


def s3_file_regex_match(file_url):
    """
    Match public (https) URLs or private presigned redirect route.
    """
    return re.match(
        r'^(https://|/api/method/frappe_s3_attachment.controller.generate_file)',
        file_url or ""
    )


@frappe.whitelist()
def migrate_existing_files():
    """
    Migrate all existing File docs that aren't already S3 URLs or private routes.
    """
    files_list = frappe.get_all('File', fields=['name', 'file_url', 'file_name'])
    for file in files_list:
        if file['file_url'] and not s3_file_regex_match(file['file_url']):
            upload_existing_files_s3(file['name'], file['file_name'])
    return True


def delete_from_cloud(doc, method):
    """Hook: delete file from S3 when File doc is deleted (if enabled)."""
    s3 = S3Operations()
    s3.delete_from_s3(doc.content_hash)


@frappe.whitelist()
def ping():
    """
    Simple test function.
    """
    return "pong"
