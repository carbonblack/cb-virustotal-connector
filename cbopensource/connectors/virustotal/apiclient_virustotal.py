#!/usr/bin/env python

import logging
import os

log = logging.getLogger(__name__)


class VirusTotalAnalysisClient(object):

    def __init__(self, session=None, api_token=None, url=None,log_level=None):
        self.session = session
        self.api_token = api_token
        self.url = url if url else "https://www.virustotal.com/vtapi/v2/file/"
        log.setLevel(logging.INFO if not log_level else log_level)

    def submit_file(self, resource_hash=None, stream=None):
        log.info("VTAnalysis: submit_file: hash = %s " % (resource_hash))
        params = {"apikey": self.api_token}
        file_name = None
        if hasattr(stream, "name"):
            log.info("submitting file: fs.name: %s" % stream.name)
            file_name = os.path.basename(stream.name)
        files = {'file': (file_name, open(file_name, 'rb'))} if file_name else {'file': (resource_hash, stream)}
        response = self.session.post(self.url + 'scan', files=files, params=params)
        log.debug("submit_file: response = %s" % response)
        return response.json()

    def rescan_hash(self, resource_hash):
        log.info("rescan_hash: resource_hash = %s" % resource_hash)
        params = {"apikey": self.api_token}
        if resource_hash:
            params["resource"] = resource_hash
        else:
            raise Exception("No resources provided")
        headers = {
            "Accept-Encoding": "gzip, deflate",
            "User-Agent": "gzip,  cb-virustotal-connector/1.0"
        }
        response = self.session.post(self.url + "rescan", params=params, headers=headers)
        log.debug("Rescan hash: response = %s" % response)
        return response.json()

    def get_report(self, resource_hash=None, batch=None):
        log.info("get_report: resource_hash = %s" % resource_hash)
        params = {"apikey": self.api_token}
        if resource_hash:
            params["resource"] = resource_hash
        elif batch:
            params['resource'] = ",".join(batch)
        else:
            raise Exception("No resources provided")
        headers = {
            "Accept-Encoding": "gzip, deflate",
            "User-Agent": "gzip,  cb-virustotal-connector/1.0"
        }
        response = self.session.get(self.url + "report",
                                    params=params, headers=headers)
        log.debug("get_report: response = %s " % response)
        return response.json()
