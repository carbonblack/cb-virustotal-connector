from cbint.utils.detonation import DetonationDaemon
from cbint.utils.detonation.binary_analysis import (BinaryAnalysisProvider,
                                                    AnalysisTemporaryError, AnalysisResult, AnalysisInProgress)
from cbapi.connection import CbAPISessionAdapter
from apiclient_virustotal import (VirusTotalAnalysisClient, VTAPIQUOTAREACHED)
from datetime import (datetime, timedelta)

import cbint.utils.feed
import logging
from requests import Session

log = logging.getLogger(__name__)


class VirusTotalProvider(BinaryAnalysisProvider):
    def __init__(self, name, virustotal_api_token, url=None, rescan_window=None,log_level=None):
        super(VirusTotalProvider, self).__init__(name)
        session = Session()
        tls_adapter = CbAPISessionAdapter(force_tls_1_2=True)
        session.mount("https://", tls_adapter)
        self.virustotal_analysis = VirusTotalAnalysisClient(api_token=virustotal_api_token, session=session,log_level=log_level)
        self.url = url
        if rescan_window and "NEVER" not in rescan_window.upper():
            specs = {"M": "minutes", "W": "weeks", "D": "days", "S": "seconds", "H": "hours"}
            spec = specs[rescan_window[-1].upper()]
            val = int(rescan_window[:-1])
            self.rescan_window = timedelta(**{spec: val})
        else:
            self.rescan_window = None

    def make_result(self, scan_id, result=None,md5=None):
        try:
            result = self.virustotal_analysis.get_report(scan_id) if not result else result
        except Exception as e:
            raise AnalysisTemporaryError(message="API error: %s" % str(e), retry_in=120)
        else:
            total = int(result.get("total",1))
            positives = int(result.get("positives",0))
            score = int(float(positives) / float(total) * 100)
            if score == 0:
                return AnalysisResult(message="Benign", extended_message="",
                                      link=result['permalink'],
                                      score=score)
            else:
                scans = result.get("scans", {})
                detected_by = filter(lambda (k, v): v.get('detected', False) is True, scans.iteritems())
                detected_by = map(lambda (k , v ) : (k , v.get("result","potential_malware")),detected_by)
                log.info("detected by = %s " % detected_by)
                report_string = "VirusTotal Report:\n" + "\n".join([k + " :\t" + v for (k, v) in detected_by])
                malware_result = "[%d / %d] VirusTotal report for %s" % (positives , total, md5)
                return AnalysisResult(message=malware_result, extended_message=report_string,
                                          link=result['permalink'],
                                          score=score)

    def check_result_for(self, md5sum):

        log.info("Submitting binary %s to VT for analysis" % md5sum)
        try:
            response = self.virustotal_analysis.get_report(resource_hash=md5sum)
        except VTAPIQUOTAREACHED as vte:
            log.debug(vte)
            return None
        response_code = response.get("response_code", -1)
        verbose_msg = response.get("verbose_msg", "")

        if response_code == -2 or "Your resource is queued for analysis" in verbose_msg:
            return AnalysisInProgress(retry_in=180)
        elif response_code == 1:
            scan_id = response.get('scan_id', None)
            now = datetime.now()
            scan_date_str = response.get('scan_date',None)
            scan_date = datetime.strptime(scan_date_str, "%Y-%m-%d %H:%M:%S") if scan_date_str else None
            log.info("Binary %s has not been scanned since: %s - timenow: %s" % (md5sum, scan_date, now))
            if self.rescan_window and scan_date and (now - scan_date) >= self.rescan_window:
                log.info("HIT RESCAN WINDOW: Binary %s" % md5sum)
                try:
                    self.virustotal_analysis.rescan_hash(md5sum)
                except VTAPIQUOTAREACHED as vte:
                    log.debug(vte)
                    return None
                except Exception as e:
                    log.debug(e)
                    return None
                return AnalysisInProgress(retry_in=180)
            elif scan_id:
                return self.make_result(scan_id,md5=md5sum,result=response)
        else:  # response_code == 0 , -1 other cases all indicate error condition / binary not yet seen by VT
            return None

    def analyze_binary(self, md5sum, binary_file_stream):

        log.info("Submitting binary %s to VT for analysis" % md5sum)
        try:
            response = self.virustotal_analysis.submit_file(resource_hash=md5sum, stream=binary_file_stream)
        except VTAPIQUOTAREACHED as vte:
            raise AnalysisTemporaryError(message="VTAPIQUOTAREACHED", retry_in=15*60)

        response_code = response.get("response_code", -1)
        verbose_msg = response.get("verbose_msg", "")
        # response_code == -2 or "scan request successfully queued" is the wait condition
        if response_code == -2 or "Scan request successfully queued" in verbose_msg:
            raise AnalysisTemporaryError(message="VirusTotal report not yet ready -> %s" % verbose_msg, retry_in=120)
        elif response_code == 1:
            scan_id = response.get("scan_id", None)
            return self.make_result(scan_id=scan_id, result=response)
        else:
            raise AnalysisTemporaryError(message="Unknown error? % s" % response, retry_in=120)


class VirusTotalConnector(DetonationDaemon):
    @property
    def filter_spec(self):
        filters = []
        max_module_len = 10 * 1024 * 1024
        filters.append('orig_mod_len:[1 TO %d]' % max_module_len)
        additional_filter_requirements = self.get_config_string("binary_filter_query", None)
        if additional_filter_requirements:
            filters.append(additional_filter_requirements)

        return ' '.join(filters)

    @property
    def integration_name(self):
        return 'Cb VT Connector 1.0.2'

    @property
    def num_quick_scan_threads(self):
        return self.get_config_integer("virustotal_quick_scan_threads", 1)

    @property
    def num_deep_scan_threads(self):
        return self.get_config_integer("virustotal_deep_scan_threads", 3)

    def get_provider(self):
        virustotal_provider = VirusTotalProvider(name=self.name, virustotal_api_token=self.virustotal_api_token,
                                                 rescan_window=self.rescan_window, url=self.virustotal_url,log_level=self.log_level)

        return virustotal_provider

    def get_metadata(self):
        return cbint.utils.feed.generate_feed(self.name, summary="VirusTotal harnesses the power of over fifty-five Anti-Virus vendors to identify suspicious binaries.",
                                              tech_data="A VirusTotal private API key is required to use this feed. There are no requirements to share any data with Carbon Black to use this feed. However, binaries may be shared with virustotal.",
                                              provider_url="http://www.virustotal.com/",
                                              icon_path='/usr/share/cb/integrations/virustotal/virustotal-logo.png',
                                              display_name="VirusTotal", category="Connectors")

    def validate_config(self):
        super(VirusTotalConnector, self).validate_config()

        self.check_required_options(["virustotal_api_token"])
        self.virustotal_api_token = self.get_config_string("virustotal_api_token", None)
        self.virustotal_url = self.get_config_string("virustotal_url", None)
        self.rescan_window = self.get_config_string("rescan_window", None)
        self.log_level = logging.DEBUG if int(self.get_config_string("debug",0)) is 1 else logging.INFO
        log.setLevel(self.log_level)

        return True


if __name__ == '__main__':
    import os

    my_path = os.path.dirname(os.path.abspath(__file__))
    temp_directory = "/tmp/virustotal"

    config_path = os.path.join(my_path, "testing.conf")
    daemon = VirusTotalConnector(name='virustotaltesting', configfile=config_path, work_directory=temp_directory,
                                 logfile=os.path.join(temp_directory, 'test.log'), debug=True)

    logging.getLogger().setLevel(logging.DEBUG)

    daemon.start()
