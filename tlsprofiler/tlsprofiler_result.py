from typing import List
from dataclasses import dataclass
from textwrap import TextWrapper
from tabulate import tabulate

from tlsprofiler import utils


@dataclass
class TLSProfilerResult:
    profile_name: str
    validation_errors: List[str]
    cert_warnings: List[str]
    profile_errors: List[str]
    vulnerability_errors: List[str]

    validated: bool
    no_warnings: bool
    profile_matched: bool
    vulnerable: bool

    all_ok: bool

    def __init__(
        self,
        profile_name: str,
        validation_errors: List[str],
        cert_warnings: List[str],
        profile_errors: List[str],
        vulnerability_errors: List[str],
    ):
        self.profile_name = profile_name
        self.validation_errors = validation_errors
        self.cert_warnings = cert_warnings
        self.profile_errors = profile_errors
        self.vulnerability_errors = vulnerability_errors

        self.validated = len(self.validation_errors) == 0
        self.no_warnings = len(self.cert_warnings) == 0
        self.profile_matched = len(self.profile_errors) == 0
        self.vulnerable = len(self.vulnerability_errors) > 0

        self.all_ok = (
            self.validated
            and self.profile_matched
            and not self.vulnerable
            and self.no_warnings
        )

    def __str__(self):
        width = 80
        wrapper = TextWrapper(width=width, replace_whitespace=False)

        tmp_val = (
            [wrapper.fill(el) for el in self.validation_errors]
            if self.validation_errors
            else ["All good ;)"]
        )
        tmp_cert = (
            [wrapper.fill(el) for el in self.cert_warnings]
            if self.cert_warnings
            else ["All good ;)"]
        )
        tmp_prof = (
            [wrapper.fill(el) for el in self.profile_errors]
            if self.profile_errors
            else ["All good ;)"]
        )
        tmp_vul = (
            [wrapper.fill(el) for el in self.vulnerability_errors]
            if self.vulnerability_errors
            else ["All good ;)"]
        )

        val = {utils.expand_string("Validation Errors", width): tmp_val}
        cert = {utils.expand_string("Certification Warnings", width): tmp_cert}
        prof = {utils.expand_string("Profile Errors", width): tmp_prof}
        vul = {utils.expand_string("Vulnerability Errors", width): tmp_vul}

        return (
            f"\nTLS settings compared with the {self.profile_name.title()} Mozilla TLS profile:\n"
            f"{tabulate(val, headers='keys', tablefmt='fancy_grid', showindex='always')}\n"
            f"{tabulate(cert, headers='keys', tablefmt='fancy_grid', showindex='always')}\n"
            f"{tabulate(prof, headers='keys', tablefmt='fancy_grid', showindex='always')}\n"
            f"{tabulate(vul, headers='keys', tablefmt='fancy_grid', showindex='always')}\n"
            f"\nValidated: {self.validated}; Profile Matched: {self.profile_matched}; "
            f"Vulnerable: {self.vulnerable}; All ok: {self.all_ok}\n"
        )
