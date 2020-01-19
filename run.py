import argparse

from tlsprofiler import TLSProfiler, PROFILE


class InvalidProfileName(Exception):
    """Exception that is raised if the specified profile is not one of [old|intermediate|modern]"""


valid_profiles = ["old", "intermediate", "modern"]

parser = argparse.ArgumentParser(
    description="Scan the TLS settings of a server and match them with a Mozilla TLS profile.",
    epilog="Example usage: python3 run.py www.example.com intermediate",
)
parser.add_argument("domain", type=str, help="Domain name of the server to be scanned")
parser.add_argument(
    "profile",
    type=str,
    help="The Mozilla TLS profile to scan for [old|intermediate|modern]",
)
parser.add_argument(
    "-c",
    "--ca-file",
    type=str,
    help="Path to a trusted custom root certificates in PEM format",
)
parser.add_argument(
    "-w",
    "--cert-expire-warning",
    type=int,
    default=15,
    help="A warning is issued if the certificate expires in less days than specified (default 15 days)",
)

args = parser.parse_args()

domain = args.domain

profile = args.profile

if profile not in valid_profiles:
    raise InvalidProfileName()

ca_file = args.ca_file
cert_expire_warning = args.cert_expire_warning

profiler = TLSProfiler(domain, profile, ca_file, cert_expire_warning)

print(profiler.run())
