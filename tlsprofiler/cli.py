import argparse

from tlsprofiler import TLSProfiler
from tlsprofiler import utils


class InvalidProfileName(Exception):
    """Exception that is raised if the specified profile is not one of [old|intermediate|modern]"""


def main():
    profile_names = ["old", "intermediate", "modern"]

    parser = argparse.ArgumentParser(
        description="Scans the TLS settings of a server and compares them with a Mozilla TLS profile.",
        epilog="Example usage: python3 run.py www.example.com intermediate",
    )
    parser.add_argument(
        "domain", type=str, help="Domain name of the server to be scanned"
    )
    parser.add_argument(
        "profile",
        type=str,
        nargs="?",
        help="The Mozilla TLS profile to scan for [old|intermediate|modern]. If no profile is specified, the server's TLS settings will be compared to all profiles.",
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

    if profile and profile not in profile_names:
        raise InvalidProfileName()

    ca_file = args.ca_file
    cert_expire_warning = args.cert_expire_warning

    print("Initialize scanner")
    profiler = TLSProfiler(domain, ca_file, cert_expire_warning)

    print("Run scan (this may take awhile)")
    profiler.scan_server()

    # print result on the console
    if profile:
        print(profiler.compare_to_profile(profile))
    else:
        for p in profile_names:
            print(profiler.compare_to_profile(p))
            print(utils.expand_string("", 90, "-"))


if __name__ == "__main__":
    main()
