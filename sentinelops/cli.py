import argparse
import json
import sys
from .scanner import scan_cloud, scan_path

def main():
    parser=argparse.ArgumentParser(prog="sentinelops",description="Scan local security snapshots safely.")
    sub=parser.add_subparsers(dest="command",required=True)
    cloud=sub.add_parser("scan-cloud",help="Scan AWS-style JSON snapshot"); cloud.add_argument("file")
    secret=sub.add_parser("scan-secrets",help="Scan local text for credential patterns"); secret.add_argument("file")
    args=parser.parse_args()
    if args.command=="scan-cloud":
        with open(args.file,encoding="utf-8") as stream: findings=scan_cloud(json.load(stream))
    else:
        try: findings=scan_path(args.file)
        except (ValueError,OSError) as exc: parser.error(str(exc))
    print(json.dumps([f.model_dump(mode="json") for f in findings],indent=2))
    return 1 if findings else 0
if __name__=="__main__": sys.exit(main())
