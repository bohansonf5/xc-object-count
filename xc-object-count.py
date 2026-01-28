import argparse
import csv
import datetime
from datetime import timezone
import sys
from typing import Any, Dict, Iterable, List, Optional, Tuple
import requests


def parse_args(argv: Optional[Iterable[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Collect object counts and HTTP request statistics per namespace "
            "from F5 Distributed Cloud APIs."
        )
    )
    parser.add_argument(
        "--base_url",
        required=True,
        help="Base URL of the XC tenant (e.g. https://mytenant.console.ves.volterra.io)",
    )
    parser.add_argument(
        "--api_token",
        required=True,
        help="API token for authentication (Authorization: APIToken <token>)",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Path to the output CSV file",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable SSL certificate verification",
    )
    parser.add_argument(
        "--days",
        type=int,
        default=30,
        help=(
            "Time horizon in days for HTTP request statistics. "
            "The script computes request totals over the past N days (default: 30)."
        ),
    )
    return parser.parse_args(argv)


def get_http_session(api_token: str, insecure: bool) -> requests.Session:
    session = requests.Session()
    session.headers.update({
        "Authorization": f"APIToken {api_token}",
        "Content-Type": "application/json",
    })
    session.verify = not insecure
    return session


def get_namespaces(base_url: str, session: requests.Session) -> List[str]:
    url = f"{base_url.rstrip('/')}/api/web/namespaces"
    try:
        resp = session.get(url)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        raise RuntimeError(f"Failed to list namespaces: {exc}") from exc
    namespaces: List[str] = []
    items = data.get("items")
    for item in items:
         name = item.get("name")
         namespaces.append(name)
    return namespaces


def get_application_inventory(base_url: str, session: requests.Session, namespace: str) -> Dict[str, Any]:
    url = f"{base_url.rstrip('/')}/api/config/namespaces/{namespace}/application_inventory"
    try:
        resp = session.post(url, json={})
        resp.raise_for_status()
        return resp.json() or {}
    except Exception as exc:
        raise RuntimeError(
            f"Failed to retrieve application inventory for namespace '{namespace}': {exc}"
        ) from exc


def extract_object_counts(inventory: Dict[str, Any]) -> Dict[str, int]:
    categories = {
        "loadbalancers": 0,
        "public_advertisment": 0,
        "private_advertisement": 0,
        "waf": 0,
        "bot_protection": 0,
        "client_side_defense": 0,
        "api_discovery": 0,
        "api_protection": 0,
        "ddos_protection": 0,
        "malicious_user_detection": 0,
        "malware_protection": 0
    }
    val = inventory.get("loadbalancers")
    categories["loadbalancers"] = int(val)
    http_lb = inventory.get("http_loadbalancers")
    for key in [
        "public_advertisment",
        "private_advertisement",
        "waf",
        "bot_protection",
        "client_side_defense",
        "api_discovery",
        "api_protection",
        "ddos_protection",
        "malicious_user_detection",
        "malware_protection"
    ]:
        value = http_lb.get(key)
        categories[key] = int(value)
    return categories


def get_http_requests(base_url: str,session: requests.Session,namespace: str,start_time: int,end_time: int) -> Tuple[Optional[int], Optional[str]]:
    url = f"{base_url.rstrip('/')}/api/data/namespaces/{namespace}/graph/service"
    payload = {
        "field_selector": {
            "node": {
                "metric": {
                    "downstream": ["HTTP_REQUEST_RATE"],
                }
            }
        },
        "step": "auto",
        "end_time": str(end_time),
        "start_time": str(start_time),
        "label_filter": [
            {
                "label": "LABEL_VHOST_TYPE",
                "op": "EQ",
                "value": "HTTP_LOAD_BALANCER",
            }
        ],
        "group_by": ["VIRTUAL_HOST_TYPE"],
    }
    try:
        resp = session.post(url, json=payload)
        resp.raise_for_status()
        data = resp.json() or {}
    except Exception as exc:
        return None, f"Graph service request failed: {exc}"
    nodes: List[Any] = []
    root_data = data.get("data", data)
    nodes = root_data.get("nodes") or []
    total_requests: float = 0.0
    SECONDS_PER_DAY = 24 * 60 * 60
    for node in nodes:
        metric_data = (
            node.get("data", {})
            .get("metric", {})
            .get("downstream", [])
        )
        for metric in metric_data:
            value_obj = metric.get("value", {})
            raw_samples = value_obj.get("raw", [])
            for sample in raw_samples:
                val = sample.get("value")
                rate = float(val)
                total_requests += rate * SECONDS_PER_DAY

    if total_requests > 0:
        return int(total_requests), None
    else:
        return None, "No HTTP request rate metrics found in graph/service response"


def write_csv(filename: str,rows: List[Dict[str, Any]],fieldnames: List[str]) -> None:
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)

CSV_FIELD_RENAME: Dict[str, str] = {
    "namespace": "Namespace",
    "loadbalancers": "Total LBs",
    "public_advertisment": "Public LBs",
    "private_advertisement": "Private LBs",
    "waf": "WAF",
    "bot_protection": "Bot Protection",
    "client_side_defense": "Client-Side Defense",
    "api_discovery": "API Discovery",
    "api_protection": "API Protection",
    "ddos_protection": "DDoS Protection",
    "malicious_user_detection": "Malicious User Detection",
    "malware_protection": "Malware Protection",
    "http_requests": "HTTP Requests",
    "issues": "Issues",
}

def main(argv: Optional[Iterable[str]] = None) -> None:
    args = parse_args(argv)
    session = get_http_session(args.api_token, args.insecure)
    try:
        namespaces = get_namespaces(args.base_url, session)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    # Compute time range for HTTP request statistics
    end_dt = datetime.datetime.now(timezone.utc)
    start_dt = end_dt - datetime.timedelta(days=args.days)
    start_ts = int(start_dt.timestamp())
    end_ts = int(end_dt.timestamp())

    # Iterate through each namespace
    rows: List[Dict[str, Any]] = []
    for ns in namespaces:
        row: Dict[str, Any] = {"namespace": ns}
        issues: List[str] = []

        # Get inventory and compute counts for each object category. If inventory retrieval fails, leave object counts blank
        try:
            inventory = get_application_inventory(args.base_url, session, ns)
            object_counts = extract_object_counts(inventory)
            row.update(object_counts)
        except Exception as exc:
            issues.append(str(exc))
            for cat in [
                "loadbalancers",
                "public_advertisment",
                "private_advertisement",
                "waf",
                "bot_protection",
                "client_side_defense",
                "api_discovery",
                "api_protection",
                "ddos_protection",
                "malicious_user_detection",
                "malware_protection"
            ]:
                row[cat] = ""

        # Get HTTP request counts via graph service
        req_count, issue = get_http_requests(args.base_url, session, ns, start_ts, end_ts)
        if issue:
            issues.append(issue)
            row["http_requests"] = ""
        else:
            row["http_requests"] = req_count
        row["issues"] = "; ".join(issues) if issues else ""
        
        # Normalize CSV Headers
        csv_row: Dict[str, Any] = {}
        for original_name, clean_name in row.items():
            if original_name in CSV_FIELD_RENAME:
                csv_row[CSV_FIELD_RENAME[original_name]] = clean_name
            else:
                csv_row[original_name] = clean_name
        rows.append(csv_row)
        
    # Write results to CSV
    fieldnames = [CSV_FIELD_RENAME[original_name] for original_name in [
        "namespace",
        "loadbalancers",
        "public_advertisment",
        "private_advertisement",
        "waf",
        "bot_protection",
        "client_side_defense",
        "api_discovery",
        "api_protection",
        "ddos_protection",
        "malicious_user_detection",
        "malware_protection",
        "http_requests",
        "issues",
    ]]
    try:
        write_csv(args.output, rows, fieldnames)
    except Exception as exc:
        print(f"Error writing CSV: {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"Successfully wrote data for {len(rows)} namespaces to {args.output}")


if __name__ == "__main__":
    main()
