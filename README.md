# xc-object-count

This script collects billable object counts and HTTP request statistics
from the F5 Distributed Cloud (XC) APIs. All billable object counts are 
grouped by namespace. There are two API endpoints used in this script:

1. **Application Inventory** – Provides a consolidated inventory of
   application objects within a namespace.  The script issues a POST
   request to `/api/config/namespaces/{namespace}/application_inventory`
   and counts the number of objects for specific billable fields. 

3. **Service Graph** – Provides service mesh metrics for a namespace.
   The script issues a POST request to `/api/data/namespaces/{namespace}/graph/service`
   with a JSON payload containing `start_time` and `end_time` entries.  The endpoint is
   designed to return time‑series data for various metrics related to service mesh
   interactions.  The script specifically extracts a total number of
   HTTP requests for the last 30 days. 

Usage example::

    python xc_namespace_inventory_requests.py \
      --base_url https://mytenant.console.ves.volterra.io \
      --api_token $API_TOKEN \
      --output xc_usage_counts.csv
