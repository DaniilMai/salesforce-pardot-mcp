"""
Tools package — re-exports all MCP tool functions.

server.py iterates over ALL_TOOLS to register them with the FastMCP instance.
"""

from tools.salesforce import (
    sf_query,
    sf_get_leads,
    sf_get_contacts,
    sf_update_lead,
    sf_update_contact,
    sf_create_lead,
    sf_pipeline_report,
    sf_get_tasks,
    sf_get_events,
    sf_get_activity_history,
)
from tools.pardot import (
    pardot_get_prospects,
    pardot_get_prospect_by_email,
    pardot_update_prospect,
    pardot_get_campaigns,
    pardot_get_lists,
    pardot_get_forms,
    pardot_add_prospect_to_list,
    pardot_get_visitor_activities,
    pardot_get_form_handlers,
    pardot_get_emails,
    pardot_get_lifecycle_history,
)

ALL_TOOLS = [
    # Salesforce
    sf_query,
    sf_get_leads,
    sf_get_contacts,
    sf_update_lead,
    sf_update_contact,
    sf_create_lead,
    sf_pipeline_report,
    sf_get_tasks,
    sf_get_events,
    sf_get_activity_history,
    # Pardot
    pardot_get_prospects,
    pardot_get_prospect_by_email,
    pardot_update_prospect,
    pardot_get_campaigns,
    pardot_get_lists,
    pardot_get_forms,
    pardot_add_prospect_to_list,
    pardot_get_visitor_activities,
    pardot_get_form_handlers,
    pardot_get_emails,
    pardot_get_lifecycle_history,
]
