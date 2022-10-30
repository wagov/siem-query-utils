from siem_query_utils.api import OutputFormat, azcli, list_workspaces, query_all, ExampleQuery
from siem_query_utils.reporting import KQL
import pandas

class TestClass:
    def test_listworkspaces(self):
        assert isinstance(list_workspaces(OutputFormat.df), pandas.DataFrame)

    def test_kql(self):
        kp = KQL()
        assert isinstance(kp.sentinelworkspaces, list)
    
    def test_grouped_query(self):
        assert query_all(query=ExampleQuery.default, format=OutputFormat.json)[0]["TableName"] == "PrimaryResult"

    def test_threaded_query(self):
        assert "TenantId" in query_all(query=ExampleQuery.default, format=OutputFormat.json, groupQueries=False)[0]
    
    def test_azcli(self):
        assert "azure-cli" in azcli(["version"])
